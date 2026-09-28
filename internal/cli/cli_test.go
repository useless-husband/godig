package cli

import (
	"bytes"
	"context"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/fakedns"
	"github.com/useless-husband/godig/internal/resolver"
)

var update = flag.Bool("update", false, "rewrite golden files")

// patternReader repeats a byte pattern forever; it makes message IDs and the
// 0x20 bits predictable.
type patternReader struct{ p []byte }

func (r patternReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = r.p[i%len(r.p)]
	}
	return len(b), nil
}

// steppingClock advances 3 ms on every call, so each exchange measures 3 ms.
type steppingClock struct{ n atomic.Int64 }

func (c *steppingClock) Now() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(c.n.Add(1)) * 3 * time.Millisecond)
}

var fixedNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func testEnv(out, errb *bytes.Buffer) *Env {
	return &Env{
		Stdout: out, Stderr: errb, Version: "test", Now: func() time.Time { return fixedNow },
		ResolvConf: filepath.Join(os.DevNull),
		ClientHook: func(c *resolver.Client) {
			c.Rand = patternReader{[]byte{0x01, 0x02, 0x55, 0xaa}} // ID 258
			c.Now = (&steppingClock{}).Now
			c.Timeout = 300 * time.Millisecond
		},
	}
}

func run(t *testing.T, env *Env, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	if env == nil {
		env = testEnv(&out, &errb)
	}
	env.Stdout, env.Stderr = &out, &errb
	code := Run(context.Background(), args, env)
	return out.String(), errb.String(), code
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name+".golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if string(want) != got {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func exampleZone() *fakedns.Zone {
	return &fakedns.Zone{Origin: "example.test.", RRs: []dnsmsg.RR{
		fakedns.RR("example.test.", 300, dnsmsg.A{Addr: netip.MustParseAddr("192.0.2.10")}),
		fakedns.RR("example.test.", 300, dnsmsg.A{Addr: netip.MustParseAddr("192.0.2.11")}),
		fakedns.RR("example.test.", 300, dnsmsg.AAAA{Addr: netip.MustParseAddr("2001:db8::10")}),
		fakedns.RR("example.test.", 3600, dnsmsg.MX{Pref: 10, Host: "mail.example.test."}),
		fakedns.RR("example.test.", 3600, dnsmsg.MX{Pref: 20, Host: "mail2.example.test."}),
		fakedns.RR("example.test.", 60, dnsmsg.TXT{Strings: []string{"v=spf1 -all", "second \"quoted\" part"}}),
		fakedns.RR("example.test.", 86400, dnsmsg.NS{Host: "ns1.example.test."}),
		fakedns.RR("_sip._tcp.example.test.", 300, dnsmsg.SRV{Priority: 1, Weight: 5, Port: 5060, Target: "sip.example.test."}),
		fakedns.RR("example.test.", 300, dnsmsg.CAA{Flag: 0, Tag: "issue", Value: "ca.example.net"}),
		fakedns.RR("example.test.", 300, dnsmsg.Unknown{T: 65, Data: []byte{0, 1, 0xab}}),
		fakedns.RR("www.example.test.", 120, dnsmsg.CNAME{Target: "example.test."}),
		fakedns.RR("4.3.2.1.in-addr.arpa.", 300, dnsmsg.PTR{Host: "host.example.test."}),
		fakedns.RR("big.example.test.", 60, dnsmsg.TXT{Strings: []string{
			strings.Repeat("a", 250), strings.Repeat("b", 250), strings.Repeat("c", 250), strings.Repeat("d", 250), strings.Repeat("e", 250)}}),
	}}
}

// serverEnv starts the fake nameserver and returns an Env whose output the
// caller can normalize (the port changes on every run).
func serverEnv(t *testing.T) (*fakedns.Server, func(args ...string) (string, string, int)) {
	t.Helper()
	srv := fakedns.Start(t, exampleZone().Handle)
	port := strconv.Itoa(srv.Port())
	return srv, func(args ...string) (string, string, int) {
		out, errs, code := run(t, nil, append([]string{"-p", port, "@127.0.0.1"}, args...)...)
		return strings.ReplaceAll(out, port, "PORT"), strings.ReplaceAll(errs, port, "PORT"), code
	}
}

func TestGoldenDigA(t *testing.T) {
	_, q := serverEnv(t)
	out, _, code := q("example.test", "A")
	if code != 0 {
		t.Fatal(code)
	}
	golden(t, "dig_a", out)
}

func TestGoldenDigNXDomain(t *testing.T) {
	_, q := serverEnv(t)
	out, _, _ := q("missing.example.test", "A")
	golden(t, "dig_nxdomain", out)
}

func TestGoldenDigMXTXTSOA(t *testing.T) {
	_, q := serverEnv(t)
	for _, typ := range []string{"MX", "TXT", "NS", "SRV", "CAA", "TYPE65"} {
		name := "example.test"
		if typ == "SRV" {
			name = "_sip._tcp.example.test"
		}
		out, _, code := q(name, typ)
		if code != 0 {
			t.Fatalf("%s: %d", typ, code)
		}
		golden(t, "dig_"+strings.ToLower(typ), out)
	}
	out, _, _ := q("example.test", "SOA")
	golden(t, "dig_soa_nodata", out)
}

func TestGoldenShort(t *testing.T) {
	_, q := serverEnv(t)
	var sb strings.Builder
	for _, typ := range []string{"A", "AAAA", "MX", "TXT", "CAA", "TYPE65", "SOA"} {
		out, _, _ := q("+short", "example.test", typ)
		sb.WriteString("$ godig +short example.test " + typ + "\n" + out)
	}
	golden(t, "short", sb.String())
}

func TestGoldenJSON(t *testing.T) {
	_, q := serverEnv(t)
	out, _, code := q("+json", "example.test", "MX")
	if code != 0 {
		t.Fatal(code)
	}
	golden(t, "json_mx", out)
}

func TestGoldenTCP(t *testing.T) {
	srv, q := serverEnv(t)
	out, _, _ := q("+tcp", "example.test", "A")
	golden(t, "dig_tcp", out)
	if srv.UDPQueries() != 0 {
		t.Fatal("+tcp must not use UDP")
	}
}

func TestGoldenReverseIPv4(t *testing.T) {
	_, q := serverEnv(t)
	out, _, _ := q("-x", "1.2.3.4")
	golden(t, "reverse_ptr", out)
}

func TestReverseIPv6UsesNibbleName(t *testing.T) {
	var seen atomic.Value
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		seen.Store(req.Questions[0].Name + " " + req.Questions[0].Type.String())
		return &dnsmsg.Message{Header: dnsmsg.Header{RCode: dnsmsg.RCodeNameError}}
	})
	run(t, nil, "-p", strconv.Itoa(srv.Port()), "@127.0.0.1", "-x", "2001:db8::567:89ab")
	want := "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa. PTR"
	if seen.Load() != want {
		t.Fatalf("server saw %v", seen.Load())
	}
}

func TestGoldenTruncationFallbackMessage(t *testing.T) {
	srv, q := serverEnv(t)
	out, _, code := q("+short", "big.example.test", "TXT")
	if code != 0 || strings.Count(out, "\n") != 1 || srv.TCPQueries() != 1 {
		t.Fatalf("code=%d lines=%d tcp=%d", code, strings.Count(out, "\n"), srv.TCPQueries())
	}
	out, _, _ = q("big.example.test", "TXT")
	if !strings.HasPrefix(out, ";; Truncated, retrying in TCP mode.\n") || !strings.Contains(out, "(TCP)") {
		t.Fatalf("missing TC notice:\n%.300s", out)
	}
}

func TestNorecClearsRDFlag(t *testing.T) {
	var rd atomic.Int32
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		if req.RecursionDesired {
			rd.Store(1)
		} else {
			rd.Store(2)
		}
		return exampleZone().Handle(req, "udp")
	})
	p := strconv.Itoa(srv.Port())
	run(t, nil, "-p", p, "@127.0.0.1", "example.test")
	if rd.Load() != 1 {
		t.Fatal("RD should be set by default")
	}
	run(t, nil, "-p", p, "@127.0.0.1", "+norec", "example.test")
	if rd.Load() != 2 {
		t.Fatal("+norec must clear RD")
	}
}

func TestNoEDNSOmitsOPT(t *testing.T) {
	var opt atomic.Int32
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		if _, ok := req.OPTRecord(); ok {
			opt.Store(1)
		} else {
			opt.Store(2)
		}
		return exampleZone().Handle(req, "udp")
	})
	p := strconv.Itoa(srv.Port())
	run(t, nil, "-p", p, "@127.0.0.1", "example.test")
	if opt.Load() != 1 {
		t.Fatal("EDNS0 OPT is sent by default")
	}
	run(t, nil, "-p", p, "@127.0.0.1", "+noedns", "example.test")
	if opt.Load() != 2 {
		t.Fatal("+noedns must drop the OPT record")
	}
}

func TestTimeoutAndRetryOptionsReachClient(t *testing.T) {
	var got resolver.Client
	env := testEnv(new(bytes.Buffer), new(bytes.Buffer))
	inner := env.ClientHook
	env.ClientHook = func(c *resolver.Client) {
		inner(c)
		got = *c
		c.Timeout = 50 * time.Millisecond
	}
	srv := fakedns.Start(t, func(*dnsmsg.Message, string) *dnsmsg.Message { return nil })
	_, errs, code := run(t, env, "-p", strconv.Itoa(srv.Port()), "@127.0.0.1", "+timeout=7", "+retry=0", "example.test")
	if code != ExitTimeout || !strings.Contains(errs, "communications error") {
		t.Fatalf("code=%d stderr=%q", code, errs)
	}
	if !got.NoRetry || got.Timeout != 300*time.Millisecond && got.Timeout != 7*time.Second {
		t.Fatalf("%+v", got)
	}
	if srv.UDPQueries() != 1 {
		t.Fatalf("+retry=0 means a single attempt, server saw %d", srv.UDPQueries())
	}
	env = testEnv(new(bytes.Buffer), new(bytes.Buffer))
	env.ClientHook = func(c *resolver.Client) { got = *c; c.Timeout = 50 * time.Millisecond; c.NoRetry = true }
	run(t, env, "-p", strconv.Itoa(srv.Port()), "@127.0.0.1", "+timeout=7", "+retry=4", "example.test")
	if got.Timeout != 7*time.Second || got.Retries != 4 || got.NoRetry {
		t.Fatalf("%+v", got)
	}
}

func TestServerGivenAsHostnameIsResolvedIteratively(t *testing.T) {
	// The fake "root" answers ns.example.test authoritatively with 127.0.0.1.
	root := fakedns.Start(t, (&fakedns.Zone{Origin: ".", RRs: []dnsmsg.RR{fakedns.A("ns.example.test.", "127.0.0.1")}}).Handle)
	target := fakedns.Start(t, exampleZone().Handle)
	env := testEnv(new(bytes.Buffer), new(bytes.Buffer))
	env.ResolverHook = func(r *resolver.Resolver) {
		r.Roots = []resolver.RootServer{{Name: "a.root.test.", V4: netip.MustParseAddr("192.0.2.1")}}
		r.Addr = func(netip.Addr) string { return root.Addr }
	}
	out, _, code := run(t, env, "-p", strconv.Itoa(target.Port()), "@ns.example.test", "+short", "example.test", "A")
	if code != 0 || !strings.Contains(out, "192.0.2.10") {
		t.Fatalf("code=%d out=%q", code, out)
	}
	if root.Queries() != 1 || target.Queries() != 1 {
		t.Fatalf("root=%d target=%d", root.Queries(), target.Queries())
	}
}

func TestServerHostnameLookupFailure(t *testing.T) {
	root := fakedns.Start(t, (&fakedns.Zone{Origin: ".", RRs: []dnsmsg.RR{fakedns.A("x.test.", "192.0.2.1")}}).Handle)
	env := testEnv(new(bytes.Buffer), new(bytes.Buffer))
	env.ResolverHook = func(r *resolver.Resolver) {
		r.Roots = []resolver.RootServer{{Name: "a.root.test.", V4: netip.MustParseAddr("192.0.2.1")}}
		r.Addr = func(netip.Addr) string { return root.Addr }
	}
	_, errs, code := run(t, env, "@nope.test", "example.test")
	if code != ExitError || !strings.Contains(errs, "cannot resolve server name") {
		t.Fatalf("code=%d %q", code, errs)
	}
}

func TestVersionHelpAndUsageErrors(t *testing.T) {
	out, _, code := run(t, nil, "--version")
	if code != 0 || out != "godig test\n" {
		t.Fatalf("%d %q", code, out)
	}
	out, _, code = run(t, nil, "-h")
	if code != 0 || !strings.Contains(out, "godig serve") || !strings.Contains(out, "+trace") {
		t.Fatalf("%d %q", code, out)
	}
	out, _, code = run(t, nil)
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Fatalf("no args should print usage, got %d %q", code, out)
	}
	_, errs, code := run(t, nil, "example.test", "+bogus")
	if code != ExitUsage || !strings.Contains(errs, "unknown option +bogus") {
		t.Fatalf("%d %q", code, errs)
	}
}

// ---- trace ----

func traceEnv(t *testing.T) (*Env, map[string]*fakedns.Server) {
	t.Helper()
	servers := map[string]*fakedns.Server{}
	addrs := map[netip.Addr]string{}
	add := func(ip string, z *fakedns.Zone) {
		s := fakedns.Start(t, z.Handle)
		servers[ip] = s
		addrs[netip.MustParseAddr(ip)] = s.Addr
	}
	add("192.0.2.1", &fakedns.Zone{Origin: ".", Cuts: []fakedns.Cut{{Zone: "test.", NS: []string{"a.nic.test."}, Glue: map[string]string{"a.nic.test.": "192.0.2.2"}}}})
	add("192.0.2.2", &fakedns.Zone{Origin: "test.", RRs: []dnsmsg.RR{fakedns.A("ns.provider.test.", "192.0.2.4")}, Cuts: []fakedns.Cut{
		{Zone: "example.test.", NS: []string{"ns1.example.test."}, Glue: map[string]string{"ns1.example.test.": "192.0.2.3"}},
		{Zone: "nogl.test.", NS: []string{"ns.provider.test."}},
	}})
	add("192.0.2.3", &fakedns.Zone{Origin: "example.test.", RRs: []dnsmsg.RR{
		fakedns.A("example.test.", "192.0.2.10"),
		fakedns.RR("www.example.test.", 120, dnsmsg.CNAME{Target: "example.test."}),
		fakedns.RR("far.example.test.", 120, dnsmsg.CNAME{Target: "www.nogl.test."}),
	}})
	add("192.0.2.4", &fakedns.Zone{Origin: "nogl.test.", RRs: []dnsmsg.RR{fakedns.A("www.nogl.test.", "192.0.2.20")}})
	env := testEnv(nil, nil)
	env.ResolverHook = func(r *resolver.Resolver) {
		r.Roots = []resolver.RootServer{{Name: "a.root-servers.net.", V4: netip.MustParseAddr("192.0.2.1")}}
		r.Addr = func(ip netip.Addr) string { return addrs[ip] }
	}
	return env, servers
}

func TestGoldenTraceSimple(t *testing.T) {
	env, _ := traceEnv(t)
	out, errs, code := run(t, env, "+trace", "example.test")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	golden(t, "trace_simple", out)
}

func TestGoldenTraceCNAME(t *testing.T) {
	env, _ := traceEnv(t)
	out, _, code := run(t, env, "+trace", "www.example.test")
	if code != 0 {
		t.Fatal(code)
	}
	golden(t, "trace_cname", out)
}

func TestGoldenTraceNoGlueAndCrossZoneCNAME(t *testing.T) {
	env, _ := traceEnv(t)
	out, _, code := run(t, env, "+trace", "far.example.test")
	if code != 0 {
		t.Fatal(code)
	}
	golden(t, "trace_noglue", out)
}

func TestGoldenTraceNXDomain(t *testing.T) {
	env, _ := traceEnv(t)
	out, _, code := run(t, env, "+trace", "nothing.example.test")
	if code != 0 || !strings.Contains(out, "NXDOMAIN") {
		t.Fatal(code, out)
	}
	golden(t, "trace_nxdomain", out)
}

func TestTraceFailureExitsNonZero(t *testing.T) {
	env, servers := traceEnv(t)
	servers["192.0.2.1"].Close()
	out, errs, code := run(t, env, "+trace", "example.test")
	if code != ExitError || !strings.Contains(errs, "trace failed") || !strings.Contains(out, "failed") {
		t.Fatalf("%d\n%s\n%s", code, out, errs)
	}
}

func TestTraceUses0x20ByDefaultAndCanDisableIt(t *testing.T) {
	env, servers := traceEnv(t)
	_ = servers
	out, _, _ := run(t, env, "+trace", "example.test")
	if !strings.Contains(out, "0x20 case randomization on") {
		t.Fatal(out)
	}
	env, _ = traceEnv(t)
	out, _, _ = run(t, env, "+trace", "+no0x20", "example.test")
	if !strings.Contains(out, "0x20 case randomization off") {
		t.Fatal(out)
	}
}

// ---- serve ----

func TestServeSubcommandAnswersAndStopsCleanly(t *testing.T) {
	root := fakedns.Start(t, (&fakedns.Zone{Origin: ".", RRs: []dnsmsg.RR{fakedns.A("example.test.", "192.0.2.77")}}).Handle)
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb bytes.Buffer
	var mu sync.Mutex
	ready := make(chan string, 1)
	env := &Env{Stdout: &out, Stderr: &syncWriter{&mu, &errb}, Version: "test",
		ResolverHook: func(r *resolver.Resolver) {
			r.Roots = []resolver.RootServer{{Name: "a.root.test.", V4: netip.MustParseAddr("192.0.2.1")}}
			r.Addr = func(netip.Addr) string { return root.Addr }
		},
		Ready: func(a string) { ready <- a }}
	done := make(chan int, 1)
	go func() { done <- Run(ctx, []string{"serve", "--port", "0"}, env) }()
	var addr string
	select {
	case addr = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not start")
	}
	c := &resolver.Client{Timeout: time.Second, NoRetry: true}
	for i := 0; i < 2; i++ {
		resp, err := c.Exchange(context.Background(), addr, "example.test", dnsmsg.TypeA, true)
		if err != nil || resp.Msg.Answers[0].Data.String() != "192.0.2.77" {
			t.Fatalf("%v %+v", err, resp)
		}
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatal(code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
	mu.Lock()
	log := errb.String()
	mu.Unlock()
	for _, want := range []string{"serving on", "source=upstream", "source=cache", "queries=2 cache_hits=1"} {
		if !strings.Contains(log, want) {
			t.Errorf("log missing %q:\n%s", want, log)
		}
	}
	if root.Queries() != 1 {
		t.Fatalf("root queries %d", root.Queries())
	}
}

type syncWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func TestServeQuietFlagAndBadArguments(t *testing.T) {
	_, errs, code := run(t, nil, "serve", "--nonsense")
	if code != ExitUsage || !strings.Contains(errs, "flag provided but not defined") {
		t.Fatalf("%d %q", code, errs)
	}
	_, errs, code = run(t, nil, "serve", "--port", "70000")
	if code != ExitUsage {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestServeReportsBindFailure(t *testing.T) {
	busy := fakedns.Start(t, func(*dnsmsg.Message, string) *dnsmsg.Message { return nil })
	_, errs, code := run(t, nil, "serve", "--port", strconv.Itoa(busy.Port()))
	if code != ExitError || !strings.Contains(errs, "cannot listen") {
		t.Fatalf("%d %q", code, errs)
	}
}
