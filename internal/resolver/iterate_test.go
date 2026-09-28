package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/fakedns"
)

// world is a small fake Internet: a root, a "test." TLD and several zones,
// all on 127.0.0.1 but addressed by documentation IPs (192.0.2.0/24) that the
// resolver's Addr hook maps to the real local ports.
type world struct {
	t       *testing.T
	addrs   map[netip.Addr]string
	servers map[string]*fakedns.Server
	res     *Resolver
	clock   *fakedns.Clock
	mu      sync.Mutex
	events  []Event
}

func (w *world) add(ip string, h fakedns.Handler, opts ...fakedns.Option) *fakedns.Server {
	s := fakedns.Start(w.t, h, opts...)
	w.addrs[netip.MustParseAddr(ip)] = s.Addr
	w.servers[ip] = s
	return s
}

func (w *world) zone(ip string, z *fakedns.Zone, opts ...fakedns.Option) *fakedns.Server {
	return w.add(ip, z.Handle, opts...)
}

func (w *world) trace(e Event) {
	w.mu.Lock()
	w.events = append(w.events, e)
	w.mu.Unlock()
}

func (w *world) kinds() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, e := range w.events {
		out = append(out, fmt.Sprintf("%d:%s:%s", e.Depth, e.Kind, strings.TrimSuffix(e.Zone, ".")))
	}
	return out
}

func servfail(*dnsmsg.Message, string) *dnsmsg.Message {
	return &dnsmsg.Message{Header: dnsmsg.Header{RCode: dnsmsg.RCodeServerFailure}}
}

func silent(*dnsmsg.Message, string) *dnsmsg.Message { return nil }

func cname(from, to string) dnsmsg.RR { return fakedns.RR(from, 60, dnsmsg.CNAME{Target: to}) }

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, addrs: map[netip.Addr]string{}, servers: map[string]*fakedns.Server{}, clock: fakedns.NewClock()}
	w.zone("192.0.2.1", &fakedns.Zone{Origin: ".", Cuts: []fakedns.Cut{
		{Zone: "test.", NS: []string{"a.nic.test."}, Glue: map[string]string{"a.nic.test.": "192.0.2.2"}},
	}})
	w.zone("192.0.2.2", &fakedns.Zone{Origin: "test.",
		RRs: []dnsmsg.RR{fakedns.A("ns.provider.test.", "192.0.2.5"), fakedns.A("a.nic.test.", "192.0.2.2")},
		Cuts: []fakedns.Cut{
			{Zone: "example.test.", NS: []string{"ns1.example.test."}, Glue: map[string]string{"ns1.example.test.": "192.0.2.3"}},
			{Zone: "other.test.", NS: []string{"ns.other.test."}, Glue: map[string]string{"ns.other.test.": "192.0.2.4"}},
			{Zone: "nogl.test.", NS: []string{"ns.provider.test."}},
			{Zone: "loop.test.", NS: []string{"ns.loop.test."}},
			{Zone: "sf.test.", NS: []string{"ns1.sf.test.", "ns2.sf.test."}, Glue: map[string]string{"ns1.sf.test.": "192.0.2.6", "ns2.sf.test.": "192.0.2.7"}},
			{Zone: "to.test.", NS: []string{"ns1.to.test.", "ns2.to.test."}, Glue: map[string]string{"ns1.to.test.": "192.0.2.8", "ns2.to.test.": "192.0.2.9"}},
		}})
	w.zone("192.0.2.3", &fakedns.Zone{Origin: "example.test.", RRs: []dnsmsg.RR{
		fakedns.A("example.test.", "192.0.2.80"),
		fakedns.A("web.example.test.", "192.0.2.81"),
		cname("www.example.test.", "web.example.test."),
		cname("alias.example.test.", "host.other.test."),
		cname("c1.example.test.", "c2.example.test."),
		cname("c2.example.test.", "c1.example.test."),
		fakedns.RR("mail.example.test.", 60, dnsmsg.MX{Pref: 10, Host: "mx.example.test."}),
		fakedns.RR("big.example.test.", 60, dnsmsg.TXT{Strings: []string{
			strings.Repeat("a", 250), strings.Repeat("b", 250), strings.Repeat("c", 250), strings.Repeat("d", 250), strings.Repeat("e", 250)}}),
	}})
	w.zone("192.0.2.4", &fakedns.Zone{Origin: "other.test.", RRs: []dnsmsg.RR{fakedns.A("host.other.test.", "192.0.2.90")}})
	w.zone("192.0.2.5", &fakedns.Zone{Origin: "nogl.test.", RRs: []dnsmsg.RR{fakedns.A("www.nogl.test.", "192.0.2.91")}})
	w.add("192.0.2.6", servfail)
	w.zone("192.0.2.7", &fakedns.Zone{Origin: "sf.test.", RRs: []dnsmsg.RR{fakedns.A("www.sf.test.", "192.0.2.92")}})
	w.add("192.0.2.8", silent)
	w.zone("192.0.2.9", &fakedns.Zone{Origin: "to.test.", RRs: []dnsmsg.RR{fakedns.A("www.to.test.", "192.0.2.93")}})

	w.res = &Resolver{
		Client: &Client{Timeout: 200 * time.Millisecond, NoRetry: true, Now: w.clock.Now},
		Roots:  []RootServer{{Name: "a.root.test.", V4: netip.MustParseAddr("192.0.2.1")}},
		Addr: func(ip netip.Addr) string {
			if a, ok := w.addrs[ip]; ok {
				return a
			}
			return "127.0.0.1:1" // nothing listens here: connection refused / no reply
		},
		Trace: w.trace,
	}
	return w
}

func (w *world) resolve(name string, t dnsmsg.Type) (*Result, error) {
	return w.res.Resolve(context.Background(), name, t)
}

func answerStrings(r *Result) []string {
	var out []string
	for _, rr := range r.Answers {
		out = append(out, rr.Type().String()+" "+rr.Data.String())
	}
	return out
}

func TestResolveWalksRootTLDAuthority(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerStrings(res); len(got) != 1 || got[0] != "A 192.0.2.80" {
		t.Fatal(got)
	}
	if res.Queries != 3 {
		t.Fatalf("queries %d", res.Queries)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if w.servers[ip].Queries() != 1 {
			t.Errorf("%s got %d queries", ip, w.servers[ip].Queries())
		}
	}
}

func TestTraceEventsShowDelegationChain(t *testing.T) {
	w := newWorld(t)
	if _, err := w.resolve("web.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(w.kinds(), ",")
	if want := "0:referral:,0:referral:test,0:answer:example.test"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	e := w.events[0]
	if e.Next != "test." || len(e.NS) != 1 || !e.NS[0].Glue || e.NS[0].Addrs[0].String() != "192.0.2.2" {
		t.Fatalf("first event: %+v", e)
	}
	if w.events[2].Server.String() != "192.0.2.3" || w.events[2].Resp == nil {
		t.Fatalf("last event: %+v", w.events[2])
	}
}

func TestResolveCNAMEInsideZone(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("www.example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	got := answerStrings(res)
	if len(got) != 2 || got[0] != "CNAME web.example.test." || got[1] != "A 192.0.2.81" {
		t.Fatal(got)
	}
}

func TestResolveCNAMEAcrossZonesRestartsFromTop(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("alias.example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	got := answerStrings(res)
	if len(got) != 2 || got[0] != "CNAME host.other.test." || got[1] != "A 192.0.2.90" {
		t.Fatal(got)
	}
	var sawCNAME bool
	for _, e := range w.events {
		if e.Kind == KindCNAME && e.Target == "host.other.test." {
			sawCNAME = true
		}
	}
	if !sawCNAME {
		t.Fatal("no cname event")
	}
}

func TestResolveCNAMELoopDetected(t *testing.T) {
	w := newWorld(t)
	_, err := w.resolve("c1.example.test", dnsmsg.TypeA)
	if err == nil {
		t.Fatal("expected error for CNAME loop")
	}
}

func TestResolveCNAMEQueryForCNAMEType(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("www.example.test", dnsmsg.TypeCNAME)
	if err != nil || len(res.Answers) != 1 || res.Answers[0].Type() != dnsmsg.TypeCNAME {
		t.Fatalf("%v %v", err, res)
	}
}

func TestResolveNoGlueResolvesNameserverFirst(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("www.nogl.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerStrings(res); len(got) != 1 || got[0] != "A 192.0.2.91" {
		t.Fatal(got)
	}
	var nsLookup, nested bool
	for _, e := range w.events {
		if e.Kind == KindNSLookup && e.Target == "ns.provider.test." {
			nsLookup = true
		}
		if e.Depth == 1 {
			nested = true
		}
	}
	if !nsLookup || !nested {
		t.Fatalf("expected a nested ns lookup, events: %v", w.kinds())
	}
}

func TestResolveNameserverLoopDetected(t *testing.T) {
	w := newWorld(t)
	_, err := w.resolve("www.loop.test", dnsmsg.TypeA)
	if err == nil {
		t.Fatal("expected failure")
	}
	var sawLoop bool
	for _, e := range w.events {
		if e.Kind == KindNSLoop {
			sawLoop = true
		}
	}
	if !sawLoop {
		t.Fatalf("loop not reported: %v (%v)", w.kinds(), err)
	}
}

func TestResolveMaxDepthOfNestedNameserverLookups(t *testing.T) {
	w := newWorld(t)
	// d0.test -> NS ns.d1.test (no glue) -> NS ns.d2.test ... each needs the next.
	var cuts []fakedns.Cut
	for i := 0; i < 12; i++ {
		cuts = append(cuts, fakedns.Cut{Zone: fmt.Sprintf("d%d.test.", i), NS: []string{fmt.Sprintf("ns.d%d.test.", i+1)}})
	}
	w.zone("192.0.2.2", &fakedns.Zone{Origin: "test.", Cuts: cuts})
	// re-point the root's glue at the new server instance
	w.addrs[netip.MustParseAddr("192.0.2.2")] = w.servers["192.0.2.2"].Addr
	w.res.MaxDepth = 3
	_, err := w.resolve("x.d0.test", dnsmsg.TypeA)
	if !errors.Is(err, ErrMaxDepth) {
		t.Fatalf("want ErrMaxDepth, got %v", err)
	}
}

func TestResolveFailsOverOnSERVFAIL(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("www.sf.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerStrings(res); got[0] != "A 192.0.2.92" {
		t.Fatal(got)
	}
	if w.servers["192.0.2.6"].Queries() != 1 || w.servers["192.0.2.7"].Queries() != 1 {
		t.Fatal("expected one query to each")
	}
	var sawErr bool
	for _, e := range w.events {
		if e.Kind == KindError && strings.Contains(e.Err.Error(), "SERVFAIL") {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("SERVFAIL not reported in trace")
	}
}

func TestResolveFailsOverOnTimeout(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("www.to.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if got := answerStrings(res); got[0] != "A 192.0.2.93" {
		t.Fatal(got)
	}
	if w.servers["192.0.2.8"].Queries() != 1 {
		t.Fatal("silent server should have been tried once")
	}
}

func TestResolveAllServersFailing(t *testing.T) {
	w := newWorld(t)
	w.servers["192.0.2.7"].Close()
	_, err := w.resolve("www.sf.test", dnsmsg.TypeA)
	if !errors.Is(err, ErrNoServers) {
		t.Fatalf("got %v", err)
	}
}

func TestResolveLameServerSkipped(t *testing.T) {
	w := newWorld(t)
	// The first nameserver answers NOERROR with nothing at all (not authoritative).
	w.add("192.0.2.6", func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		return &dnsmsg.Message{Questions: req.Questions}
	})
	res, err := w.resolve("www.sf.test", dnsmsg.TypeA)
	if err != nil || answerStrings(res)[0] != "A 192.0.2.92" {
		t.Fatalf("%v %v", err, res)
	}
}

func TestResolveNXDomainCarriesSOA(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("nope.example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if res.RCode != dnsmsg.RCodeNameError || len(res.Answers) != 0 || len(res.Authorities) != 1 || res.Authorities[0].Type() != dnsmsg.TypeSOA {
		t.Fatalf("%+v", res)
	}
}

func TestResolveNoDataCarriesSOA(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("web.example.test", dnsmsg.TypeMX)
	if err != nil {
		t.Fatal(err)
	}
	if res.RCode != dnsmsg.RCodeSuccess || len(res.Answers) != 0 || len(res.Authorities) != 1 {
		t.Fatalf("%+v", res)
	}
	if last := w.events[len(w.events)-1]; last.Kind != KindNoData {
		t.Fatal(last.Kind)
	}
}

func TestResolveTruncatedAnswerViaTCP(t *testing.T) {
	w := newWorld(t)
	res, err := w.resolve("big.example.test", dnsmsg.TypeTXT)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Answers) != 1 || w.servers["192.0.2.3"].TCPQueries() != 1 {
		t.Fatalf("tcp queries %d", w.servers["192.0.2.3"].TCPQueries())
	}
	last := w.events[len(w.events)-1]
	if !last.Resp.FellBackToTCP {
		t.Fatal("trace should record the TCP fallback")
	}
}

func TestIterativeQueriesClearRecursionDesired(t *testing.T) {
	w := newWorld(t)
	var rd atomic.Bool
	w.add("192.0.2.3", func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		rd.Store(req.RecursionDesired)
		return (&fakedns.Zone{Origin: "example.test.", RRs: []dnsmsg.RR{fakedns.A("example.test.", "192.0.2.80")}}).Handle(req, "udp")
	})
	if _, err := w.resolve("example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if rd.Load() {
		t.Fatal("iterative queries must not set RD")
	}
}

func TestResolveDropsUnrelatedRecordsInAnswer(t *testing.T) {
	w := newWorld(t)
	w.add("192.0.2.3", func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		m := (&fakedns.Zone{Origin: "example.test.", RRs: []dnsmsg.RR{fakedns.A("example.test.", "192.0.2.80")}}).Handle(req, "udp")
		m.Answers = append(m.Answers, fakedns.A("bank.example.", "6.6.6.6"), fakedns.A("example.test.", "192.0.2.81"))
		return m
	})
	res, err := w.resolve("example.test", dnsmsg.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	for _, rr := range res.Answers {
		if rr.Name == "bank.example." {
			t.Fatal("out-of-chain record leaked into the result")
		}
	}
	if len(res.Answers) != 2 {
		t.Fatalf("%v", answerStrings(res))
	}
}

func TestGlueOutsideBailiwickIgnored(t *testing.T) {
	m := &dnsmsg.Message{
		Authorities: []dnsmsg.RR{fakedns.RR("victim.test.", 300, dnsmsg.NS{Host: "ns.victim.net."}), fakedns.RR("victim.test.", 300, dnsmsg.NS{Host: "ns.victim.test."})},
		Additionals: []dnsmsg.RR{fakedns.A("ns.victim.net.", "6.6.6.6"), fakedns.A("ns.victim.test.", "192.0.2.50"), fakedns.A("unrelated.test.", "6.6.6.7")},
	}
	d := buildDelegation(m, "victim.test.", "test.", time.Unix(0, 0))
	if len(d.NS) != 2 {
		t.Fatalf("%+v", d)
	}
	if len(d.NS[0].Addrs) != 0 {
		t.Fatalf("out-of-bailiwick glue accepted: %+v", d.NS[0])
	}
	if len(d.NS[1].Addrs) != 1 || d.NS[1].Addrs[0].String() != "192.0.2.50" || !d.NS[1].Glue {
		t.Fatalf("%+v", d.NS[1])
	}
	if d.Expires != time.Unix(300, 0) {
		t.Fatalf("expires %v", d.Expires)
	}
}

func TestReferralMustMoveDownward(t *testing.T) {
	m := &dnsmsg.Message{Authorities: []dnsmsg.RR{fakedns.RR("com.", 60, dnsmsg.NS{Host: "a."})}}
	if _, ok := referral(m, "example.com.", "www.example.com."); ok {
		t.Fatal("referral to a parent zone must be refused")
	}
	if _, ok := referral(m, "com.", "www.example.com."); ok {
		t.Fatal("referral to the same zone must be refused")
	}
	m.Authorities[0].Name = "org."
	if _, ok := referral(m, ".", "www.example.com."); ok {
		t.Fatal("referral for an unrelated zone must be refused")
	}
	m.Authorities[0].Name = "example.com."
	if z, ok := referral(m, "com.", "www.example.com."); !ok || z != "example.com." {
		t.Fatal("valid referral rejected")
	}
}

func TestFollowChainStopsAtLoopWithinAnswer(t *testing.T) {
	rrs := []dnsmsg.RR{cname("a.test.", "b.test."), cname("b.test.", "a.test.")}
	chain, target, done := followChain(rrs, "a.test.", dnsmsg.TypeA)
	if done || len(chain) != 2 || target != "a.test." {
		t.Fatalf("%v %q %v", chain, target, done)
	}
}

func TestMaxQueriesBudget(t *testing.T) {
	w := newWorld(t)
	w.res.MaxQueries = 2
	_, err := w.resolve("example.test", dnsmsg.TypeA)
	if !errors.Is(err, ErrTooManyQueries) {
		t.Fatalf("got %v", err)
	}
}

func TestMaxCNAMEChain(t *testing.T) {
	w := newWorld(t)
	w.res.MaxCNAME = 0
	_, err := w.resolve("alias.example.test", dnsmsg.TypeA)
	// MaxCNAME 0 means "default", so this must still work...
	if err != nil {
		t.Fatal(err)
	}
	w.res.MaxCNAME = 1
	if _, err := w.resolve("alias.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err) // exactly one hop is allowed
	}
}

func TestZoneCacheSkipsRootAndTLD(t *testing.T) {
	w := newWorld(t)
	w.res.Zones = NewZoneCache(w.clock.Now)
	if _, err := w.resolve("example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := w.resolve("web.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if w.servers["192.0.2.1"].Queries() != 1 || w.servers["192.0.2.2"].Queries() != 1 || w.servers["192.0.2.3"].Queries() != 2 {
		t.Fatalf("root=%d tld=%d auth=%d", w.servers["192.0.2.1"].Queries(), w.servers["192.0.2.2"].Queries(), w.servers["192.0.2.3"].Queries())
	}
}

func TestZoneCacheEntriesExpire(t *testing.T) {
	w := newWorld(t)
	w.res.Zones = NewZoneCache(w.clock.Now)
	if _, err := w.resolve("example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	w.clock.Advance(86400*time.Second - time.Second)
	if _, ok := w.res.Zones.Lookup("example.test."); !ok {
		t.Fatal("entry should still be valid")
	}
	w.clock.Advance(2 * time.Second)
	if _, err := w.resolve("web.example.test", dnsmsg.TypeA); err != nil {
		t.Fatal(err)
	}
	if w.servers["192.0.2.1"].Queries() != 2 {
		t.Fatalf("root queries %d, want 2 after expiry", w.servers["192.0.2.1"].Queries())
	}
}

func TestZoneCacheLookupPicksDeepestAndIgnoresRoot(t *testing.T) {
	c := NewZoneCache(nil)
	exp := time.Now().Add(time.Hour)
	c.Put(delegation{Zone: "com.", Expires: exp})
	c.Put(delegation{Zone: "example.com.", Expires: exp})
	c.Put(delegation{Zone: ".", Expires: exp})
	if d, ok := c.Lookup("a.b.example.com."); !ok || d.Zone != "example.com." {
		t.Fatalf("%v %v", d, ok)
	}
	if d, ok := c.Lookup("other.com"); !ok || d.Zone != "com." {
		t.Fatalf("%v %v", d, ok)
	}
	if _, ok := c.Lookup("example.org."); ok {
		t.Fatal("no delegation for org")
	}
	if c.Len() != 2 {
		t.Fatalf("root must not be cached, len=%d", c.Len())
	}
}

func TestIPv6DisabledByDefault(t *testing.T) {
	r := &Resolver{}
	d := r.rootDelegation()
	if len(d.NS) != 13 {
		t.Fatalf("%d roots", len(d.NS))
	}
	for _, e := range d.NS {
		if len(e.Addrs) != 1 || !e.Addrs[0].Is4() {
			t.Fatalf("%s: %v", e.Host, e.Addrs)
		}
	}
	r.IPv6 = true
	for _, e := range r.rootDelegation().NS {
		if len(e.Addrs) != 2 || !e.Addrs[1].Is6() {
			t.Fatalf("%s: %v", e.Host, e.Addrs)
		}
	}
	if got := r.usable([]netip.Addr{netip.MustParseAddr("::1")}); len(got) != 1 {
		t.Fatal("IPv6 should be usable when enabled")
	}
	r.IPv6 = false
	if got := r.usable([]netip.Addr{netip.MustParseAddr("::1")}); len(got) != 0 {
		t.Fatal("IPv6 should be filtered")
	}
}

func TestRootHintsAreComplete(t *testing.T) {
	if len(RootServers) != 13 {
		t.Fatal(len(RootServers))
	}
	seen := map[string]bool{}
	for i, rs := range RootServers {
		want := string(rune('a'+i)) + ".root-servers.net."
		if rs.Name != want || !rs.V4.Is4() || !rs.V6.Is6() || seen[rs.V4.String()] {
			t.Fatalf("bad root hint %d: %+v", i, rs)
		}
		seen[rs.V4.String()] = true
	}
}
