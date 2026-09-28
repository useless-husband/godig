package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/fakedns"
	"github.com/useless-husband/godig/internal/resolver"
)

// stub is a Resolver whose answers and timing the test controls.
type stub struct {
	calls atomic.Int64
	gate  chan struct{} // if set, Resolve blocks until it is closed
	fn    func(name string, t dnsmsg.Type) (*resolver.Result, error)
}

func (s *stub) Resolve(_ context.Context, name string, t dnsmsg.Type) (*resolver.Result, error) {
	s.calls.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	return s.fn(name, t)
}

func aRes(name, ip string, ttl uint32) *resolver.Result {
	return &resolver.Result{Answers: []dnsmsg.RR{fakedns.RR(name, ttl, dnsmsg.A{Addr: netip.MustParseAddr(ip)})}}
}

func soa(ttl, minimum uint32) dnsmsg.RR {
	return fakedns.RR("example.test.", ttl, dnsmsg.SOA{MName: "ns.example.test.", RName: "h.example.test.", Serial: 1, Minimum: minimum})
}

func newTestServer(fn func(string, dnsmsg.Type) (*resolver.Result, error)) (*Server, *stub, *fakedns.Clock) {
	clk := fakedns.NewClock()
	st := &stub{fn: fn}
	return New(Config{Resolver: st, Cache: NewCache(clk.Now), Now: clk.Now}), st, clk
}

func query(name string, t dnsmsg.Type) *dnsmsg.Message {
	return dnsmsg.NewQuery(7, name, t, true, false)
}

func constA(string, dnsmsg.Type) (*resolver.Result, error) {
	return aRes("example.test.", "192.0.2.1", 60), nil
}

// ---- cache ----

func TestCacheHitAndTTLDecay(t *testing.T) {
	clk := fakedns.NewClock()
	c := NewCache(clk.Now)
	c.Put("example.test.", dnsmsg.TypeA, aRes("example.test.", "192.0.2.1", 60))
	clk.Advance(20 * time.Second)
	res, ok := c.Get("example.test.", dnsmsg.TypeA)
	if !ok || res.Answers[0].TTL != 40 {
		t.Fatalf("%v %+v", ok, res)
	}
}

func TestCacheEntryExpiresAtTTL(t *testing.T) {
	clk := fakedns.NewClock()
	c := NewCache(clk.Now)
	c.Put("example.test.", dnsmsg.TypeA, aRes("example.test.", "192.0.2.1", 60))
	clk.Advance(59 * time.Second)
	if _, ok := c.Get("example.test.", dnsmsg.TypeA); !ok {
		t.Fatal("should still be cached at 59s")
	}
	clk.Advance(1 * time.Second)
	if _, ok := c.Get("example.test.", dnsmsg.TypeA); ok {
		t.Fatal("should have expired at 60s")
	}
	if c.Len() != 0 {
		t.Fatal("expired entry not removed")
	}
}

func TestCacheUsesSmallestTTLInAnswerSet(t *testing.T) {
	clk := fakedns.NewClock()
	c := NewCache(clk.Now)
	res := &resolver.Result{Answers: []dnsmsg.RR{
		fakedns.RR("www.example.test.", 3600, dnsmsg.CNAME{Target: "web.example.test."}),
		fakedns.RR("web.example.test.", 30, dnsmsg.A{Addr: netip.MustParseAddr("192.0.2.1")}),
	}}
	c.Put("www.example.test.", dnsmsg.TypeA, res)
	clk.Advance(31 * time.Second)
	if _, ok := c.Get("www.example.test.", dnsmsg.TypeA); ok {
		t.Fatal("entry must expire with its shortest-lived record")
	}
}

func TestCacheSkipsZeroTTL(t *testing.T) {
	c := NewCache(nil)
	c.Put("example.test.", dnsmsg.TypeA, aRes("example.test.", "192.0.2.1", 0))
	if c.Len() != 0 {
		t.Fatal("TTL 0 must not be cached")
	}
}

func TestCacheCapsHugeTTL(t *testing.T) {
	clk := fakedns.NewClock()
	c := NewCache(clk.Now)
	c.MaxTTL = 100
	c.Put("example.test.", dnsmsg.TypeA, aRes("example.test.", "192.0.2.1", 999999))
	clk.Advance(101 * time.Second)
	if _, ok := c.Get("example.test.", dnsmsg.TypeA); ok {
		t.Fatal("MaxTTL not applied")
	}
}

func TestNegativeCacheUsesSOAMinimum(t *testing.T) {
	clk := fakedns.NewClock()
	c := NewCache(clk.Now)
	c.Put("nope.example.test.", dnsmsg.TypeA, &resolver.Result{RCode: dnsmsg.RCodeNameError, Authorities: []dnsmsg.RR{soa(300, 60)}})
	clk.Advance(59 * time.Second)
	res, ok := c.Get("nope.example.test.", dnsmsg.TypeA)
	if !ok || res.RCode != dnsmsg.RCodeNameError || len(res.Answers) != 0 {
		t.Fatalf("%v %+v", ok, res)
	}
	if res.Authorities[0].TTL != 1 {
		t.Fatalf("SOA TTL should decay too, got %d", res.Authorities[0].TTL)
	}
	clk.Advance(time.Second)
	if _, ok := c.Get("nope.example.test.", dnsmsg.TypeA); ok {
		t.Fatal("negative entry outlived SOA minimum")
	}
}

func TestNegativeCacheUsesSOATTLWhenSmaller(t *testing.T) {
	c := NewCache(nil)
	if ttl := c.TTLFor(&resolver.Result{RCode: dnsmsg.RCodeNameError, Authorities: []dnsmsg.RR{soa(30, 900)}}); ttl != 30 {
		t.Fatal(ttl)
	}
}

func TestNegativeCacheCappedAndNeedsSOA(t *testing.T) {
	c := NewCache(nil)
	if ttl := c.TTLFor(&resolver.Result{RCode: dnsmsg.RCodeNameError, Authorities: []dnsmsg.RR{soa(99999, 99999)}}); ttl != 3600 {
		t.Fatal(ttl)
	}
	if ttl := c.TTLFor(&resolver.Result{RCode: dnsmsg.RCodeNameError}); ttl != 0 {
		t.Fatal("negative answers without SOA must not be cached")
	}
}

func TestNoDataIsCachedNegatively(t *testing.T) {
	clk := fakedns.NewClock()
	c := NewCache(clk.Now)
	c.Put("example.test.", dnsmsg.TypeMX, &resolver.Result{Authorities: []dnsmsg.RR{soa(300, 120)}})
	res, ok := c.Get("example.test.", dnsmsg.TypeMX)
	if !ok || res.RCode != dnsmsg.RCodeSuccess || len(res.Answers) != 0 {
		t.Fatalf("%v %+v", ok, res)
	}
	if _, ok := c.Get("example.test.", dnsmsg.TypeA); ok {
		t.Fatal("NODATA for MX must not answer an A query")
	}
}

func TestCacheDoesNotStoreServerFailures(t *testing.T) {
	c := NewCache(nil)
	c.Put("x.test.", dnsmsg.TypeA, &resolver.Result{RCode: dnsmsg.RCodeServerFailure, Authorities: []dnsmsg.RR{soa(60, 60)}})
	if c.Len() != 0 {
		t.Fatal("SERVFAIL cached")
	}
}

func TestCacheKeyIsCaseInsensitiveAndPerType(t *testing.T) {
	c := NewCache(nil)
	c.Put("Example.TEST", dnsmsg.TypeA, aRes("example.test.", "192.0.2.1", 60))
	if _, ok := c.Get("EXAMPLE.test.", dnsmsg.TypeA); !ok {
		t.Fatal("case-insensitive lookup failed")
	}
	if _, ok := c.Get("example.test.", dnsmsg.TypeAAAA); ok {
		t.Fatal("type must be part of the key")
	}
}

func TestCacheReturnsCopies(t *testing.T) {
	c := NewCache(nil)
	c.Put("example.test.", dnsmsg.TypeA, aRes("example.test.", "192.0.2.1", 60))
	r1, _ := c.Get("example.test.", dnsmsg.TypeA)
	r1.Answers[0].TTL = 1
	r2, _ := c.Get("example.test.", dnsmsg.TypeA)
	if r2.Answers[0].TTL == 1 {
		t.Fatal("cache entry mutated through returned slice")
	}
}

func TestCacheEvictsWhenFull(t *testing.T) {
	c := NewCache(nil)
	c.MaxItems = 3
	for i := 0; i < 10; i++ {
		c.Put(fmt.Sprintf("h%d.test.", i), dnsmsg.TypeA, aRes("x.", "192.0.2.1", 60))
	}
	if c.Len() > 3 {
		t.Fatalf("len %d", c.Len())
	}
}

func TestCacheStats(t *testing.T) {
	c := NewCache(nil)
	c.Get("a.test.", dnsmsg.TypeA)
	c.Put("a.test.", dnsmsg.TypeA, aRes("a.test.", "192.0.2.1", 60))
	c.Get("a.test.", dnsmsg.TypeA)
	if h, m := c.Stats(); h != 1 || m != 1 {
		t.Fatal(h, m)
	}
}

// ---- Handle ----

func TestHandleMissThenHit(t *testing.T) {
	s, st, _ := newTestServer(constA)
	r1, src1 := s.Handle(query("example.test", dnsmsg.TypeA))
	r2, src2 := s.Handle(query("EXAMPLE.test", dnsmsg.TypeA))
	if st.calls.Load() != 1 || src1 != "upstream" || src2 != "cache" {
		t.Fatalf("calls=%d %s %s", st.calls.Load(), src1, src2)
	}
	if len(r1.Answers) != 1 || len(r2.Answers) != 1 || s.CacheHits.Load() != 1 {
		t.Fatal("answers")
	}
}

func TestHandleCacheExpiryTriggersNewLookup(t *testing.T) {
	s, st, clk := newTestServer(constA)
	s.Handle(query("example.test", dnsmsg.TypeA))
	clk.Advance(61 * time.Second)
	s.Handle(query("example.test", dnsmsg.TypeA))
	if st.calls.Load() != 2 {
		t.Fatalf("calls %d", st.calls.Load())
	}
}

func TestHandleNegativeAnswerServedFromCache(t *testing.T) {
	s, st, _ := newTestServer(func(string, dnsmsg.Type) (*resolver.Result, error) {
		return &resolver.Result{RCode: dnsmsg.RCodeNameError, Authorities: []dnsmsg.RR{soa(300, 60)}}, nil
	})
	for i := 0; i < 3; i++ {
		resp, _ := s.Handle(query("nope.example.test", dnsmsg.TypeA))
		if resp.RCode != dnsmsg.RCodeNameError || len(resp.Authorities) != 1 {
			t.Fatalf("%+v", resp)
		}
	}
	if st.calls.Load() != 1 {
		t.Fatalf("calls %d", st.calls.Load())
	}
}

func TestHandleCoalescesConcurrentIdenticalQueries(t *testing.T) {
	s, st, _ := newTestServer(constA)
	st.gate = make(chan struct{})
	const n = 25
	key := "example.test./1"
	var wg sync.WaitGroup
	sources := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, sources[i] = s.Handle(query("example.test", dnsmsg.TypeA))
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.group.waiting(key) < n-1 {
		if time.Now().After(deadline) {
			t.Fatalf("only %d requests joined", s.group.waiting(key))
		}
		time.Sleep(time.Millisecond)
	}
	close(st.gate)
	wg.Wait()
	if st.calls.Load() != 1 || s.Upstream.Load() != 1 || s.Coalesced.Load() != n-1 {
		t.Fatalf("resolver calls=%d upstream=%d coalesced=%d", st.calls.Load(), s.Upstream.Load(), s.Coalesced.Load())
	}
	up := 0
	for _, src := range sources {
		if src == "upstream" {
			up++
		}
	}
	if up != 1 {
		t.Fatalf("%d leaders", up)
	}
}

func TestHandleDoesNotMergeDifferentQuestions(t *testing.T) {
	s, st, _ := newTestServer(constA)
	st.gate = make(chan struct{})
	var wg sync.WaitGroup
	for _, ty := range []dnsmsg.Type{dnsmsg.TypeA, dnsmsg.TypeAAAA, dnsmsg.TypeMX} {
		wg.Add(1)
		go func() { defer wg.Done(); s.Handle(query("example.test", ty)) }()
	}
	for st.calls.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	close(st.gate)
	wg.Wait()
	if s.Coalesced.Load() != 0 {
		t.Fatal("different types were coalesced")
	}
}

func TestHandleServfailOnResolverErrorAndNoCaching(t *testing.T) {
	s, st, _ := newTestServer(func(string, dnsmsg.Type) (*resolver.Result, error) { return nil, errors.New("boom") })
	for i := 0; i < 2; i++ {
		resp, _ := s.Handle(query("example.test", dnsmsg.TypeA))
		if resp.RCode != dnsmsg.RCodeServerFailure {
			t.Fatal(resp.RCode)
		}
	}
	if st.calls.Load() != 2 {
		t.Fatal("failures must not be cached")
	}
}

func TestHandleSetsResponseFlags(t *testing.T) {
	s, _, _ := newTestServer(constA)
	req := query("example.test", dnsmsg.TypeA)
	req.ID = 0xabcd
	resp, _ := s.Handle(req)
	if resp.ID != 0xabcd || !resp.Response || !resp.RecursionDesired || !resp.RecursionAvailable || resp.Authoritative {
		t.Fatalf("%+v", resp.Header)
	}
	req.RecursionDesired = false
	resp, _ = s.Handle(req)
	if resp.RecursionDesired {
		t.Fatal("RD must be echoed, not forced")
	}
}

func TestHandleEchoesEDNS(t *testing.T) {
	s, _, _ := newTestServer(constA)
	resp, _ := s.Handle(dnsmsg.NewQuery(1, "example.test", dnsmsg.TypeA, true, true))
	opt, ok := resp.OPTRecord()
	if !ok || opt.Class != dnsmsg.DefaultUDPSize {
		t.Fatalf("%+v", resp.Additionals)
	}
	resp, _ = s.Handle(query("example.test", dnsmsg.TypeA))
	if _, ok := resp.OPTRecord(); ok {
		t.Fatal("no OPT expected for a plain query")
	}
}

func TestHandleRefusesZoneTransferAndChaos(t *testing.T) {
	s, st, _ := newTestServer(constA)
	for _, ty := range []dnsmsg.Type{252, 251} {
		if resp, _ := s.Handle(query("example.test", ty)); resp.RCode != dnsmsg.RCodeRefused {
			t.Fatalf("type %d: %v", ty, resp.RCode)
		}
	}
	q := query("version.bind", dnsmsg.TypeTXT)
	q.Questions[0].Class = dnsmsg.ClassCH
	if resp, _ := s.Handle(q); resp.RCode != dnsmsg.RCodeRefused {
		t.Fatal(resp.RCode)
	}
	if st.calls.Load() != 0 {
		t.Fatal("refused queries must not reach the resolver")
	}
}

func TestHandleRejectsOtherOpcodesAndMalformedQuestionCount(t *testing.T) {
	s, _, _ := newTestServer(constA)
	q := query("example.test", dnsmsg.TypeA)
	q.Opcode = dnsmsg.OpcodeUpdate
	if resp, _ := s.Handle(q); resp.RCode != dnsmsg.RCodeNotImplemented {
		t.Fatal(resp.RCode)
	}
	q = query("example.test", dnsmsg.TypeA)
	q.Questions = append(q.Questions, q.Questions[0])
	if resp, _ := s.Handle(q); resp.RCode != dnsmsg.RCodeFormatError {
		t.Fatal(resp.RCode)
	}
	q.Questions = nil
	if resp, _ := s.Handle(q); resp.RCode != dnsmsg.RCodeFormatError {
		t.Fatal(resp.RCode)
	}
}

func bigTXT(string, dnsmsg.Type) (*resolver.Result, error) {
	var ss []string
	for i := 0; i < 6; i++ {
		ss = append(ss, strings.Repeat("x", 250))
	}
	return &resolver.Result{Answers: []dnsmsg.RR{fakedns.RR("big.test.", 60, dnsmsg.TXT{Strings: ss})}}, nil
}

func TestHandlePacketTruncatesOverUDPButNotTCP(t *testing.T) {
	s, _, _ := newTestServer(bigTXT)
	for _, edns := range []bool{false, true} {
		pkt, _ := dnsmsg.NewQuery(3, "big.test", dnsmsg.TypeTXT, true, edns).Pack()
		udp, err := dnsmsg.Unpack(s.HandlePacket(pkt, "udp", "c"))
		if err != nil || !udp.Truncated || len(udp.Answers) != 0 || len(udp.Questions) != 1 {
			t.Fatalf("edns=%v: %v %+v", edns, err, udp)
		}
		tcp, err := dnsmsg.Unpack(s.HandlePacket(pkt, "tcp", "c"))
		if err != nil || tcp.Truncated || len(tcp.Answers) != 1 {
			t.Fatalf("tcp: %v %+v", err, tcp)
		}
	}
}

func TestHandlePacketLargeEDNSBufferStillCappedAt1232(t *testing.T) {
	s, _, _ := newTestServer(bigTXT) // ~1500 bytes
	q := dnsmsg.NewQuery(3, "big.test", dnsmsg.TypeTXT, true, true)
	q.SetEDNS(4096, false)
	pkt, _ := q.Pack()
	resp, _ := dnsmsg.Unpack(s.HandlePacket(pkt, "udp", "c"))
	if !resp.Truncated {
		t.Fatal("responses above 1232 bytes should be truncated over UDP")
	}
}

func TestHandlePacketDropsResponsesAndAnswersFormErrToGarbage(t *testing.T) {
	s, _, _ := newTestServer(constA)
	q := query("example.test", dnsmsg.TypeA)
	q.Response = true
	pkt, _ := q.Pack()
	if s.HandlePacket(pkt, "udp", "c") != nil {
		t.Fatal("must not answer a response packet")
	}
	if s.HandlePacket([]byte{1, 2, 3}, "udp", "c") != nil {
		t.Fatal("packets without a header are dropped")
	}
	bad := append([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, 0xC0, 0x0C) // loop
	resp, err := dnsmsg.Unpack(s.HandlePacket(bad, "udp", "c"))
	if err != nil || resp.RCode != dnsmsg.RCodeFormatError || resp.ID != 0x1234 {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestRequestLogLine(t *testing.T) {
	var buf bytes.Buffer
	clk := fakedns.NewClock()
	s := New(Config{Resolver: &stub{fn: constA}, Cache: NewCache(clk.Now), Now: clk.Now, Logger: log.New(&buf, "", 0)})
	pkt, _ := query("example.test", dnsmsg.TypeA).Pack()
	s.HandlePacket(pkt, "udp", "127.0.0.1:5353")
	s.HandlePacket(pkt, "tcp", "127.0.0.1:5354")
	want := `client=127.0.0.1:5353 proto=udp q="example.test. A" rcode=NOERROR answers=1 source=upstream tc=false ms=0
client=127.0.0.1:5354 proto=tcp q="example.test. A" rcode=NOERROR answers=1 source=cache tc=false ms=0
`
	if buf.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
}

// ---- network ----

func startServer(t *testing.T, r Resolver) *Server {
	t.Helper()
	s := New(Config{Addr: "127.0.0.1:0", Resolver: r})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestServerAnswersOverUDPAndTCP(t *testing.T) {
	s := startServer(t, &stub{fn: constA})
	c := &resolver.Client{Timeout: time.Second, NoRetry: true}
	resp, err := c.Exchange(context.Background(), s.Addr(), "example.test", dnsmsg.TypeA, true)
	if err != nil || resp.Network != "udp" || resp.Msg.Answers[0].Data.String() != "192.0.2.1" {
		t.Fatalf("%v %+v", err, resp)
	}
	c.TCP = true
	resp, err = c.Exchange(context.Background(), s.Addr(), "example.test", dnsmsg.TypeA, true)
	if err != nil || resp.Network != "tcp" || !resp.Msg.RecursionAvailable {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestServerTruncationRoundTripWithClientFallback(t *testing.T) {
	s := startServer(t, &stub{fn: bigTXT})
	c := &resolver.Client{Timeout: time.Second, NoRetry: true}
	resp, err := c.Exchange(context.Background(), s.Addr(), "big.test", dnsmsg.TypeTXT, true)
	if err != nil || !resp.FellBackToTCP || len(resp.Msg.Answers) != 1 {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestServerTCPHandlesSeveralQueriesOnOneConnection(t *testing.T) {
	s := startServer(t, &stub{fn: constA})
	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 3; i++ {
		pkt, _ := dnsmsg.NewQuery(uint16(i+1), "example.test", dnsmsg.TypeA, true, false).Pack()
		if err := resolver.WriteTCPMessage(conn, pkt); err != nil {
			t.Fatal(err)
		}
		raw, err := resolver.ReadTCPMessage(conn)
		if err != nil {
			t.Fatal(err)
		}
		m, err := dnsmsg.Unpack(raw)
		if err != nil || m.ID != uint16(i+1) {
			t.Fatalf("%v %+v", err, m)
		}
	}
}

func TestServerWithRealResolverAndFakeRoot(t *testing.T) {
	root := fakedns.Start(t, (&fakedns.Zone{Origin: ".", RRs: []dnsmsg.RR{
		fakedns.A("example.test.", "192.0.2.77"),
		fakedns.RR("www.example.test.", 60, dnsmsg.CNAME{Target: "example.test."}),
	}}).Handle)
	rootIP := netip.MustParseAddr("192.0.2.1")
	r := &resolver.Resolver{
		Client: &resolver.Client{Timeout: time.Second, NoRetry: true},
		Roots:  []resolver.RootServer{{Name: "a.root.test.", V4: rootIP}},
		Addr:   func(netip.Addr) string { return root.Addr },
	}
	s := startServer(t, r)
	c := &resolver.Client{Timeout: time.Second, NoRetry: true}
	for i := 0; i < 2; i++ {
		resp, err := c.Exchange(context.Background(), s.Addr(), "www.example.test", dnsmsg.TypeA, true)
		if err != nil || len(resp.Msg.Answers) != 2 || resp.Msg.Answers[1].Data.String() != "192.0.2.77" {
			t.Fatalf("%v %+v", err, resp)
		}
	}
	if root.Queries() != 1 {
		t.Fatalf("root saw %d queries, second answer should come from the cache", root.Queries())
	}
	resp, err := c.Exchange(context.Background(), s.Addr(), "missing.example.test", dnsmsg.TypeA, true)
	if err != nil || resp.Msg.RCode != dnsmsg.RCodeNameError {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestServerCloseReleasesPorts(t *testing.T) {
	s := New(Config{Addr: "127.0.0.1:0", Resolver: &stub{fn: constA}})
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	addr := s.Addr()
	s.Close()
	s2 := New(Config{Addr: addr, Resolver: &stub{fn: constA}})
	if err := s2.Start(); err != nil {
		t.Fatalf("port not released: %v", err)
	}
	s2.Close()
}

func TestStartRejectsBadAddress(t *testing.T) {
	if err := New(Config{Addr: "not-an-address"}).Start(); err == nil {
		t.Fatal("expected error")
	}
}
