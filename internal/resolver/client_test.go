package resolver

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/fakedns"
)

type constReader byte

func (c constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}

func testZone() *fakedns.Zone {
	return &fakedns.Zone{Origin: "example.test.", RRs: []dnsmsg.RR{
		fakedns.A("example.test.", "192.0.2.10"),
		fakedns.RR("big.example.test.", 60, dnsmsg.TXT{Strings: []string{
			strings.Repeat("a", 250), strings.Repeat("b", 250), strings.Repeat("c", 250), strings.Repeat("d", 250), strings.Repeat("e", 250)}}),
	}}
}

func fast() *Client { return &Client{Timeout: 300 * time.Millisecond, NoRetry: true} }

func TestClientBasicUDP(t *testing.T) {
	srv := fakedns.Start(t, testZone().Handle)
	resp, err := fast().Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Network != "udp" || len(resp.Msg.Answers) != 1 || resp.Msg.Answers[0].Data.String() != "192.0.2.10" {
		t.Fatalf("%+v", resp.Msg)
	}
	if resp.Size == 0 || resp.Server != srv.Addr {
		t.Fatalf("%+v", resp)
	}
}

func TestClientRTTUsesInjectedClock(t *testing.T) {
	srv := fakedns.Start(t, testZone().Handle)
	base := time.Unix(1000, 0)
	var calls atomic.Int64
	c := fast()
	c.Now = func() time.Time { return base.Add(time.Duration(calls.Add(1)) * 7 * time.Millisecond) }
	resp, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.RTT != 7*time.Millisecond {
		t.Fatalf("rtt %v", resp.RTT)
	}
}

func TestClientIDComesFromRandSource(t *testing.T) {
	var seen atomic.Int64
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		seen.Store(int64(req.ID))
		return testZone().Handle(req, "udp")
	})
	c := fast()
	c.Rand = bytes.NewReader([]byte{0x12, 0x34, 0x56, 0x78})
	if _, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true); err != nil {
		t.Fatal(err)
	}
	if seen.Load() != 0x1234 {
		t.Fatalf("id %#x", seen.Load())
	}
}

func forgedFirst(mut func(b []byte) []byte) fakedns.Option {
	return fakedns.WithMangle(func(_ *dnsmsg.Message, reply []byte) [][]byte {
		bad := mut(append([]byte(nil), reply...))
		return [][]byte{bad, reply}
	})
}

func TestClientIgnoresReplyWithWrongID(t *testing.T) {
	srv := fakedns.Start(t, testZone().Handle, forgedFirst(func(b []byte) []byte { b[0] ^= 0xff; return b }))
	resp, err := fast().Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil || len(resp.Msg.Answers) != 1 {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestClientIgnoresReplyForOtherQuestion(t *testing.T) {
	forged := func(b []byte) []byte {
		m, _ := dnsmsg.Unpack(b)
		m.Questions[0].Name = "evil.test."
		m.Answers = []dnsmsg.RR{fakedns.A("evil.test.", "6.6.6.6")}
		out, _ := m.Pack()
		return out
	}
	srv := fakedns.Start(t, testZone().Handle, forgedFirst(forged))
	resp, err := fast().Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil || resp.Msg.Answers[0].Data.String() != "192.0.2.10" {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestClientIgnoresQueryPacketsAndGarbage(t *testing.T) {
	garbage := fakedns.WithMangle(func(_ *dnsmsg.Message, reply []byte) [][]byte {
		q := append([]byte(nil), reply...)
		q[2] &^= 0x80 // QR=0: looks like a query, not a response
		return [][]byte{{1, 2, 3}, q, reply}
	})
	srv := fakedns.Start(t, testZone().Handle, garbage)
	if _, err := fast().Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true); err != nil {
		t.Fatal(err)
	}
}

func TestClientTimeout(t *testing.T) {
	srv := fakedns.Start(t, func(*dnsmsg.Message, string) *dnsmsg.Message { return nil })
	c := &Client{Timeout: 80 * time.Millisecond, NoRetry: true}
	_, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestClientRetrySucceedsOnSecondAttempt(t *testing.T) {
	var n atomic.Int64
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		if n.Add(1) == 1 {
			return nil
		}
		return testZone().Handle(req, "udp")
	})
	c := &Client{Timeout: 100 * time.Millisecond, Retries: 2}
	if _, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true); err != nil {
		t.Fatal(err)
	}
	if srv.UDPQueries() != 2 {
		t.Fatalf("queries %d", srv.UDPQueries())
	}
}

func TestClientContextCancel(t *testing.T) {
	srv := fakedns.Start(t, func(*dnsmsg.Message, string) *dnsmsg.Message { return nil })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	c := &Client{Timeout: 5 * time.Second}
	start := time.Now()
	if _, err := c.Exchange(ctx, srv.Addr, "example.test", dnsmsg.TypeA, true); err == nil {
		t.Fatal("expected error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("context deadline ignored")
	}
}

func TestClientTruncatedUDPFallsBackToTCP(t *testing.T) {
	srv := fakedns.Start(t, testZone().Handle)
	resp, err := fast().Exchange(context.Background(), srv.Addr, "big.example.test", dnsmsg.TypeTXT, true)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.FellBackToTCP || resp.Network != "tcp" || resp.Msg.Truncated {
		t.Fatalf("%+v", resp)
	}
	if got := len(resp.Msg.Answers[0].Data.(dnsmsg.TXT).Strings); got != 5 {
		t.Fatalf("strings %d", got)
	}
	if srv.UDPQueries() != 1 || srv.TCPQueries() != 1 {
		t.Fatalf("udp=%d tcp=%d", srv.UDPQueries(), srv.TCPQueries())
	}
}

func TestClientTruncationWithoutEDNSUses512Limit(t *testing.T) {
	// 300 bytes fit in 1232 but not in the classic 512 when combined with more data.
	srv := fakedns.Start(t, testZone().Handle)
	c := fast()
	c.NoEDNS = true
	resp, err := c.Exchange(context.Background(), srv.Addr, "big.example.test", dnsmsg.TypeTXT, true)
	if err != nil || !resp.FellBackToTCP {
		t.Fatalf("%v %+v", err, resp)
	}
}

func TestClientTCPOnly(t *testing.T) {
	srv := fakedns.Start(t, testZone().Handle)
	c := fast()
	c.TCP = true
	resp, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil || resp.Network != "tcp" || resp.FellBackToTCP {
		t.Fatalf("%v %+v", err, resp)
	}
	if srv.UDPQueries() != 0 {
		t.Fatal("UDP used")
	}
}

func TestClientTCPFallbackFailureReported(t *testing.T) {
	srv := fakedns.Start(t, testZone().Handle)
	srv.Close() // both UDP and TCP now refuse
	_, err := fast().Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err == nil {
		t.Fatal("expected error from closed server")
	}
}

func TestClient0x20SendsMixedCaseAndAcceptsEcho(t *testing.T) {
	var seen atomic.Value
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		seen.Store(req.Questions[0].Name)
		return testZone().Handle(req, "udp")
	})
	c := fast()
	c.Use0x20 = true
	c.Rand = constReader(0xff) // flips every letter to upper case
	resp, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil {
		t.Fatal(err)
	}
	if seen.Load() != "EXAMPLE.TEST." {
		t.Fatalf("query name on the wire: %v", seen.Load())
	}
	// The randomized casing is undone for display.
	if resp.Msg.Questions[0].Name != "example.test." || resp.Msg.Answers[0].Name != "example.test." {
		t.Fatalf("case not restored: %v / %v", resp.Msg.Questions[0].Name, resp.Msg.Answers[0].Name)
	}
}

func TestClient0x20FallsBackWhenServerLowercases(t *testing.T) {
	srv := fakedns.Start(t, func(req *dnsmsg.Message, _ string) *dnsmsg.Message {
		resp := testZone().Handle(req, "udp")
		resp.Questions = []dnsmsg.Question{{Name: strings.ToLower(req.Questions[0].Name), Type: req.Questions[0].Type, Class: req.Questions[0].Class}}
		return resp
	})
	c := &Client{Timeout: 100 * time.Millisecond, Retries: 2, Use0x20: true, Rand: constReader(0xff)}
	resp, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil || len(resp.Msg.Answers) != 1 {
		t.Fatalf("%v %+v", err, resp)
	}
	if srv.UDPQueries() != 2 {
		t.Fatalf("expected one 0x20 attempt and one plain retry, got %d", srv.UDPQueries())
	}
}

func TestClient0x20RejectsForgedLowercaseReply(t *testing.T) {
	// A forged packet with the right ID but wrong letter case must not be accepted.
	forge := fakedns.WithMangle(func(_ *dnsmsg.Message, reply []byte) [][]byte {
		m, _ := dnsmsg.Unpack(reply)
		m.Questions[0].Name = strings.ToLower(m.Questions[0].Name)
		m.Answers = []dnsmsg.RR{fakedns.A("example.test.", "6.6.6.6")}
		bad, _ := m.Pack()
		return [][]byte{bad, reply}
	})
	srv := fakedns.Start(t, testZone().Handle, forge)
	c := fast()
	c.Use0x20 = true
	c.Rand = constReader(0xff)
	resp, err := c.Exchange(context.Background(), srv.Addr, "example.test", dnsmsg.TypeA, true)
	if err != nil || resp.Msg.Answers[0].Data.String() != "192.0.2.10" {
		t.Fatalf("forged answer accepted: %v %+v", err, resp)
	}
}

func TestRandomize0x20Pattern(t *testing.T) {
	got := Randomize0x20("abcdefgh.", constReader(0xaa))
	if got != "aBcDeFgH." {
		t.Fatal(got)
	}
	if Randomize0x20("Ab-1.", constReader(0xff)) != "AB-1." {
		t.Fatal("digits and punctuation must stay unchanged")
	}
	if !dnsmsg.EqualNames(Randomize0x20("WwW.ExAmPlE.com", constReader(0x5a)), "www.example.com") {
		t.Fatal("must stay equal ignoring case")
	}
}

func TestTCPFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteTCPMessage(&buf, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0, 5, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("%x", buf.Bytes())
	}
	got, err := ReadTCPMessage(&buf)
	if err != nil || string(got) != "hello" {
		t.Fatal(got, err)
	}
	if _, err := ReadTCPMessage(bytes.NewReader([]byte{0, 9, 1})); err == nil {
		t.Fatal("short body must fail")
	}
	if WriteTCPMessage(&buf, make([]byte, 70000)) == nil {
		t.Fatal("oversized message must fail")
	}
}

func TestRestoreCase(t *testing.T) {
	for _, c := range []struct{ name, sent, orig, want string }{
		{"WwW.EXaMplE.CoM.", "WwW.EXaMplE.CoM.", "www.example.com.", "www.example.com."},
		{"hera.ns.cloudflare.Com.", "wWw.exAMple.Com.", "www.example.com.", "hera.ns.cloudflare.com."},
		{"other.net.", "wWw.exAMple.Com.", "www.example.com.", "other.net."},
		{".", "Ab.", "ab.", "."},
	} {
		if got := restoreCase(c.name, c.sent, c.orig); got != c.want {
			t.Errorf("restoreCase(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}
