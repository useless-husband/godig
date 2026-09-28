package cli

import (
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/resolver"
)

// tracePrinter turns resolver events into the +trace listing.
type tracePrinter struct {
	w     io.Writer
	step  int
	names map[netip.Addr]string
}

func newTracePrinter(w io.Writer, roots []resolver.RootServer) *tracePrinter {
	p := &tracePrinter{w: w, names: map[netip.Addr]string{}}
	for _, r := range roots {
		if r.V4.IsValid() {
			p.names[r.V4] = r.Name
		}
		if r.V6.IsValid() {
			p.names[r.V6] = r.Name
		}
	}
	return p
}

func (p *tracePrinter) printf(depth int, format string, args ...any) {
	fmt.Fprintf(p.w, strings.Repeat("    ", depth)+format+"\n", args...)
}

func (p *tracePrinter) rr(depth int, rr dnsmsg.RR) {
	fmt.Fprintln(p.w, strings.Repeat("    ", depth)+rrLine(rr))
}

// Event prints one resolver step.
func (p *tracePrinter) Event(e resolver.Event) {
	d := e.Depth
	switch e.Kind {
	case resolver.KindNSLookup:
		p.printf(d, ";; no glue for %s, so its address is looked up first:", e.Target)
		return
	case resolver.KindNSFound:
		for _, a := range e.NS[0].Addrs {
			p.names[a] = e.Target
		}
		p.printf(d, ";; %s is now known; continuing with the original question", e.Target)
		return
	case resolver.KindNSLoop:
		p.printf(d, ";; %s is already being looked up further up: %s", e.Target, e.Note)
		return
	}
	p.step++
	who := p.names[e.Server]
	if who == "" {
		who = "?"
	}
	zone := e.Zone
	p.printf(d, ";; [%d] ask %s (%s#53), zone %q: %s %s", p.step, who, e.Server, zone, e.Question.Name, e.Question.Type)
	if e.Err != nil && e.Resp == nil {
		p.printf(d, ";;     failed: %v", e.Err)
		return
	}
	m := e.Resp.Msg
	switch e.Kind {
	case resolver.KindReferral:
		p.printf(d, ";;     referral to %s (%d nameservers)", e.Next, len(e.NS))
		for _, rr := range m.Authorities {
			if rr.Type() == dnsmsg.TypeNS && dnsmsg.EqualNames(rr.Name, e.Next) {
				p.rr(d, rr)
			}
		}
		for _, ns := range e.NS {
			for _, a := range ns.Addrs {
				p.names[a] = ns.Host
			}
			if len(ns.Addrs) == 0 {
				p.printf(d, ";;     glue: %s has none", ns.Host)
				continue
			}
			var addrs []string
			for _, a := range ns.Addrs {
				addrs = append(addrs, a.String())
			}
			p.printf(d, ";;     glue: %s = %s", ns.Host, strings.Join(addrs, ", "))
		}
	case resolver.KindAnswer, resolver.KindCNAME:
		for _, rr := range m.Answers {
			p.rr(d, rr)
		}
		if e.Kind == resolver.KindCNAME {
			p.printf(d, ";;     answer ends in a CNAME; continuing with %s from the root", e.Target)
		}
	case resolver.KindNXDomain, resolver.KindNoData:
		if e.Kind == resolver.KindNXDomain {
			p.printf(d, ";;     status: NXDOMAIN (the name does not exist)")
		} else {
			p.printf(d, ";;     status: NOERROR but no data of this type")
		}
		for _, rr := range m.Authorities {
			if rr.Type() == dnsmsg.TypeSOA {
				p.rr(d, rr)
			}
		}
	case resolver.KindError:
		p.printf(d, ";;     failed: %v", e.Err)
	}
	how := strings.ToUpper(e.Resp.Network)
	if e.Resp.FellBackToTCP {
		how = "UDP truncated, retried over TCP"
	}
	p.printf(d, ";;     received %d bytes in %d ms (%s)", e.Resp.Size, e.Resp.RTT.Milliseconds(), how)
}
