package fakedns

import (
	"net/netip"
	"strings"

	"github.com/useless-husband/godig/internal/dnsmsg"
)

// Cut delegates a child zone. Glue maps nameserver host to an IP; hosts
// without an entry are delegated without glue.
type Cut struct {
	Zone string
	NS   []string
	Glue map[string]string
}

// Zone is a tiny authoritative zone.
type Zone struct {
	Origin string
	RRs    []dnsmsg.RR
	Cuts   []Cut
	// NegTTL is the SOA TTL and minimum used in negative answers (default 300).
	NegTTL uint32
}

// RR builds a record with IN class and TTL 60 unless ttl is given.
func RR(name string, ttl uint32, d dnsmsg.RData) dnsmsg.RR {
	return dnsmsg.RR{Name: dnsmsg.FQDN(name), Class: dnsmsg.ClassIN, TTL: ttl, Data: d}
}

// A builds an A record.
func A(name, ip string) dnsmsg.RR {
	return RR(name, 60, dnsmsg.A{Addr: netip.MustParseAddr(ip)})
}

// SOA returns the zone's SOA record.
func (z *Zone) SOA() dnsmsg.RR {
	ttl := z.NegTTL
	if ttl == 0 {
		ttl = 300
	}
	return RR(z.Origin, ttl, dnsmsg.SOA{MName: "ns." + strings.TrimPrefix(dnsmsg.FQDN(z.Origin), "."), RName: "hostmaster." + strings.TrimPrefix(dnsmsg.FQDN(z.Origin), "."),
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minimum: ttl})
}

// Handle implements Handler.
func (z *Zone) Handle(req *dnsmsg.Message, network string) *dnsmsg.Message {
	if len(req.Questions) != 1 {
		return &dnsmsg.Message{Header: dnsmsg.Header{RCode: dnsmsg.RCodeFormatError}}
	}
	q := req.Questions[0]
	resp := &dnsmsg.Message{Header: dnsmsg.Header{RecursionDesired: req.RecursionDesired}, Questions: req.Questions}
	if _, ok := req.OPTRecord(); ok {
		resp.SetEDNS(dnsmsg.DefaultUDPSize, false)
	}
	for _, c := range z.Cuts {
		if !dnsmsg.IsSubdomain(q.Name, c.Zone) {
			continue
		}
		for _, h := range c.NS {
			resp.Authorities = append(resp.Authorities, RR(c.Zone, 172800, dnsmsg.NS{Host: h}))
			if ip, ok := c.Glue[h]; ok {
				resp.Additionals = append(resp.Additionals, A(h, ip))
			}
		}
		return resp
	}
	resp.Authoritative = true
	name := q.Name
	exists := false
	for hops := 0; hops < 8; hops++ {
		var direct []dnsmsg.RR
		var cname *dnsmsg.RR
		for i, rr := range z.RRs {
			if !dnsmsg.EqualNames(rr.Name, name) {
				continue
			}
			exists = true
			if rr.Type() == q.Type || q.Type == dnsmsg.TypeANY {
				direct = append(direct, rr)
			} else if rr.Type() == dnsmsg.TypeCNAME {
				cname = &z.RRs[i]
			}
		}
		if len(direct) > 0 {
			resp.Answers = append(resp.Answers, direct...)
			return resp
		}
		if cname == nil {
			break
		}
		resp.Answers = append(resp.Answers, *cname)
		name = cname.Data.(dnsmsg.CNAME).Target
		if !dnsmsg.IsSubdomain(name, z.Origin) {
			return resp // target elsewhere: the client must restart
		}
	}
	if len(resp.Answers) > 0 {
		return resp
	}
	if !exists {
		resp.RCode = dnsmsg.RCodeNameError
	}
	resp.Authorities = append(resp.Authorities, z.SOA())
	return resp
}
