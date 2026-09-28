package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
)

// Errors of the iterative resolver.
var (
	ErrCNAMELoop      = errors.New("resolver: CNAME loop")
	ErrTooManyCNAMEs  = errors.New("resolver: CNAME chain too long")
	ErrMaxDepth       = errors.New("resolver: nameserver lookups nested too deeply")
	ErrTooManyQueries = errors.New("resolver: too many upstream queries for one question")
	ErrNoServers      = errors.New("resolver: no reachable nameserver")
)

// Event kinds reported to Resolver.Trace.
const (
	KindReferral = "referral" // server delegated to a child zone
	KindAnswer   = "answer"   // final data
	KindCNAME    = "cname"    // answer ends in a CNAME that must be followed
	KindNoData   = "nodata"   // name exists, type does not
	KindNXDomain = "nxdomain"
	KindError    = "error" // timeout, SERVFAIL, lame server...
	KindNSLookup = "ns-lookup"
	KindNSLoop   = "ns-loop"
	KindNSFound  = "ns-found" // the address lookup for a glueless nameserver finished
)

// NSInfo describes one nameserver of a delegation.
type NSInfo struct {
	Host  string
	Addrs []netip.Addr
	Glue  bool // addresses came from the additional section of the referral
}

// Event is emitted for every upstream query (and for a few decisions in
// between) so callers can print a +trace.
type Event struct {
	Depth    int // 0 for the user's question, +1 for each nested nameserver lookup
	Kind     string
	Zone     string // zone the queried server is authoritative for (the parent of Next)
	Server   netip.Addr
	Question dnsmsg.Question
	Resp     *Response
	Err      error
	Next     string   // for referrals: the child zone
	NS       []NSInfo // for referrals
	Target   string   // for CNAME follow / NS lookup
	Note     string
}

// Result is the outcome of a resolution.
type Result struct {
	RCode       dnsmsg.RCode
	Answers     []dnsmsg.RR // CNAME chain followed by the final records
	Authorities []dnsmsg.RR // SOA for negative answers
	Queries     int         // upstream queries sent
}

// Resolver performs iterative resolution starting at the root servers.
type Resolver struct {
	Client *Client
	// IPv6 allows talking to servers over IPv6.
	IPv6 bool
	// Roots overrides the built-in root hints (used by tests).
	Roots []RootServer
	// Addr turns a server IP into the "host:port" to dial; default port 53.
	Addr func(netip.Addr) string
	// Trace, if set, receives an Event per step.
	Trace func(Event)
	// Zones caches delegations between resolutions. Nil disables caching.
	Zones *ZoneCache

	MaxReferrals int // per hop chain, default 16
	MaxCNAME     int // default 8
	MaxDepth     int // nested nameserver lookups, default 6
	MaxQueries   int // per Resolve call, default 64
}

func (r *Resolver) addr(ip netip.Addr) string {
	if r.Addr != nil {
		return r.Addr(ip)
	}
	return net.JoinHostPort(ip.String(), "53")
}

func def(v, d int) int {
	if v > 0 {
		return v
	}
	return d
}

func (r *Resolver) emit(e Event) {
	if r.Trace != nil {
		r.Trace(e)
	}
}

// maxDelegationTTL caps how long a delegation is remembered (seconds).
const maxDelegationTTL = 86400

type nsEntry struct {
	Host  string
	Addrs []netip.Addr
	Glue  bool
}

type delegation struct {
	Zone    string
	NS      []nsEntry
	Expires time.Time
}

type state struct {
	queries   int
	resolving map[string]bool // "name/type" currently being resolved as a nameserver address
}

// Resolve answers name/type by iterating from the root (or the deepest cached
// delegation), following CNAMEs.
func (r *Resolver) Resolve(ctx context.Context, name string, t dnsmsg.Type) (*Result, error) {
	st := &state{resolving: map[string]bool{}}
	res, err := r.resolve(ctx, st, name, t, 0)
	if res != nil {
		res.Queries = st.queries
	}
	return res, err
}

func (r *Resolver) resolve(ctx context.Context, st *state, name string, t dnsmsg.Type, depth int) (*Result, error) {
	res := &Result{}
	cur := dnsmsg.FQDN(name)
	seen := map[string]bool{}
	for n := 0; ; n++ {
		if n > def(r.MaxCNAME, 8) {
			return nil, ErrTooManyCNAMEs
		}
		key := dnsmsg.CanonicalName(cur)
		if seen[key] {
			return nil, fmt.Errorf("%w at %s", ErrCNAMELoop, cur)
		}
		seen[key] = true
		step, err := r.iterate(ctx, st, cur, t, depth)
		if err != nil {
			return nil, err
		}
		res.Answers = append(res.Answers, step.answers...)
		res.RCode = step.rcode
		res.Authorities = step.authority
		if step.cname == "" {
			return res, nil
		}
		cur = step.cname
	}
}

type stepResult struct {
	rcode     dnsmsg.RCode
	answers   []dnsmsg.RR
	authority []dnsmsg.RR
	cname     string // unresolved CNAME target, if the chain did not finish
}

func (r *Resolver) rootDelegation() delegation {
	roots := r.Roots
	if roots == nil {
		roots = RootServers
	}
	d := delegation{Zone: "."}
	for _, rt := range roots {
		e := nsEntry{Host: rt.Name, Glue: true}
		if rt.V4.IsValid() {
			e.Addrs = append(e.Addrs, rt.V4)
		}
		if r.IPv6 && rt.V6.IsValid() {
			e.Addrs = append(e.Addrs, rt.V6)
		}
		d.NS = append(d.NS, e)
	}
	return d
}

func (r *Resolver) startDelegation(name string) delegation {
	if r.Zones != nil {
		if d, ok := r.Zones.Lookup(name); ok {
			return d
		}
	}
	return r.rootDelegation()
}

// iterate follows referrals for one name until a server gives an answer.
func (r *Resolver) iterate(ctx context.Context, st *state, name string, t dnsmsg.Type, depth int) (*stepResult, error) {
	q := dnsmsg.Question{Name: name, Type: t, Class: dnsmsg.ClassIN}
	deleg := r.startDelegation(name)
	for hop := 0; hop < def(r.MaxReferrals, 16); hop++ {
		resp, from, err := r.askDelegation(ctx, st, &deleg, q, depth)
		if err != nil {
			return nil, err
		}
		msg := resp.Msg
		ev := Event{Depth: depth, Zone: deleg.Zone, Server: from, Question: q, Resp: resp}

		if msg.RCode == dnsmsg.RCodeNameError {
			ev.Kind = KindNXDomain
			r.emit(ev)
			return &stepResult{rcode: msg.RCode, authority: negativeAuthority(msg)}, nil
		}
		// (askDelegation only returns NOERROR / NXDOMAIN replies.)
		answers, target, done := followChain(msg.Answers, name, t)
		if len(answers) > 0 {
			if done {
				ev.Kind = KindAnswer
				r.emit(ev)
				return &stepResult{answers: answers}, nil
			}
			ev.Kind = KindCNAME
			ev.Target = target
			ev.Note = "answer ends in a CNAME; restarting from the top for the target"
			r.emit(ev)
			return &stepResult{answers: answers, cname: target}, nil
		}
		if next, ok := referral(msg, deleg.Zone, name); ok {
			nd := buildDelegation(msg, next, deleg.Zone, r.Now())
			ev.Kind = KindReferral
			ev.Next = next
			for _, e := range nd.NS {
				ev.NS = append(ev.NS, NSInfo{Host: e.Host, Addrs: e.Addrs, Glue: e.Glue})
			}
			r.emit(ev)
			if r.Zones != nil {
				r.Zones.Put(nd)
			}
			deleg = nd
			continue
		}
		// Neither data nor delegation: an authoritative "no such type".
		ev.Kind = KindNoData
		r.emit(ev)
		return &stepResult{rcode: dnsmsg.RCodeSuccess, authority: negativeAuthority(msg)}, nil
	}
	return nil, fmt.Errorf("resolver: more than %d referrals for %s", def(r.MaxReferrals, 16), name)
}

// Now returns the resolver's clock (the client's, so tests control both).
func (r *Resolver) Now() time.Time {
	if r.Client != nil && r.Client.Now != nil {
		return r.Client.Now()
	}
	return time.Now()
}

func negativeAuthority(m *dnsmsg.Message) []dnsmsg.RR {
	var out []dnsmsg.RR
	for _, rr := range m.Authorities {
		if rr.Type() == dnsmsg.TypeSOA {
			out = append(out, rr)
		}
	}
	return out
}

// followChain walks the answer section from name along CNAMEs. It returns the
// records that belong to the chain (anything else is ignored: an off-path or
// misbehaving server must not be able to smuggle in unrelated records), the
// last CNAME target, and whether the chain ended in records of type t.
func followChain(rrs []dnsmsg.RR, name string, t dnsmsg.Type) (chain []dnsmsg.RR, target string, done bool) {
	cur := name
	seen := map[string]bool{}
	for !seen[dnsmsg.CanonicalName(cur)] {
		seen[dnsmsg.CanonicalName(cur)] = true
		var direct []dnsmsg.RR
		var cname *dnsmsg.RR
		for i, rr := range rrs {
			if rr.Class != dnsmsg.ClassIN || !dnsmsg.EqualNames(rr.Name, cur) {
				continue
			}
			switch {
			case rr.Type() == t || t == dnsmsg.TypeANY:
				direct = append(direct, rr)
			case rr.Type() == dnsmsg.TypeCNAME && cname == nil:
				cname = &rrs[i]
			}
		}
		if len(direct) > 0 {
			return append(chain, direct...), "", true
		}
		if cname == nil {
			return chain, target, false
		}
		chain = append(chain, *cname)
		target = cname.Data.(dnsmsg.CNAME).Target
		cur = target
	}
	return chain, target, false // loop inside the answer; the caller's loop check reports it
}

// referral looks for NS records in the authority section that delegate a zone
// strictly below the current one and above (or at) the queried name.
func referral(m *dnsmsg.Message, zone, name string) (string, bool) {
	for _, rr := range m.Authorities {
		if rr.Type() != dnsmsg.TypeNS {
			continue
		}
		if dnsmsg.IsSubdomain(name, rr.Name) && dnsmsg.IsSubdomain(rr.Name, zone) && !dnsmsg.EqualNames(rr.Name, zone) {
			return rr.Name, true
		}
	}
	return "", false
}

func buildDelegation(m *dnsmsg.Message, next, parent string, now time.Time) delegation {
	d := delegation{Zone: next}
	minTTL := uint32(maxDelegationTTL)
	index := map[string]int{}
	for _, rr := range m.Authorities {
		ns, ok := rr.Data.(dnsmsg.NS)
		if !ok || !dnsmsg.EqualNames(rr.Name, next) {
			continue
		}
		if rr.TTL < minTTL {
			minTTL = rr.TTL
		}
		if _, dup := index[dnsmsg.CanonicalName(ns.Host)]; dup {
			continue
		}
		index[dnsmsg.CanonicalName(ns.Host)] = len(d.NS)
		d.NS = append(d.NS, nsEntry{Host: ns.Host})
	}
	// Glue is only believed when it is inside the zone that sent it.
	for _, rr := range m.Additionals {
		i, ok := index[dnsmsg.CanonicalName(rr.Name)]
		if !ok || !dnsmsg.IsSubdomain(rr.Name, parent) {
			continue
		}
		switch v := rr.Data.(type) {
		case dnsmsg.A:
			d.NS[i].Addrs = append(d.NS[i].Addrs, v.Addr)
			d.NS[i].Glue = true
		case dnsmsg.AAAA:
			d.NS[i].Addrs = append(d.NS[i].Addrs, v.Addr)
			d.NS[i].Glue = true
		}
	}
	d.Expires = now.Add(time.Duration(minTTL) * time.Second)
	return d
}

// usable filters addresses to the families we may use.
func (r *Resolver) usable(addrs []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() || r.IPv6 {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// askDelegation queries the servers of d until one gives a usable reply
// (NOERROR or NXDOMAIN). Nameservers without addresses are resolved lazily,
// only after the ones that have addresses have failed.
func (r *Resolver) askDelegation(ctx context.Context, st *state, d *delegation, q dnsmsg.Question, depth int) (*Response, netip.Addr, error) {
	var lastErr error
	order := make([]int, 0, len(d.NS))
	for i, e := range d.NS { // glued / already known first
		if len(r.usable(e.Addrs)) > 0 {
			order = append(order, i)
		}
	}
	for i, e := range d.NS {
		if len(r.usable(e.Addrs)) == 0 {
			order = append(order, i)
		}
	}
	tried := 0
	for _, i := range order {
		if err := ctx.Err(); err != nil {
			return nil, netip.Addr{}, err
		}
		addrs := r.usable(d.NS[i].Addrs)
		if len(addrs) == 0 {
			var err error
			addrs, err = r.resolveNSAddrs(ctx, st, d, i, q, depth)
			if err != nil {
				if errors.Is(err, ErrMaxDepth) || errors.Is(err, ErrTooManyQueries) || ctx.Err() != nil {
					return nil, netip.Addr{}, err
				}
				lastErr = err
				continue
			}
		}
		for _, a := range addrs {
			if tried >= 8 {
				break
			}
			tried++
			if st.queries >= def(r.MaxQueries, 64) {
				return nil, netip.Addr{}, ErrTooManyQueries
			}
			st.queries++
			// Iterative queries ask for no recursion (RD=0).
			resp, err := r.Client.Exchange(ctx, r.addr(a), q.Name, q.Type, false)
			ev := Event{Depth: depth, Zone: d.Zone, Server: a, Question: q, Resp: resp, Err: err}
			if err != nil {
				ev.Kind = KindError
				r.emit(ev)
				lastErr = err
				continue
			}
			rc := resp.Msg.RCode
			if rc != dnsmsg.RCodeSuccess && rc != dnsmsg.RCodeNameError {
				ev.Kind = KindError
				ev.Err = fmt.Errorf("%s from %s (%s)", rc, d.NS[i].Host, a)
				r.emit(ev)
				lastErr = ev.Err
				continue
			}
			if !lameFree(resp.Msg, d.Zone, q) {
				ev.Kind = KindError
				ev.Err = fmt.Errorf("lame reply from %s (%s): no answer, no delegation, no SOA", d.NS[i].Host, a)
				r.emit(ev)
				lastErr = ev.Err
				continue
			}
			return resp, a, nil
		}
	}
	if lastErr == nil {
		lastErr = ErrNoServers
	}
	return nil, netip.Addr{}, fmt.Errorf("%w for zone %s: %v", ErrNoServers, d.Zone, lastErr)
}

// lameFree rejects replies that carry nothing useful: an empty NOERROR with
// neither an SOA (authoritative NODATA) nor a delegation nor answers.
func lameFree(m *dnsmsg.Message, zone string, q dnsmsg.Question) bool {
	if m.RCode == dnsmsg.RCodeNameError || len(m.Answers) > 0 {
		return true
	}
	if _, ok := referral(m, zone, q.Name); ok {
		return true
	}
	for _, rr := range m.Authorities {
		if rr.Type() == dnsmsg.TypeSOA {
			return true
		}
	}
	return m.Authoritative
}

// resolveNSAddrs finds the addresses of a nameserver that came without glue
// and records them in the delegation for later hops and for the cache.
func (r *Resolver) resolveNSAddrs(ctx context.Context, st *state, d *delegation, i int, q dnsmsg.Question, depth int) ([]netip.Addr, error) {
	host := d.NS[i].Host
	if depth+1 > def(r.MaxDepth, 6) {
		return nil, ErrMaxDepth
	}
	key := dnsmsg.CanonicalName(host)
	if st.resolving[key] {
		r.emit(Event{Depth: depth, Kind: KindNSLoop, Zone: d.Zone, Question: q, Target: host,
			Note: "already resolving this nameserver name; skipping it to avoid a loop"})
		return nil, fmt.Errorf("loop while resolving nameserver %s", host)
	}
	st.resolving[key] = true
	defer delete(st.resolving, key)
	r.emit(Event{Depth: depth, Kind: KindNSLookup, Zone: d.Zone, Question: q, Target: host,
		Note: "no glue for this nameserver; looking up its address first"})
	var addrs []netip.Addr
	types := []dnsmsg.Type{dnsmsg.TypeA}
	if r.IPv6 {
		types = append(types, dnsmsg.TypeAAAA)
	}
	var firstErr error
	for _, t := range types {
		res, err := r.resolve(ctx, st, host, t, depth+1)
		if err != nil {
			if errors.Is(err, ErrMaxDepth) || errors.Is(err, ErrTooManyQueries) {
				return nil, err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range res.Answers {
			switch v := rr.Data.(type) {
			case dnsmsg.A:
				addrs = append(addrs, v.Addr)
			case dnsmsg.AAAA:
				addrs = append(addrs, v.Addr)
			}
		}
	}
	if len(addrs) == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("nameserver %s has no address", host)
		}
		return nil, firstErr
	}
	d.NS[i].Addrs = addrs
	r.emit(Event{Depth: depth, Kind: KindNSFound, Zone: d.Zone, Question: q, Target: host,
		NS: []NSInfo{{Host: host, Addrs: addrs}}})
	if r.Zones != nil {
		r.Zones.Put(*d)
	}
	return r.usable(addrs), nil
}

// ZoneCache remembers delegations (which servers are authoritative for a
// zone) so that most lookups can skip the root and TLD servers.
type ZoneCache struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]delegation
	max int
}

// NewZoneCache creates a cache using the given clock (time.Now if nil).
func NewZoneCache(now func() time.Time) *ZoneCache {
	if now == nil {
		now = time.Now
	}
	return &ZoneCache{now: now, m: map[string]delegation{}, max: 4096}
}

// Put stores (a copy of) a delegation.
func (c *ZoneCache) Put(d delegation) {
	if d.Zone == "." {
		return
	}
	cp := d
	cp.NS = make([]nsEntry, len(d.NS))
	for i, e := range d.NS {
		e.Addrs = append([]netip.Addr(nil), e.Addrs...)
		cp.NS[i] = e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		c.m = map[string]delegation{}
	}
	c.m[dnsmsg.CanonicalName(d.Zone)] = cp
}

// Lookup returns the deepest unexpired delegation that contains name.
func (c *ZoneCache) Lookup(name string) (delegation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	for z := dnsmsg.CanonicalName(name); z != "."; z = dnsmsg.ParentName(z) {
		d, ok := c.m[z]
		if !ok {
			continue
		}
		if !now.Before(d.Expires) {
			delete(c.m, z)
			continue
		}
		cp := d
		cp.NS = make([]nsEntry, len(d.NS))
		for i, e := range d.NS {
			e.Addrs = append([]netip.Addr(nil), e.Addrs...)
			cp.NS[i] = e
		}
		return cp, true
	}
	return delegation{}, false
}

// Len is the number of cached delegations.
func (c *ZoneCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

// String helps debugging.
func (d delegation) String() string {
	var hosts []string
	for _, e := range d.NS {
		hosts = append(hosts, e.Host)
	}
	return d.Zone + " -> " + strings.Join(hosts, ",")
}
