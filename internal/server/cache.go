// Package server implements godig's small recursive DNS server: a TTL cache
// with negative caching, request coalescing and a UDP+TCP front end.
package server

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/useless-husband/godig/internal/dnsmsg"
	"github.com/useless-husband/godig/internal/resolver"
)

type cacheKey struct {
	name string
	typ  dnsmsg.Type
}

type entry struct {
	rcode     dnsmsg.RCode
	answers   []dnsmsg.RR
	authority []dnsmsg.RR
	stored    time.Time
	ttl       uint32
}

// Cache stores answers until their TTL runs out. Negative answers (NXDOMAIN
// and NODATA) are cached for min(SOA TTL, SOA MINIMUM) as RFC 2308 says.
type Cache struct {
	MaxTTL    uint32 // upper bound for positive entries (default 86400)
	MaxNegTTL uint32 // upper bound for negative entries (default 3600)
	MaxItems  int    // default 10000

	now func() time.Time
	mu  sync.Mutex
	m   map[cacheKey]*entry

	hits, misses atomic.Int64
}

// NewCache creates a cache reading time from now (time.Now if nil).
func NewCache(now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{now: now, m: map[cacheKey]*entry{}}
}

// Stats returns the number of hits and misses seen by Get.
func (c *Cache) Stats() (hits, misses int64) { return c.hits.Load(), c.misses.Load() }

// Len is the current number of entries (expired ones included until touched).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}

func (c *Cache) maxTTL() uint32 {
	if c.MaxTTL > 0 {
		return c.MaxTTL
	}
	return 86400
}

func (c *Cache) maxNegTTL() uint32 {
	if c.MaxNegTTL > 0 {
		return c.MaxNegTTL
	}
	return 3600
}

// TTLFor computes how long a result may be cached, in seconds (0 = do not cache).
func (c *Cache) TTLFor(res *resolver.Result) uint32 {
	if res.RCode != dnsmsg.RCodeSuccess && res.RCode != dnsmsg.RCodeNameError {
		return 0
	}
	if len(res.Answers) > 0 {
		ttl := res.Answers[0].TTL
		for _, rr := range res.Answers {
			ttl = min(ttl, rr.TTL)
		}
		return min(ttl, c.maxTTL())
	}
	for _, rr := range res.Authorities {
		if soa, ok := rr.Data.(dnsmsg.SOA); ok {
			return min(min(rr.TTL, soa.Minimum), c.maxNegTTL())
		}
	}
	return 0
}

// Put stores res under name/type if it is cacheable.
func (c *Cache) Put(name string, t dnsmsg.Type, res *resolver.Result) {
	ttl := c.TTLFor(res)
	if ttl == 0 {
		return
	}
	e := &entry{
		rcode:     res.RCode,
		answers:   append([]dnsmsg.RR(nil), res.Answers...),
		authority: append([]dnsmsg.RR(nil), res.Authorities...),
		stored:    c.now(),
		ttl:       ttl,
	}
	if len(e.answers) == 0 {
		// RFC 2308: a cached negative answer carries the SOA with the
		// TTL it was cached for (the smaller of SOA TTL and MINIMUM).
		for i, rr := range e.authority {
			if soa, ok := rr.Data.(dnsmsg.SOA); ok {
				e.authority[i].TTL = min(rr.TTL, soa.Minimum, ttl)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	max := c.MaxItems
	if max <= 0 {
		max = 10000
	}
	if len(c.m) >= max {
		c.evictLocked(max)
	}
	c.m[cacheKey{dnsmsg.CanonicalName(name), t}] = e
}

func (c *Cache) evictLocked(max int) {
	now := c.now()
	for k, e := range c.m {
		if !now.Before(e.stored.Add(time.Duration(e.ttl) * time.Second)) {
			delete(c.m, k)
		}
	}
	for k := range c.m { // still full: drop arbitrary entries
		if len(c.m) < max {
			break
		}
		delete(c.m, k)
	}
}

// Get returns a cached result with TTLs reduced by the time spent in the cache.
func (c *Cache) Get(name string, t dnsmsg.Type) (*resolver.Result, bool) {
	k := cacheKey{dnsmsg.CanonicalName(name), t}
	c.mu.Lock()
	e, ok := c.m[k]
	var elapsed uint32
	if ok {
		secs := c.now().Sub(e.stored) / time.Second
		if secs < 0 {
			secs = 0
		}
		if secs >= time.Duration(e.ttl) {
			delete(c.m, k)
			ok = false
		} else {
			elapsed = uint32(secs)
		}
	}
	c.mu.Unlock()
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	res := &resolver.Result{RCode: e.rcode}
	res.Answers = decay(e.answers, elapsed)
	res.Authorities = decay(e.authority, elapsed)
	return res, true
}

func decay(rrs []dnsmsg.RR, elapsed uint32) []dnsmsg.RR {
	out := make([]dnsmsg.RR, len(rrs))
	for i, rr := range rrs {
		if rr.TTL > elapsed {
			rr.TTL -= elapsed
		} else {
			rr.TTL = 0
		}
		out[i] = rr
	}
	return out
}

// group merges concurrent calls for the same key into one (like
// golang.org/x/sync/singleflight, written out to stay dependency free).
type group struct {
	mu sync.Mutex
	m  map[string]*call
}

type call struct {
	dups int // callers that joined instead of running fn
	wg   sync.WaitGroup
	res  *resolver.Result
	err  error
}

// do runs fn once per key at a time; concurrent callers wait for and share
// its result. shared reports whether this caller piggybacked on another.
func (g *group) do(key string, fn func() (*resolver.Result, error)) (res *resolver.Result, err error, shared bool) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*call{}
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.mu.Unlock()
		c.wg.Wait()
		return c.res, c.err, true
	}
	c := &call{}
	c.wg.Add(1)
	g.m[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		c.wg.Done()
	}()
	c.res, c.err = fn()
	return c.res, c.err, false
}

// waiting reports how many callers are currently sharing the in-flight call
// for key (used by tests to know when everyone has joined).
func (g *group) waiting(key string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if c, ok := g.m[key]; ok {
		return c.dups
	}
	return 0
}
