package fakedns

import (
	"sync"
	"time"
)

// Clock is a manually advanced clock for cache tests.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock starts at a fixed instant.
func NewClock() *Clock {
	return &Clock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

// Now returns the current fake time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance moves the clock forward.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
