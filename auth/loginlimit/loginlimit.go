// Package loginlimit throttles password guessing on the server side.
//
// A CAPTCHA stops bots, not a patient human, and a check in the browser can be
// bypassed with a single curl command, so the limit that counts has to live on
// the server. Count failures under more than one key, typically:
//
//   - per client IP, to stop one source trying many accounts;
//   - per account, to stop many sources (a botnet) trying one account.
//
// State is kept in memory, which is right for a single server process. Behind
// several instances each one keeps its own counters, multiplying an attacker's
// budget by the instance count; move the state to shared storage in that case.
package loginlimit

import (
	"sync"
	"time"
)

// Config sets the policy. Zero fields take the defaults below.
type Config struct {
	// MaxFails is the number of failures within Window that triggers a lock.
	MaxFails int
	// LockFor is how long a key stays locked.
	LockFor time.Duration
	// Window is how far back failures are counted.
	Window time.Duration
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Defaults used for zero Config fields.
const (
	DefaultMaxFails = 5
	DefaultLockFor  = 15 * time.Minute
	DefaultWindow   = 15 * time.Minute
)

// sweepAbove is the map size at which expired entries are dropped, so a flood
// of distinct IPs cannot grow the map without bound.
const sweepAbove = 1000

type record struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// Limiter counts failures per key. It is safe for concurrent use.
type Limiter struct {
	cfg Config
	mu  sync.Mutex
	m   map[string]*record
}

// New returns a Limiter with cfg, filling in defaults.
func New(cfg Config) *Limiter {
	if cfg.MaxFails <= 0 {
		cfg.MaxFails = DefaultMaxFails
	}
	if cfg.LockFor <= 0 {
		cfg.LockFor = DefaultLockFor
	}
	if cfg.Window <= 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Limiter{cfg: cfg, m: map[string]*record{}}
}

// Config returns the effective policy.
func (l *Limiter) Config() Config { return l.cfg }

// Locked reports whether any of keys is locked and, if so, the time left.
func (l *Limiter) Locked(keys ...string) (bool, time.Duration) {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if r := l.m[k]; r != nil && now.Before(r.lockedUntil) {
			return true, r.lockedUntil.Sub(now)
		}
	}
	return false, 0
}

// Failures returns the failures counted for key in its current window. It is
// 0 for an unknown key, after the window has passed, and right after a lock
// starts (the count restarts once a key is locked).
func (l *Limiter) Failures(key string) int {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.m[key]
	if r == nil || now.Sub(r.windowStart) > l.cfg.Window {
		return 0
	}
	return r.count
}

// Fail records one failed attempt against every key.
func (l *Limiter) Fail(keys ...string) {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweep(now)
	for _, k := range keys {
		r := l.m[k]
		if r == nil || now.Sub(r.windowStart) > l.cfg.Window {
			r = &record{windowStart: now}
			l.m[k] = r
		}
		r.count++
		if r.count >= l.cfg.MaxFails {
			r.lockedUntil = now.Add(l.cfg.LockFor)
			r.count = 0
			r.windowStart = now
		}
	}
}

// Reset forgets the keys, typically after a successful login, so earlier typos
// do not count against the user later.
func (l *Limiter) Reset(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.m, k)
	}
}

func (l *Limiter) sweep(now time.Time) {
	if len(l.m) < sweepAbove {
		return
	}
	for k, r := range l.m {
		if now.After(r.lockedUntil) && now.Sub(r.windowStart) > l.cfg.Window {
			delete(l.m, k)
		}
	}
}
