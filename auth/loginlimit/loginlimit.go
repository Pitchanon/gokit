// Package loginlimit throttles password guessing on the server side.
//
// A CAPTCHA stops bots, not a patient human, and a check in the browser can be
// bypassed with a single curl command, so the limit that counts has to live on
// the server. Count failures under more than one key, typically:
//
//   - per client IP, to stop one source trying many accounts;
//   - per account, to stop many sources (a botnet) trying one account.
//
// Count per-IP failures under IPKey(ip) rather than the raw address: one IPv6
// host usually owns a whole /64 and could otherwise start afresh with every new
// address it picks.
//
// State is kept in memory, which is right for a single server process. Behind
// several instances each one keeps its own counters, multiplying an attacker's
// budget by the instance count; move the state to shared storage in that case.
// A restart also forgets every counter and lock.
package loginlimit

import (
	"net/netip"
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

// sweepAbove is the map size at which expired entries start being dropped.
// sweepEvery spaces the sweeps out: a sweep walks the whole map, and while a
// flood of distinct keys is still inside its window nothing can be dropped, so
// sweeping on every Fail would cost O(n) per call for no gain.
const (
	sweepAbove = 1000
	sweepEvery = time.Minute
)

type record struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

// Limiter counts failures per key. It is safe for concurrent use.
type Limiter struct {
	cfg       Config
	mu        sync.Mutex
	m         map[string]*record
	lastSweep time.Time
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

// Locked reports whether any of keys is locked and, if so, the time left until
// all of them are free again (the longest remaining lock), so a caller that
// tells the user when to retry never names a time that is still locked.
func (l *Limiter) Locked(keys ...string) (bool, time.Duration) {
	now := l.cfg.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	var left time.Duration
	for _, k := range keys {
		if r := l.m[k]; r != nil && now.Before(r.lockedUntil) {
			left = max(left, r.lockedUntil.Sub(now))
		}
	}
	return left > 0, left
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
	if len(l.m) < sweepAbove || now.Sub(l.lastSweep) < sweepEvery {
		return
	}
	l.lastSweep = now
	for k, r := range l.m {
		if now.After(r.lockedUntil) && now.Sub(r.windowStart) > l.cfg.Window {
			delete(l.m, k)
		}
	}
}

// IPKey returns the key to count an address under: "ip:" plus the address for
// IPv4, or plus its /64 network for IPv6. IPv4-mapped IPv6 addresses
// (::ffff:1.2.3.4) count as the IPv4 address. Text that does not parse as an
// address is used as is, so a bad header cannot make keys collide with real
// ones or with each other.
func IPKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "ip:" + ip
	}
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return "ip:" + a.String()
	}
	return "ip:" + netip.PrefixFrom(a, 64).Masked().String()
}
