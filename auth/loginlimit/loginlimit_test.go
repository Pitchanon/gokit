package loginlimit

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) add(d time.Duration)     { c.t = c.t.Add(d) }
func newClock() *clock                   { return &clock{t: time.Unix(1_700_000_000, 0)} }
func limiter(c *clock, max int) *Limiter { return New(Config{MaxFails: max, Now: c.now}) }

func TestDefaults(t *testing.T) {
	cfg := New(Config{}).Config()
	if cfg.MaxFails != DefaultMaxFails || cfg.LockFor != DefaultLockFor || cfg.Window != DefaultWindow || cfg.Now == nil {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestLocksAfterMaxFails(t *testing.T) {
	c := newClock()
	l := limiter(c, 8)
	keys := []string{"ip:1.2.3.4", "user:DEMO"}
	for i := 0; i < 7; i++ {
		l.Fail(keys...)
		if locked, _ := l.Locked(keys...); locked {
			t.Fatalf("locked after %d failures, limit is 8", i+1)
		}
	}
	l.Fail(keys...)
	locked, left := l.Locked(keys...)
	if !locked || left != DefaultLockFor {
		t.Fatalf("locked=%v left=%v, want true %v", locked, left, DefaultLockFor)
	}
	c.add(DefaultLockFor)
	if locked, _ := l.Locked(keys...); locked {
		t.Error("lock must expire after LockFor")
	}
}

func TestAnyKeyLocks(t *testing.T) {
	c := newClock()
	l := limiter(c, 3)
	for i := 0; i < 3; i++ {
		l.Fail("ip:9.9.9.9")
	}
	if locked, _ := l.Locked("ip:9.9.9.9", "user:OTHER"); !locked {
		t.Error("a locked IP must block any account")
	}
	if locked, _ := l.Locked("ip:8.8.8.8", "user:OTHER"); locked {
		t.Error("other IPs must not be affected")
	}
}

func TestResetOnSuccess(t *testing.T) {
	c := newClock()
	l := limiter(c, 3)
	l.Fail("k")
	l.Fail("k")
	l.Reset("k")
	l.Fail("k")
	if locked, _ := l.Locked("k"); locked {
		t.Error("failures before Reset must not count")
	}
}

func TestWindowExpires(t *testing.T) {
	c := newClock()
	l := limiter(c, 3)
	l.Fail("k")
	l.Fail("k")
	c.add(DefaultWindow + time.Minute)
	l.Fail("k")
	if locked, _ := l.Locked("k"); locked {
		t.Error("failures outside the window must not count")
	}
}

func TestFailures(t *testing.T) {
	c := newClock()
	l := limiter(c, 3)
	if n := l.Failures("k"); n != 0 {
		t.Errorf("unknown key: %d", n)
	}
	l.Fail("k")
	l.Fail("k")
	if n := l.Failures("k"); n != 2 {
		t.Errorf("after 2 failures: %d", n)
	}
	l.Fail("k") // third failure locks and restarts the count
	if n := l.Failures("k"); n != 0 {
		t.Errorf("after lock: %d", n)
	}
	l.Reset("k")
	l.Fail("k")
	c.add(DefaultWindow + time.Second)
	if n := l.Failures("k"); n != 0 {
		t.Errorf("after window: %d", n)
	}
}

func TestSweepDropsExpired(t *testing.T) {
	c := newClock()
	l := limiter(c, 3)
	for i := 0; i < sweepAbove; i++ {
		l.Fail(fmt.Sprintf("ip:%d", i))
	}
	c.add(DefaultWindow + time.Minute)
	l.Fail("fresh")
	l.mu.Lock()
	n := len(l.m)
	l.mu.Unlock()
	if n != 1 {
		t.Errorf("map holds %d entries after sweep, want 1", n)
	}
}

func TestLockedReportsLongestWait(t *testing.T) {
	c := newClock()
	l := limiter(c, 1)
	l.Fail("ip:1.2.3.4")
	c.add(10 * time.Minute)
	l.Fail("user:DEMO")
	// The IP lock has 5 minutes left, the user lock 15; the user can only get
	// in after the later one, whichever key is listed first.
	for _, keys := range [][]string{{"ip:1.2.3.4", "user:DEMO"}, {"user:DEMO", "ip:1.2.3.4"}} {
		if locked, left := l.Locked(keys...); !locked || left != DefaultLockFor {
			t.Errorf("Locked(%v) = %v, %v; want true, %v", keys, locked, left, DefaultLockFor)
		}
	}
}

func TestSweepIsSpacedOut(t *testing.T) {
	c := newClock()
	l := limiter(c, 3)
	for i := 0; i < sweepAbove; i++ {
		l.Fail(fmt.Sprintf("ip:%d", i))
	}
	c.add(DefaultWindow - 10*time.Second)
	l.Fail("first") // sweeps, but nothing has expired yet
	c.add(20 * time.Second)
	l.Fail("too-soon") // the 1000 have expired, but the last sweep was 20s ago
	l.mu.Lock()
	n := len(l.m)
	l.mu.Unlock()
	if n != sweepAbove+2 {
		t.Fatalf("map holds %d entries, want %d (no sweep yet)", n, sweepAbove+2)
	}
	c.add(sweepEvery)
	l.Fail("later")
	l.mu.Lock()
	n = len(l.m)
	l.mu.Unlock()
	if n != 3 {
		t.Errorf("map holds %d entries after sweep, want 3", n)
	}
}

func TestIPKey(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":                       "ip:1.2.3.4",
		"::ffff:1.2.3.4":                "ip:1.2.3.4",
		"2001:db8:1:2:aaaa:bbbb:cccc:d": "ip:2001:db8:1:2::/64",
		"2001:db8:1:2::1":               "ip:2001:db8:1:2::/64",
		"2001:db8:1:3::1":               "ip:2001:db8:1:3::/64",
		"fe80::1%eth0":                  "ip:fe80::/64",
		"not-an-ip":                     "ip:not-an-ip",
		"":                              "ip:",
	}
	for in, want := range cases {
		if got := IPKey(in); got != want {
			t.Errorf("IPKey(%q) = %q, want %q", in, got, want)
		}
	}
}
