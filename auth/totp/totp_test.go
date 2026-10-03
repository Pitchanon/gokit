package totp

import (
	"strings"
	"testing"
	"time"
)

// rfcSecret is the ASCII SHA-1 secret from RFC 6238 Appendix B.
var rfcSecret = []byte("12345678901234567890")

func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix  int64
		eight string
		six   string
	}{
		{59, "94287082", "287082"},
		{1111111109, "07081804", "081804"},
		{1111111111, "14050471", "050471"},
		{1234567890, "89005924", "005924"},
		{2000000000, "69279037", "279037"},
	}
	for _, c := range cases {
		ctr := Counter(time.Unix(c.unix, 0))
		if got := Code(rfcSecret, ctr, 8); got != c.eight {
			t.Errorf("unix %d 8 digits = %s, want %s", c.unix, got, c.eight)
		}
		if got := Code(rfcSecret, ctr, 6); got != c.six {
			t.Errorf("unix %d 6 digits = %s, want %s", c.unix, got, c.six)
		}
		if _, ok := Verify(rfcSecret, c.six, time.Unix(c.unix, 0)); !ok {
			t.Errorf("unix %d: Verify(%s) failed", c.unix, c.six)
		}
	}
}

func TestVerifySkew(t *testing.T) {
	now := time.Unix(1234567890, 0)
	cur := Counter(now)
	for _, off := range []int64{-1, 0, 1} {
		code := Code(rfcSecret, cur+off, Digits)
		got, ok := Verify(rfcSecret, code, now)
		if !ok || got != cur+off {
			t.Errorf("skew %+d must pass (got %d ok=%v)", off, got, ok)
		}
	}
	for _, off := range []int64{-3, -2, 2, 3} {
		code := Code(rfcSecret, cur+off, Digits)
		// A distant step can collide with a near one (1 in 10^6); skip that case.
		collide := false
		for _, near := range []int64{-1, 0, 1} {
			if Code(rfcSecret, cur+near, Digits) == code {
				collide = true
			}
		}
		if collide {
			continue
		}
		if _, ok := Verify(rfcSecret, code, now); ok {
			t.Errorf("skew %+d must fail", off)
		}
	}
}

func TestVerifySkewZero(t *testing.T) {
	now := time.Unix(1234567890, 0)
	cur := Counter(now)
	next := Code(rfcSecret, cur+1, Digits)
	if next != Code(rfcSecret, cur, Digits) {
		if _, ok := VerifySkew(rfcSecret, next, now, 0); ok {
			t.Error("skew 0 must accept the current step only")
		}
	}
	if _, ok := VerifySkew(rfcSecret, Code(rfcSecret, cur, Digits), now, -1); ok {
		t.Error("negative skew must fail")
	}
}

func TestVerifyRejects(t *testing.T) {
	now := time.Unix(1234567890, 0)
	code := Code(rfcSecret, Counter(now), Digits)
	other := []byte("abcdefghijabcdefghij")
	if Code(other, Counter(now), Digits) != code {
		if _, ok := Verify(other, code, now); ok {
			t.Error("a different secret must fail")
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456", "abcdef", "１２３４５６", "-----"} {
		if _, ok := Verify(rfcSecret, bad, now); ok {
			t.Errorf("malformed input %q must fail", bad)
		}
	}
	spaced := code[:3] + " " + code[3:]
	if _, ok := Verify(rfcSecret, spaced, now); !ok {
		t.Errorf("code with a space %q must pass", spaced)
	}
	if _, ok := Verify(nil, code, now); ok {
		t.Error("empty secret must fail")
	}
}

func TestSecretEncoding(t *testing.T) {
	s, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodeSecret(s)
	if len(enc) != 32 || strings.Contains(enc, "=") || strings.ToUpper(enc) != enc {
		t.Errorf("base32 must be 32 upper-case chars without '=': %q", enc)
	}
	back, err := DecodeSecret(strings.ToLower(enc))
	if err != nil || string(back) != string(s) {
		t.Errorf("decode round trip failed")
	}
}

func TestURI(t *testing.T) {
	u := URI("Example", "jane doe@x", rfcSecret)
	for _, part := range []string{"otpauth://totp/Example:jane%20doe%40x", "secret=" + EncodeSecret(rfcSecret),
		"&issuer=Example", "&algorithm=SHA1", "&digits=6", "&period=30"} {
		if !strings.Contains(u, part) {
			t.Errorf("URI missing %q: %s", part, u)
		}
	}
	if strings.Contains(u, "+") || strings.Contains(u, " ") {
		t.Errorf("URI must not contain '+' or a raw space: %s", u)
	}
	if !strings.Contains(URI("Example Co", "a", rfcSecret), "Example%20Co") {
		t.Error("space must become %20")
	}
}
