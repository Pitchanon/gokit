// Package totp implements time-based one-time passwords (RFC 6238) on top of
// HOTP (RFC 4226), using only the standard library.
//
// It uses HMAC-SHA1, 6 digits and a 30-second period, which is what every
// mainstream authenticator app (Google Authenticator, 1Password, Authy, …)
// expects. SHA-1 inside HMAC does not depend on SHA-1 collision resistance, so
// it is not weakened by the known SHA-1 collision attacks.
//
// Verify only checks the code. To stop the same code being accepted twice the
// caller must remember the returned counter and reject any counter that is not
// greater than the last one accepted, e.g.
//
//	UPDATE user_totp SET last_counter = $2 WHERE user_id = $1 AND last_counter < $2
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

const (
	// Period is the length of one time step in seconds.
	Period = 30
	// Digits is the length of the codes Verify accepts.
	Digits = 6
	// SecretBytes is the size of a generated secret: 160 bits as RFC 4226
	// recommends, which is 32 base32 characters and still typeable by hand.
	SecretBytes = 20
	// DefaultSkew is the number of steps accepted before and after the current
	// one, to tolerate clock drift of about ±30 seconds.
	DefaultSkew = 1
)

// b32 is the encoding authenticator apps use: upper case, no padding.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random secret from crypto/rand.
func NewSecret() ([]byte, error) {
	b := make([]byte, SecretBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// EncodeSecret returns the base32 form shown to users and put in the QR code.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// DecodeSecret parses base32 text, tolerating spaces, dashes, padding and
// lower case.
func DecodeSecret(text string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(strings.TrimSpace(text)))
	return b32.DecodeString(clean)
}

// Counter returns the time-step number for t (Unix time / Period).
func Counter(t time.Time) int64 { return t.Unix() / Period }

// Code returns the HOTP value of secret at counter (RFC 4226 section 5.3).
// digits is a parameter so the 8-digit RFC 6238 test vectors can be checked.
func Code(secret []byte, counter int64, digits int) string {
	var block [8]byte
	binary.BigEndian.PutUint64(block[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(block[:])
	sum := mac.Sum(nil)

	off := sum[len(sum)-1] & 0x0f
	v := int64(binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff)
	mod := int64(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	s := strconv.FormatInt(v%mod, 10)
	if len(s) < digits {
		s = strings.Repeat("0", digits-len(s)) + s
	}
	return s
}

// NormalizeCode strips the spaces, dashes and tabs some apps display inside a
// code (e.g. "123 456").
func NormalizeCode(code string) string {
	return strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(code))
}

// Verify checks code against secret at time now with DefaultSkew and returns
// the matching counter.
func Verify(secret []byte, code string, now time.Time) (int64, bool) {
	return VerifySkew(secret, code, now, DefaultSkew)
}

// VerifySkew is Verify with an explicit skew. Codes are compared in constant
// time so response timing does not reveal how many digits were right.
func VerifySkew(secret []byte, code string, now time.Time, skew int) (int64, bool) {
	code = NormalizeCode(code)
	if len(code) != Digits || len(secret) == 0 || skew < 0 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	cur := Counter(now)
	for off := int64(0); off <= int64(skew); off++ {
		for _, c := range [2]int64{cur - off, cur + off} {
			if c < 0 {
				continue
			}
			if hmac.Equal([]byte(Code(secret, c, Digits)), []byte(code)) {
				return c, true
			}
			if off == 0 {
				break
			}
		}
	}
	return 0, false
}

// URI builds the otpauth:// URI encoded in the enrolment QR code.
//
// Spaces must become %20, not '+': the label is a path segment and apps show
// a literal '+' otherwise, so url.QueryEscape is not used.
func URI(issuer, account string, secret []byte) string {
	return "otpauth://totp/" + escape(issuer) + ":" + escape(account) +
		"?secret=" + EncodeSecret(secret) +
		"&issuer=" + escape(issuer) +
		"&algorithm=SHA1" +
		"&digits=" + strconv.Itoa(Digits) +
		"&period=" + strconv.Itoa(Period)
}

// escape percent-encodes every byte that is not unreserved (RFC 3986).
func escape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}
