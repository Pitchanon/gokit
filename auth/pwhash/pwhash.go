// Package pwhash hashes passwords with PBKDF2-HMAC-SHA256 using only the
// standard library (crypto/pbkdf2, Go 1.24+).
//
// The stored form is self-describing:
//
//	pbkdf2-sha256$<iterations>$<salt-base64>$<key-base64>
//
// Because the iteration count travels with the hash, the cost can be raised
// later without invalidating hashes that already exist.
package pwhash

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	algo = "pbkdf2-sha256"
	// Iterations is the cost used for new hashes (OWASP recommends at least
	// 600,000 for PBKDF2-HMAC-SHA256).
	Iterations = 600_000
	saltLen    = 16
	keyLen     = 32
	// minIters rejects stored hashes whose cost is too low to mean anything,
	// e.g. a row that was edited by hand.
	minIters = 1_000
)

// ErrBadFormat reports a stored hash that is not in the expected format.
var ErrBadFormat = errors.New("pwhash: malformed stored hash")

// Hash returns the string to store for password, with a fresh random salt.
func Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, Iterations, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s$%d$%s$%s", algo, Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches stored. A malformed stored value
// never matches. The final comparison is constant-time.
func Verify(stored, password string) bool {
	iter, salt, want, err := parse(stored)
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NeedsRehash reports whether stored was made with fewer iterations than the
// current Iterations, so the caller can re-hash it after a successful login.
func NeedsRehash(stored string) bool {
	iter, _, _, err := parse(stored)
	return err != nil || iter < Iterations
}

// IsHash reports whether s looks like a value produced by Hash, as opposed to
// a legacy plaintext password awaiting migration.
func IsHash(s string) bool {
	return strings.HasPrefix(s, algo+"$")
}

func parse(stored string) (iter int, salt, key []byte, err error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != algo {
		return 0, nil, nil, ErrBadFormat
	}
	iter, err = strconv.Atoi(parts[1])
	if err != nil || iter < minIters {
		return 0, nil, nil, ErrBadFormat
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, nil, ErrBadFormat
	}
	key, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(key) == 0 {
		return 0, nil, nil, ErrBadFormat
	}
	return iter, salt, key, nil
}
