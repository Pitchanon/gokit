package pwhash

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("1234")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !Verify(h, "1234") {
		t.Error("correct password rejected")
	}
	if Verify(h, "1235") {
		t.Error("wrong password accepted")
	}
	if Verify(h, "") {
		t.Error("empty password accepted")
	}
}

func TestHashIsSaltedPerCall(t *testing.T) {
	a, _ := Hash("1234")
	b, _ := Hash("1234")
	if a == b {
		t.Error("same password produced the same hash: salt missing")
	}
	if !Verify(a, "1234") || !Verify(b, "1234") {
		t.Error("both salted hashes must verify")
	}
}

// TestVerifyKnownVector pins the stored format: a hash written by an earlier
// release must keep verifying. The vector was computed independently with
// Python's hashlib.pbkdf2_hmac("sha256", b"password", b"saltsaltsaltsalt", 1000, 32).
func TestVerifyKnownVector(t *testing.T) {
	const stored = "pbkdf2-sha256$1000$c2FsdHNhbHRzYWx0c2FsdA$" +
		"8nX7hwFEzIB8aPajJTYK8weHQc5Ngz0pFVAKvSu4jQA"
	if !Verify(stored, "password") {
		t.Fatal("known vector no longer verifies")
	}
	if Verify(stored, "Password") {
		t.Error("known vector accepted a different password")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"1234",
		"pbkdf2-sha256$600000$xx",
		"pbkdf2-sha256$abc$c2E$a2V",
		"pbkdf2-sha256$1$c2E$a2V",
		"md5$600000$c2E$a2V",
		"pbkdf2-sha256$600000$!!!$a2V",
		"pbkdf2-sha256$600000$c2E$",
	} {
		if Verify(bad, "1234") {
			t.Errorf("malformed %q verified", bad)
		}
	}
}

func TestIsHash(t *testing.T) {
	h, _ := Hash("1234")
	if !IsHash(h) {
		t.Error("fresh hash not recognised")
	}
	for _, plain := range []string{"1234", "abcd", "", "0000"} {
		if IsHash(plain) {
			t.Errorf("%q recognised as a hash", plain)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	h, _ := Hash("x")
	if NeedsRehash(h) {
		t.Error("fresh hash should not need a rehash")
	}
	if !NeedsRehash("pbkdf2-sha256$1000$c2FsdA$a2V5") {
		t.Error("low-cost hash should need a rehash")
	}
	if !NeedsRehash("garbage") {
		t.Error("malformed value should need a rehash")
	}
}

func TestHashFormat(t *testing.T) {
	h, _ := Hash("x")
	parts := strings.Split(h, "$")
	if len(parts) != 4 {
		t.Fatalf("got %d parts, want 4", len(parts))
	}
	if parts[0] != algo || parts[1] != "600000" {
		t.Errorf("prefix = %s$%s", parts[0], parts[1])
	}
}
