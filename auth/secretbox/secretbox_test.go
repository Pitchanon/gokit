package secretbox

import (
	"encoding/base64"
	"strings"
	"testing"
)

var testLabels = Labels{Secret: "example/totp-secret-v1", Backup: "example/backup-code-v1"}

func TestNewRequiresSecretAndLabels(t *testing.T) {
	if New("", testLabels) != nil {
		t.Error("empty app secret must give nil")
	}
	if New("x", Labels{Secret: "a"}) != nil || New("x", Labels{Backup: "b"}) != nil {
		t.Error("missing label must give nil")
	}
}

func TestEncryptedSecretStorage(t *testing.T) {
	k := New("test-app-secret-1", testLabels)
	s := []byte("12345678901234567890")
	a, err := k.EncryptSecret(s)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := k.EncryptSecret(s)
	if a == b {
		t.Error("ciphertext must differ each time (random nonce)")
	}
	got, err := k.DecryptSecret(a)
	if err != nil || string(got) != string(s) {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := New("test-app-secret-2", testLabels).DecryptSecret(a); err == nil {
		t.Error("a different app secret must not decrypt")
	}
	if _, err := New("test-app-secret-1", Labels{Secret: "other", Backup: testLabels.Backup}).DecryptSecret(a); err == nil {
		t.Error("a different label must not decrypt")
	}
	raw, _ := base64.StdEncoding.DecodeString(a)
	raw[len(raw)-1] ^= 0x01
	if _, err := k.DecryptSecret(base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("a tampered value must not decrypt")
	}
	if _, err := k.DecryptSecret(""); err != ErrNoSecret {
		t.Errorf("empty value: err = %v, want ErrNoSecret", err)
	}
	if _, err := k.DecryptSecret("AAAA"); err == nil {
		t.Error("a too-short value must fail")
	}
}

// TestHashBackupCodeKnownVector pins the digest format. The expected value was
// computed independently with Python's
// hmac.new(b"test-app-secret-1", b"example/backup-code-v1" + b"ABCDEFGHJK", sha256).
func TestHashBackupCodeKnownVector(t *testing.T) {
	k := New("test-app-secret-1", testLabels)
	const want = "855461399fa669521c33576db92e090aa527732de78de1e13b100c54365ec637"
	if got := k.HashBackupCode("abcde-fghjk"); got != want {
		t.Errorf("HashBackupCode = %s, want %s", got, want)
	}
}

func TestBackupCodes(t *testing.T) {
	k := New("test-app-secret-1", testLabels)
	plain, hashes, err := k.NewBackupCodes()
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != BackupCodeCount || len(hashes) != BackupCodeCount {
		t.Fatalf("want %d codes, got %d/%d", BackupCodeCount, len(plain), len(hashes))
	}
	seen := map[string]bool{}
	for i, p := range plain {
		if len(p) != 11 || p[5] != '-' {
			t.Errorf("format must be XXXXX-XXXXX: %q", p)
		}
		for _, c := range strings.ReplaceAll(p, "-", "") {
			if !strings.ContainsRune(BackupAlphabet, c) || strings.ContainsRune("0O1ILU", c) {
				t.Errorf("forbidden letter %q in %q", c, p)
			}
		}
		if seen[p] {
			t.Errorf("duplicate code %q", p)
		}
		seen[p] = true
		if k.HashBackupCode(p) != hashes[i] {
			t.Errorf("digest mismatch for %q", p)
		}
		loose := "  " + strings.ToLower(strings.ReplaceAll(p, "-", "")) + "\t"
		if k.HashBackupCode(loose) != hashes[i] {
			t.Errorf("normalisation failed for %q", loose)
		}
	}
	if NormalizeBackupCode(" ab-cd e\t") != "ABCDE" {
		t.Error("NormalizeBackupCode")
	}
	if New("other", testLabels).HashBackupCode(plain[0]) == hashes[0] {
		t.Error("digest must depend on the app secret")
	}
}
