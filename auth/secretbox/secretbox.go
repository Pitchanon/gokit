// Package secretbox protects the two kinds of 2FA material an application
// stores in its database, using keys derived from one application secret that
// lives only in the environment:
//
//   - TOTP secrets must be recoverable to compute codes, so they are encrypted
//     with AES-256-GCM.
//   - Backup codes only need to be compared, so they are stored as
//     HMAC-SHA256 digests. A plain SHA-256 would not do: the codes are short
//     and drawn from a small alphabet, so an offline search is fast.
//
// A database dump alone is therefore not enough to impersonate a user.
//
// Changing the application secret, or either label, makes every stored secret
// undecryptable and every stored backup code unusable. Pick the labels once
// per application and never change them.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// BackupCodeCount is the number of codes in one set.
	BackupCodeCount = 10
	// backupCodeLen is the code length without the dash: 10 characters from a
	// 30-letter alphabet is about 49 bits.
	backupCodeLen = 10
	// BackupAlphabet leaves out 0 O 1 I L U, which are easy to misread when
	// written down by hand.
	BackupAlphabet = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
)

// ErrNoSecret is returned by DecryptSecret for an empty stored value.
var ErrNoSecret = errors.New("secretbox: no secret stored")

// Labels separate the keys derived from the application secret, so the raw
// secret is never used directly as an encryption key. Use values unique to
// your application, e.g. "myapp/totp-secret-v1" and "myapp/backup-code-v1".
type Labels struct {
	Secret string
	Backup string
}

// Keys holds the derived keys.
type Keys struct {
	aead        cipher.AEAD
	backupKey   []byte
	backupLabel string
}

// New derives the keys from appSecret. It returns nil when appSecret is empty
// or a label is missing; callers must then refuse 2FA operations rather than
// skip the second factor silently.
func New(appSecret string, l Labels) *Keys {
	if appSecret == "" || l.Secret == "" || l.Backup == "" {
		return nil
	}
	block, err := aes.NewCipher(derive(appSecret, l.Secret)) // 32 bytes: AES-256
	if err != nil {
		return nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil
	}
	return &Keys{aead: aead, backupKey: []byte(appSecret), backupLabel: l.Backup}
}

// derive returns HMAC-SHA256(appSecret, label): always 32 bytes, whatever the
// length of appSecret.
func derive(appSecret, label string) []byte {
	m := hmac.New(sha256.New, []byte(appSecret))
	m.Write([]byte(label))
	return m.Sum(nil)
}

// EncryptSecret returns base64(nonce || ciphertext). The nonce is random, so
// encrypting the same secret twice gives different results.
func (k *Keys) EncryptSecret(secret []byte) (string, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := k.aead.Seal(nil, nonce, secret, nil)
	return base64.StdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// DecryptSecret reverses EncryptSecret. GCM authenticates the value, so a
// tampered value or a wrong key fails instead of returning garbage.
func (k *Keys) DecryptSecret(stored string) ([]byte, error) {
	if strings.TrimSpace(stored) == "" {
		return nil, ErrNoSecret
	}
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return nil, err
	}
	ns := k.aead.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("secretbox: stored secret too short")
	}
	return k.aead.Open(nil, raw[:ns], raw[ns:], nil)
}

// HashBackupCode returns hex(HMAC-SHA256(appSecret, label || normalized code)).
func (k *Keys) HashBackupCode(code string) string {
	m := hmac.New(sha256.New, k.backupKey)
	m.Write([]byte(k.backupLabel))
	m.Write([]byte(NormalizeBackupCode(code)))
	return hex.EncodeToString(m.Sum(nil))
}

// NormalizeBackupCode trims, removes dashes, spaces and tabs, and upper-cases,
// so "abcde fghjk" and "ABCDE-FGHJK" are the same code.
func NormalizeBackupCode(code string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "").Replace(strings.TrimSpace(code)))
}

// NewBackupCodes returns one set of codes in the form XXXXX-XXXXX, to be shown
// to the user once, and their digests, to be stored. Codes are unique within
// the set.
func (k *Keys) NewBackupCodes() (plain, hashes []string, err error) {
	seen := map[string]bool{}
	for len(plain) < BackupCodeCount {
		c, err := randomBackupCode()
		if err != nil {
			return nil, nil, err
		}
		h := k.HashBackupCode(c)
		if seen[h] {
			continue
		}
		seen[h] = true
		plain = append(plain, c[:backupCodeLen/2]+"-"+c[backupCodeLen/2:])
		hashes = append(hashes, h)
	}
	return plain, hashes, nil
}

// randomBackupCode draws from crypto/rand with rejection sampling, discarding
// bytes >= 256 - 256%30 so no letter is more likely than another.
func randomBackupCode() (string, error) {
	n := len(BackupAlphabet)
	limit := 256 - (256 % n)
	out := make([]byte, 0, backupCodeLen)
	buf := make([]byte, backupCodeLen)
	for len(out) < backupCodeLen {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= limit {
				continue
			}
			out = append(out, BackupAlphabet[int(b)%n])
			if len(out) == backupCodeLen {
				break
			}
		}
	}
	return string(out), nil
}
