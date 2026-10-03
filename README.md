# gokit

Small, dependency-free Go packages I reuse across projects. Every package uses
the standard library only (Go 1.24+).

```
go get github.com/Pitchanon/gokit@latest
```

| Package | What it does |
|---|---|
| [`auth/pwhash`](auth/pwhash) | PBKDF2-HMAC-SHA256 password hashing with a self-describing format, so the cost can be raised later. |
| [`auth/totp`](auth/totp) | TOTP codes (RFC 6238) for authenticator apps, with skew tolerance and `otpauth://` URIs for QR codes. |
| [`auth/secretbox`](auth/secretbox) | AES-256-GCM encryption for stored TOTP secrets and HMAC digests for backup codes, keyed from one application secret. |
| [`auth/loginlimit`](auth/loginlimit) | In-memory lockout after repeated failed logins, counted per key (IP, account, …). |
| [`turnstile`](turnstile) | Server-side Cloudflare Turnstile verification that fails closed, plus a client-IP helper. |
| [`thai`](thai) | Amounts in Thai words (`BahtText`) and Buddhist-era dates. |

## Example

```go
hash, _ := pwhash.Hash(password)
ok := pwhash.Verify(hash, attempt)

lim := loginlimit.New(loginlimit.Config{MaxFails: 5})
keys := []string{"ip:" + turnstile.ClientIP(r, turnstile.ClientIPOptions{}), "user:" + user}
if locked, wait := lim.Locked(keys...); locked {
	// refuse, tell the user to retry after wait
}
```

## Security notes

- Nothing here depends on the code being secret. The protection comes from the
  secrets you configure (application secret, Turnstile secret) and from your
  password policy. Keep those out of source control.
- `auth/secretbox`: changing the application secret or the labels makes every
  stored TOTP secret and backup code unusable. Choose them once.
- `auth/totp`: `Verify` does not prevent replay on its own. Store the returned
  counter and reject a counter that is not greater than the last one used.
- `auth/loginlimit` keeps its counters in memory. Run one instance, or move the
  state to shared storage.
- `turnstile.ClientIP` trusts `CF-Connecting-IP` only with
  `TrustCloudflare: true`. Enable it only when the origin is reachable through
  Cloudflare alone; otherwise anyone can forge the header.

Found a security issue? Please open a private security advisory on GitHub
instead of a public issue.

## ภาษาไทย

`thai.BahtText(143.50)` ให้ผลเป็น `"หนึ่งร้อยสี่สิบสามบาทห้าสิบสตางค์"` และ
`thai.DateThai(t)` ให้ผลเป็น `"22 ก.ค. 2569"` (ปี พ.ศ.) รายละเอียดกฎการอ่านตัวเลขอยู่ใน
godoc ของ `BahtText`

## License

MIT, see [LICENSE](LICENSE).
