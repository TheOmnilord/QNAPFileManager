package guard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"sort"
	"time"
)

// Confirmation tokens let the front-end demand a second, deliberate POST for a
// dangerous operation while carrying a real scan summary to the dialog. A token
// is unforgeable (HMAC over the op, the sorted paths and the expiry) and
// single-use (a spent-token set). Verification is otherwise stateless: the
// expiry travels inside the token, so a restart — which regenerates serverKey —
// simply invalidates every outstanding token.
//
// Token layout, base64url (no padding) of:
//
//	nonce[16] || expiryUnix[8, big-endian] || HMAC-SHA256(serverKey, canon)[32]
//
// where canon is a length-prefixed encoding of (op, sorted paths, expiryUnix,
// nonce). Length prefixing means a filename containing any byte — including a
// newline or a slash — cannot be confused for a field boundary.
const (
	confirmTTL     = 60 * time.Second
	confirmNonce   = 16
	confirmTagLen  = 32
	confirmExpLen  = 8
	confirmTokLen  = confirmNonce + confirmExpLen + confirmTagLen
	confirmFileMax = 100     // more than this many files → confirm
	confirmByteMax = 1 << 30 // more than 1 GiB → confirm
)

// Summary is the real, scanned cost of an operation, shown verbatim in the
// confirmation dialog so it states facts rather than a guess.
type Summary struct {
	Files    int64    `json:"files"`
	Bytes    int64    `json:"bytes"`
	Warnings []string `json:"warnings,omitempty"`
}

func newServerKey() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		// crypto/rand failing is unrecoverable; a root daemon must not run on a
		// predictable key.
		panic("guard: cannot read a random server key: " + err.Error())
	}
	return k
}

// Issue mints a single-use confirmation token for op over paths, valid for
// confirmTTL. The summary is not bound into the token — the caller returns it
// to the client alongside the token — but the op and the exact set of paths
// are, so a token cannot be replayed against a different operation. The
// returned expiry is the absolute deadline.
func (g *Guard) Issue(op string, summary Summary, paths []string) (string, time.Time) {
	_ = summary
	exp := time.Now().Add(confirmTTL)
	nonce := make([]byte, confirmNonce)
	if _, err := rand.Read(nonce); err != nil {
		panic("guard: cannot read a random nonce: " + err.Error())
	}
	tag := g.confirmTag(op, sortedCopy(paths), exp.Unix(), nonce)

	tok := make([]byte, 0, confirmTokLen)
	tok = append(tok, nonce...)
	var eb [confirmExpLen]byte
	binary.BigEndian.PutUint64(eb[:], uint64(exp.Unix()))
	tok = append(tok, eb[:]...)
	tok = append(tok, tag...)
	return base64.RawURLEncoding.EncodeToString(tok), exp
}

// Redeem verifies and spends a confirmation token. It returns nil exactly once
// per token, and ErrConfirmInvalid for a malformed, forged, expired, replayed,
// or wrong-op/wrong-paths token — the caller cannot tell which, deliberately.
func (g *Guard) Redeem(token, op string, paths []string) error {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != confirmTokLen {
		return ErrConfirmInvalid
	}
	nonce := raw[:confirmNonce]
	exp := int64(binary.BigEndian.Uint64(raw[confirmNonce : confirmNonce+confirmExpLen]))
	tag := raw[confirmNonce+confirmExpLen:]

	now := time.Now()
	if now.Unix() > exp {
		return ErrConfirmInvalid
	}
	want := g.confirmTag(op, sortedCopy(paths), exp, nonce)
	if !hmac.Equal(tag, want) {
		return ErrConfirmInvalid
	}

	// Authentic and unexpired: now enforce single use.
	g.seenMu.Lock()
	defer g.seenMu.Unlock()
	g.sweepLocked(now.Unix())
	if _, spent := g.seen[token]; spent {
		return ErrConfirmInvalid
	}
	g.seen[token] = exp
	return nil
}

// NeedsConfirm reports whether an operation is large enough to warrant a
// confirmation token on scale alone: more than 100 files or more than 1 GiB.
// Warn-class paths and mount-point deletes are handled by Check; this covers
// the "you are about to delete a great many files" case that no path rule sees.
// Non-mutating ops never need confirmation.
func NeedsConfirm(op Op, path string, count int, bytes int64) bool {
	_ = path
	if op&writeOps == 0 {
		return false
	}
	return count > confirmFileMax || bytes > confirmByteMax
}

// confirmTag computes the HMAC over the length-prefixed canonical encoding.
func (g *Guard) confirmTag(op string, sortedPaths []string, expiry int64, nonce []byte) []byte {
	m := hmac.New(sha256.New, g.serverKey)
	var n [8]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		m.Write(n[:])
		m.Write(b)
	}
	writeField([]byte(op))
	binary.BigEndian.PutUint64(n[:], uint64(len(sortedPaths)))
	m.Write(n[:])
	for _, p := range sortedPaths {
		writeField([]byte(p))
	}
	binary.BigEndian.PutUint64(n[:], uint64(expiry))
	m.Write(n[:])
	writeField(nonce)
	return m.Sum(nil)
}

// sweepLocked drops spent-token entries whose expiry has passed. Called under
// seenMu on every Redeem, so the set never outgrows the tokens live in the last
// confirmTTL window.
func (g *Guard) sweepLocked(nowUnix int64) {
	for tok, exp := range g.seen {
		if nowUnix > exp {
			delete(g.seen, tok)
		}
	}
}

func sortedCopy(paths []string) []string {
	s := append([]string(nil), paths...)
	sort.Strings(s)
	return s
}
