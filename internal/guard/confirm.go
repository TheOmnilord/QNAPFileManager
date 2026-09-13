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
	// maxIssuedCosts bounds the issued-cost ledger (see Issue). Minting a token
	// is cheap, so the ledger must not be a way to grow the daemon's memory:
	// beyond this many live records nothing more is remembered and the caller
	// simply measures again, which is what it did before the ledger existed.
	maxIssuedCosts = 4096
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

// issuedCost is the MEASURED half of a Summary, remembered against a live token.
//
// The warning sentences are deliberately not kept. They are the caller's own
// wording, cheap to rebuild, and one operation can carry a sentence per selected
// root — so keeping them would make the ledger's memory a function of what a
// client asked for rather than of how many tokens are live.
type issuedCost struct {
	files, bytes int64
	exp          int64
}

// Issue mints a single-use confirmation token for op over parts, valid for
// confirmTTL. The summary is not bound into the token — the caller returns it
// to the client alongside the token — but the op and the canonical parts are,
// so a token cannot be replayed against a different operation.
//
// The summary's measured totals ARE remembered here, against the token, until
// it is redeemed or expires. That exists so a caller whose summary cost real
// work — an M3 recursive permissions change pre-scans the tree to state how many
// items it will touch — does not have to walk the tree a second time when the
// token comes back. Peek returns them; nothing else can, and a client cannot
// influence them, because the token they hang off is unforgeable.
//
// ordered governs how parts are bound. An unordered operation (a batch delete
// over an arbitrary set of targets) passes ordered=false: the parts are sorted
// so redemption order does not matter. An ordered operation (a rename, whose
// direction and overwrite flag matter) passes ordered=true with the caller's
// structured descriptor — for example {"from=/a","to=/b","overwrite=false"} —
// so a token for A→B does not authorise B→A or overwrite:true (adv 5).
//
// The returned expiry is the absolute deadline.
func (g *Guard) Issue(op string, summary Summary, parts []string, ordered bool) (string, time.Time) {
	exp := time.Now().Add(confirmTTL)
	nonce := make([]byte, confirmNonce)
	if _, err := rand.Read(nonce); err != nil {
		panic("guard: cannot read a random nonce: " + err.Error())
	}
	tag := g.confirmTag(op, canonParts(parts, ordered), exp.Unix(), nonce)

	tok := make([]byte, 0, confirmTokLen)
	tok = append(tok, nonce...)
	var eb [confirmExpLen]byte
	binary.BigEndian.PutUint64(eb[:], uint64(exp.Unix()))
	tok = append(tok, eb[:]...)
	tok = append(tok, tag...)
	g.recordCost(string(tok), summary, exp.Unix())
	return base64.RawURLEncoding.EncodeToString(tok), exp
}

// recordCost remembers a token's measured totals, sweeping expired records
// first. Beyond maxIssuedCosts live records it records nothing: the ledger is an
// optimisation, and a caller that finds no record measures again.
func (g *Guard) recordCost(key string, summary Summary, exp int64) {
	if summary.Files == 0 && summary.Bytes == 0 {
		return // nothing measured; nothing worth remembering
	}
	g.seenMu.Lock()
	defer g.seenMu.Unlock()
	g.sweepLocked(time.Now().Unix())
	if g.issued == nil {
		g.issued = make(map[string]issuedCost)
	}
	if len(g.issued) >= maxIssuedCosts {
		return
	}
	g.issued[key] = issuedCost{files: summary.Files, bytes: summary.Bytes, exp: exp}
}

// Peek verifies a token WITHOUT spending it and returns the measured totals that
// were recorded when it was issued. It reports false for a token that is
// malformed, forged, expired, already spent, or issued for a different op or
// parts — and also for an authentic token whose record the ledger did not keep,
// so a caller must treat false as "measure it yourself" and never as "refused".
//
// Spending stays Redeem's job, and Redeem is still what authorises the
// operation. Peek exists so the expensive half of building a challenge can be
// skipped on the re-post: it is the same HMAC check Redeem performs, so it tells
// a caller nothing Redeem would not tell it a moment later.
func (g *Guard) Peek(token, op string, parts []string, ordered bool) (Summary, bool) {
	raw, ok := g.verifyToken(token, op, parts, ordered)
	if !ok {
		return Summary{}, false
	}
	g.seenMu.Lock()
	defer g.seenMu.Unlock()
	if _, spent := g.seen[string(raw)]; spent {
		return Summary{}, false
	}
	rec, found := g.issued[string(raw)]
	if !found {
		return Summary{}, false
	}
	return Summary{Files: rec.files, Bytes: rec.bytes}, true
}

// verifyToken performs the stateless half of redemption: decoding, the canonical
// spelling check, the expiry and the HMAC. It returns the decoded bytes, which
// are the key the spent set and the cost ledger use.
func (g *Guard) verifyToken(token, op string, parts []string, ordered bool) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != confirmTokLen {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, false
	}
	nonce := raw[:confirmNonce]
	exp := int64(binary.BigEndian.Uint64(raw[confirmNonce : confirmNonce+confirmExpLen]))
	tag := raw[confirmNonce+confirmExpLen:]
	if time.Now().Unix() > exp {
		return nil, false
	}
	if !hmac.Equal(tag, g.confirmTag(op, canonParts(parts, ordered), exp, nonce)) {
		return nil, false
	}
	return raw, true
}

// Redeem verifies and spends a confirmation token. It returns nil exactly once
// per token, and ErrConfirmInvalid for a malformed, forged, expired, replayed,
// or wrong-op/wrong-parts token — the caller cannot tell which, deliberately.
// ordered must match the value passed to Issue.
// The non-canonical spelling of a token is refused inside verifyToken: Go's
// base64 decoder silently ignores CR/LF, so token+"\n" (and other alternate
// encodings) decode to the same bytes, and keying the spent set on the string
// alone would let each variant redeem once (adv 4). The spent set is keyed on
// the DECODED bytes as a second line of defence.
func (g *Guard) Redeem(token, op string, parts []string, ordered bool) error {
	raw, ok := g.verifyToken(token, op, parts, ordered)
	if !ok {
		return ErrConfirmInvalid
	}
	exp := int64(binary.BigEndian.Uint64(raw[confirmNonce : confirmNonce+confirmExpLen]))

	// Authentic and unexpired: now enforce single use.
	key := string(raw)
	g.seenMu.Lock()
	defer g.seenMu.Unlock()
	g.sweepLocked(time.Now().Unix())
	if _, spent := g.seen[key]; spent {
		return ErrConfirmInvalid
	}
	g.seen[key] = exp
	// The cost record has done its work; a spent token will never be peeked at
	// again, so it must not hold memory until its expiry.
	delete(g.issued, key)
	return nil
}

// canonParts returns the parts in the exact order they should be bound into a
// token: as given for an ordered operation, sorted for an unordered one.
func canonParts(parts []string, ordered bool) []string {
	if ordered {
		return parts
	}
	return sortedCopy(parts)
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

// confirmTag computes the HMAC over the length-prefixed canonical encoding. The
// parts are already in canonical order (canonParts): sorted for an unordered
// operation, caller-ordered for an ordered one.
func (g *Guard) confirmTag(op string, parts []string, expiry int64, nonce []byte) []byte {
	m := hmac.New(sha256.New, g.serverKey)
	var n [8]byte
	writeField := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		m.Write(n[:])
		m.Write(b)
	}
	writeField([]byte(op))
	binary.BigEndian.PutUint64(n[:], uint64(len(parts)))
	m.Write(n[:])
	for _, p := range parts {
		writeField([]byte(p))
	}
	binary.BigEndian.PutUint64(n[:], uint64(expiry))
	m.Write(n[:])
	writeField(nonce)
	return m.Sum(nil)
}

// sweepLocked drops spent-token entries and issued-cost records whose expiry has
// passed. Called under seenMu on every Redeem and every Issue, so neither map
// outgrows the tokens live in the last confirmTTL window.
func (g *Guard) sweepLocked(nowUnix int64) {
	for tok, exp := range g.seen {
		if nowUnix > exp {
			delete(g.seen, tok)
		}
	}
	for tok, rec := range g.issued {
		if nowUnix > rec.exp {
			delete(g.issued, tok)
		}
	}
}

func sortedCopy(paths []string) []string {
	s := append([]string(nil), paths...)
	sort.Strings(s)
	return s
}
