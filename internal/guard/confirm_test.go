package guard

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"testing"
	"time"
)

// makeSignedToken builds a valid token for an arbitrary expiry, so the expiry
// branch can be tested without waiting or shortening the TTL. White-box: this
// test file is in package guard.
func makeSignedToken(g *Guard, op string, paths []string, exp int64) string {
	nonce := []byte("0123456789abcdef") // 16 bytes
	tag := g.confirmTag(op, sortedCopy(paths), exp, nonce)
	tok := append([]byte(nil), nonce...)
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(exp))
	tok = append(tok, eb[:]...)
	tok = append(tok, tag...)
	return base64.RawURLEncoding.EncodeToString(tok)
}

func TestConfirmRoundTrip(t *testing.T) {
	g := New("", false)
	paths := []string{"/share/a", "/share/b"}
	tok, exp := g.Issue("delete", Summary{Files: 8003, Bytes: 41231234}, paths, false)
	if tok == "" {
		t.Fatal("Issue returned an empty token")
	}
	if d := time.Until(exp); d <= 0 || d > confirmTTL+time.Second {
		t.Fatalf("expiry %v is not ~%v out", exp, confirmTTL)
	}
	// Path order at redemption must not matter for an unordered operation.
	if err := g.Redeem(tok, "delete", []string{"/share/b", "/share/a"}, false); err != nil {
		t.Fatalf("Redeem of a fresh token failed: %v", err)
	}
}

func TestConfirmReplayRejected(t *testing.T) {
	g := New("", false)
	paths := []string{"/x"}
	tok, _ := g.Issue("empty-trash", Summary{}, paths, false)
	if err := g.Redeem(tok, "empty-trash", paths, false); err != nil {
		t.Fatalf("first Redeem failed: %v", err)
	}
	if err := g.Redeem(tok, "empty-trash", paths, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Fatalf("replay = %v, want ErrConfirmInvalid", err)
	}
}

// TestConfirmReplayAlternateEncodingRejected proves the adv 4 fix: Go's base64
// decoder ignores CR/LF, so token+"\n" decodes to the same bytes. Neither the
// non-canonical string (rejected outright) nor a second spend of the same
// decoded bytes may pass.
func TestConfirmReplayAlternateEncodingRejected(t *testing.T) {
	g := New("", false)
	paths := []string{"/etc/config/smb.conf"}
	tok, _ := g.Issue("delete", Summary{}, paths, false)

	// A newline-padded spelling of a *fresh* token must be refused as
	// non-canonical, never redeemed once.
	if err := g.Redeem(tok+"\n", "delete", paths, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Fatalf("non-canonical fresh token = %v, want ErrConfirmInvalid", err)
	}
	// Spend the canonical token once.
	if err := g.Redeem(tok, "delete", paths, false); err != nil {
		t.Fatalf("canonical Redeem failed: %v", err)
	}
	// Every alternate spelling of the spent token must also be refused.
	for _, variant := range []string{tok + "\n", tok + "\r\n", "\n" + tok, tok + "="} {
		if err := g.Redeem(variant, "delete", paths, false); !errors.Is(err, ErrConfirmInvalid) {
			t.Errorf("alternate spelling %q = %v, want ErrConfirmInvalid", variant, err)
		}
	}
}

// TestConfirmOrderedRenameBinding proves the adv 5 fix: a token issued for an
// ordered rename A→B (overwrite:false) does not authorise B→A or overwrite:true.
func TestConfirmOrderedRenameBinding(t *testing.T) {
	g := New("", false)
	forward := []string{"from=/etc/config/a", "to=/etc/config/b", "overwrite=false"}
	tok, _ := g.Issue("rename", Summary{Files: 1}, forward, true)

	// The reverse direction must not verify.
	reverse := []string{"from=/etc/config/b", "to=/etc/config/a", "overwrite=false"}
	if err := g.Redeem(tok, "rename", reverse, true); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("reverse rename = %v, want ErrConfirmInvalid", err)
	}
	// Flipping overwrite must not verify.
	over := []string{"from=/etc/config/a", "to=/etc/config/b", "overwrite=true"}
	if err := g.Redeem(tok, "rename", over, true); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("overwrite flip = %v, want ErrConfirmInvalid", err)
	}
	// The exact forward descriptor still redeems once.
	if err := g.Redeem(tok, "rename", forward, true); err != nil {
		t.Errorf("forward rename redemption failed: %v", err)
	}
}

func TestConfirmWrongOpOrPaths(t *testing.T) {
	g := New("", false)
	paths := []string{"/etc/config/smb.conf"}
	tok, _ := g.Issue("write", Summary{}, paths, false)

	if err := g.Redeem(tok, "delete", paths, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("wrong op = %v, want ErrConfirmInvalid", err)
	}
	// The token was not spent by the failed attempt, so a different-paths attempt
	// still fails on the MAC, not on replay.
	if err := g.Redeem(tok, "write", []string{"/etc/config/other"}, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("wrong paths = %v, want ErrConfirmInvalid", err)
	}
	// Extra path in the set also fails.
	if err := g.Redeem(tok, "write", []string{"/etc/config/smb.conf", "/etc/config/extra"}, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("extra path = %v, want ErrConfirmInvalid", err)
	}
	// The correct redemption still works — none of the above spent it.
	if err := g.Redeem(tok, "write", paths, false); err != nil {
		t.Errorf("correct redemption after failed attempts failed: %v", err)
	}
}

func TestConfirmTamperedAndMalformed(t *testing.T) {
	g := New("", false)
	tok, _ := g.Issue("delete", Summary{}, []string{"/x"}, false)

	// Flip the last character to corrupt the MAC.
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	raw[len(raw)-1] ^= 0xFF
	bad := base64.RawURLEncoding.EncodeToString(raw)
	if err := g.Redeem(bad, "delete", []string{"/x"}, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("tampered token = %v, want ErrConfirmInvalid", err)
	}

	for _, junk := range []string{"", "not-base64-!!!", "AAAA", base64.RawURLEncoding.EncodeToString([]byte("short"))} {
		if err := g.Redeem(junk, "delete", []string{"/x"}, false); !errors.Is(err, ErrConfirmInvalid) {
			t.Errorf("malformed token %q = %v, want ErrConfirmInvalid", junk, err)
		}
	}
}

func TestConfirmExpired(t *testing.T) {
	g := New("", false)
	paths := []string{"/x"}
	past := time.Now().Add(-time.Second).Unix()
	tok := makeSignedToken(g, "delete", paths, past)
	if err := g.Redeem(tok, "delete", paths, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("expired token = %v, want ErrConfirmInvalid", err)
	}
	// A token signed by a *different* guard's key must also be rejected.
	other := New("", false)
	tok2, _ := other.Issue("delete", Summary{}, paths, false)
	if err := g.Redeem(tok2, "delete", paths, false); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("foreign-key token = %v, want ErrConfirmInvalid", err)
	}
}

func TestNeedsConfirm(t *testing.T) {
	table := []struct {
		op    Op
		count int
		bytes int64
		want  bool
	}{
		{OpDelete, 100, 0, false},
		{OpDelete, 101, 0, true},
		{OpWrite, 0, 1 << 30, false},
		{OpWrite, 0, (1 << 30) + 1, true},
		{OpRead, 10000, 1 << 40, false}, // reads never need confirmation
		{OpTraverse, 10000, 1 << 40, false},
		{OpChown, 200, 0, true},
	}
	for _, c := range table {
		if got := NeedsConfirm(c.op, "/some/path", c.count, c.bytes); got != c.want {
			t.Errorf("NeedsConfirm(%v, count=%d, bytes=%d) = %v, want %v", c.op, c.count, c.bytes, got, c.want)
		}
	}
}

// TestPeekReturnsTheMeasuredCostWithoutSpending covers the ledger M3 needs: a
// recursive permissions change pre-scans the tree to say how many items it will
// touch, and the re-post that redeems the token must not walk it again. The
// count is remembered against the token — unforgeable, so a client cannot
// influence it — and Peek reads it back without spending anything.
func TestPeekReturnsTheMeasuredCostWithoutSpending(t *testing.T) {
	g := New("", false)
	parts := []string{"op=chmod", "/data/tree"}
	token, _ := g.Issue("chmod", Summary{Files: 8003, Bytes: 12, Warnings: []string{"a sentence"}}, parts, true)

	cost, ok := g.Peek(token, "chmod", parts, true)
	if !ok || cost.Files != 8003 || cost.Bytes != 12 {
		t.Fatalf("Peek = %+v, %v; want the measured totals", cost, ok)
	}
	// The warning sentences are deliberately not kept: they are the caller's own
	// wording and one operation can carry a sentence per selected root.
	if cost.Warnings != nil {
		t.Fatalf("Peek must not retain warnings: %v", cost.Warnings)
	}
	// Peeking does not spend: the token still redeems, exactly once.
	if _, ok := g.Peek(token, "chmod", parts, true); !ok {
		t.Fatal("Peek spent the token")
	}
	if err := g.Redeem(token, "chmod", parts, true); err != nil {
		t.Fatalf("Redeem after Peek: %v", err)
	}
	if err := g.Redeem(token, "chmod", parts, true); err == nil {
		t.Fatal("a spent token redeemed twice")
	}
	// A spent token's record is dropped rather than held until its expiry, and
	// Peek reports it as unusable.
	if _, ok := g.Peek(token, "chmod", parts, true); ok {
		t.Fatal("a spent token must not peek")
	}
	g.seenMu.Lock()
	held := len(g.issued)
	g.seenMu.Unlock()
	if held != 0 {
		t.Fatalf("the ledger still holds %d record(s) for a spent token", held)
	}
}

// TestPeekFailsClosed: every way a token can be wrong reports false, so a caller
// that cannot read a count measures one rather than proceeding on a guess.
func TestPeekFailsClosed(t *testing.T) {
	g := New("", false)
	parts := []string{"op=chmod", "/data/tree"}
	token, _ := g.Issue("chmod", Summary{Files: 8003}, parts, true)
	for name, peek := range map[string]func() (Summary, bool){
		"no token":    func() (Summary, bool) { return g.Peek("", "chmod", parts, true) },
		"malformed":   func() (Summary, bool) { return g.Peek("not-a-token", "chmod", parts, true) },
		"wrong op":    func() (Summary, bool) { return g.Peek(token, "chown", parts, true) },
		"wrong parts": func() (Summary, bool) { return g.Peek(token, "chmod", []string{"op=chmod", "/data/other"}, true) },
		"wrong order": func() (Summary, bool) { return g.Peek(token, "chmod", []string{"/data/tree", "op=chmod"}, true) },
	} {
		if _, ok := peek(); ok {
			t.Errorf("%s: Peek reported a usable record", name)
		}
	}
	// An authentic token whose summary measured nothing is not recorded at all,
	// which the caller must read as "measure it yourself", never as a zero.
	empty, _ := g.Issue("chmod", Summary{}, parts, true)
	if _, ok := g.Peek(empty, "chmod", parts, true); ok {
		t.Fatal("an unmeasured summary must not be recorded")
	}
}

// TestIssuedLedgerIsBounded: minting a token is cheap, so the ledger must not be
// a way to grow the daemon's memory. Beyond its cap it records nothing and the
// caller measures again — which is what it did before the ledger existed.
func TestIssuedLedgerIsBounded(t *testing.T) {
	g := New("", false)
	for i := 0; i < maxIssuedCosts+50; i++ {
		g.Issue("chmod", Summary{Files: int64(i + 1)}, []string{"op=chmod", strconv.Itoa(i)}, true)
	}
	g.seenMu.Lock()
	held := len(g.issued)
	g.seenMu.Unlock()
	if held > maxIssuedCosts {
		t.Fatalf("the ledger holds %d records, cap is %d", held, maxIssuedCosts)
	}
}
