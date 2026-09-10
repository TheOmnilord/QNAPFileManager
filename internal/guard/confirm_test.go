package guard

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
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
	tok, exp := g.Issue("delete", Summary{Files: 8003, Bytes: 41231234}, paths)
	if tok == "" {
		t.Fatal("Issue returned an empty token")
	}
	if d := time.Until(exp); d <= 0 || d > confirmTTL+time.Second {
		t.Fatalf("expiry %v is not ~%v out", exp, confirmTTL)
	}
	// Path order at redemption must not matter (both sides sort).
	if err := g.Redeem(tok, "delete", []string{"/share/b", "/share/a"}); err != nil {
		t.Fatalf("Redeem of a fresh token failed: %v", err)
	}
}

func TestConfirmReplayRejected(t *testing.T) {
	g := New("", false)
	paths := []string{"/x"}
	tok, _ := g.Issue("empty-trash", Summary{}, paths)
	if err := g.Redeem(tok, "empty-trash", paths); err != nil {
		t.Fatalf("first Redeem failed: %v", err)
	}
	if err := g.Redeem(tok, "empty-trash", paths); !errors.Is(err, ErrConfirmInvalid) {
		t.Fatalf("replay = %v, want ErrConfirmInvalid", err)
	}
}

func TestConfirmWrongOpOrPaths(t *testing.T) {
	g := New("", false)
	paths := []string{"/etc/config/smb.conf"}
	tok, _ := g.Issue("write", Summary{}, paths)

	if err := g.Redeem(tok, "delete", paths); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("wrong op = %v, want ErrConfirmInvalid", err)
	}
	// The token was not spent by the failed attempt, so a different-paths attempt
	// still fails on the MAC, not on replay.
	if err := g.Redeem(tok, "write", []string{"/etc/config/other"}); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("wrong paths = %v, want ErrConfirmInvalid", err)
	}
	// Extra path in the set also fails.
	if err := g.Redeem(tok, "write", []string{"/etc/config/smb.conf", "/etc/config/extra"}); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("extra path = %v, want ErrConfirmInvalid", err)
	}
	// The correct redemption still works — none of the above spent it.
	if err := g.Redeem(tok, "write", paths); err != nil {
		t.Errorf("correct redemption after failed attempts failed: %v", err)
	}
}

func TestConfirmTamperedAndMalformed(t *testing.T) {
	g := New("", false)
	tok, _ := g.Issue("delete", Summary{}, []string{"/x"})

	// Flip the last character to corrupt the MAC.
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	raw[len(raw)-1] ^= 0xFF
	bad := base64.RawURLEncoding.EncodeToString(raw)
	if err := g.Redeem(bad, "delete", []string{"/x"}); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("tampered token = %v, want ErrConfirmInvalid", err)
	}

	for _, junk := range []string{"", "not-base64-!!!", "AAAA", base64.RawURLEncoding.EncodeToString([]byte("short"))} {
		if err := g.Redeem(junk, "delete", []string{"/x"}); !errors.Is(err, ErrConfirmInvalid) {
			t.Errorf("malformed token %q = %v, want ErrConfirmInvalid", junk, err)
		}
	}
}

func TestConfirmExpired(t *testing.T) {
	g := New("", false)
	paths := []string{"/x"}
	past := time.Now().Add(-time.Second).Unix()
	tok := makeSignedToken(g, "delete", paths, past)
	if err := g.Redeem(tok, "delete", paths); !errors.Is(err, ErrConfirmInvalid) {
		t.Errorf("expired token = %v, want ErrConfirmInvalid", err)
	}
	// A token signed by a *different* guard's key must also be rejected.
	other := New("", false)
	tok2, _ := other.Issue("delete", Summary{}, paths)
	if err := g.Redeem(tok2, "delete", paths); !errors.Is(err, ErrConfirmInvalid) {
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
