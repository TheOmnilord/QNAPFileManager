package breakglass

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckPasswordRules(t *testing.T) {
	long := strings.Repeat("a", BcryptLimit+8)
	cases := []struct {
		name       string
		password   string
		wantErr    bool
		wantNotice bool
	}{
		{"empty", "", true, false},
		{"eleven bytes", strings.Repeat("x", MinPasswordBytes-1), true, false},
		{"exactly twelve", strings.Repeat("x", MinPasswordBytes), false, false},
		// No composition rules, per NIST: a long passphrase of ordinary words is
		// exactly what this should accept.
		{"passphrase", "correct horse battery staple", false, false},
		{"only whitespace", strings.Repeat(" ", MinPasswordBytes+4), true, false},
		{"whitespace and tabs", "\t\t\n   \t\t \n\r  ", true, false},
		{"leading and trailing space is fine", "   secret pass   ", false, false},
		// Past what bcrypt can read: refused by name (x/crypto no longer
		// truncates, it errors), never accepted with an ignored tail.
		{"past the bcrypt limit", long, true, false},
		{"near the bcrypt limit", strings.Repeat("z", BcryptLimit-2), false, true},
		{"over the maximum", strings.Repeat("y", MaxPasswordBytes+1), true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			notice, err := CheckPassword(c.password)
			if (err != nil) != c.wantErr {
				t.Fatalf("CheckPassword = %v, wantErr %v", err, c.wantErr)
			}
			if (notice != "") != c.wantNotice {
				t.Fatalf("notice = %q, want a notice: %v", notice, c.wantNotice)
			}
			if c.wantNotice && !strings.Contains(notice, "72") {
				t.Fatalf("the notice must name the bcrypt limit: %q", notice)
			}
		})
	}
}

func TestCheckCostBounds(t *testing.T) {
	for _, c := range []struct {
		in      int
		want    int
		wantErr bool
	}{
		{0, DefaultCost, false},
		{MinCost, MinCost, false},
		{MaxCost, MaxCost, false},
		{MinCost - 1, 0, true},
		{MaxCost + 1, 0, true},
		{-1, 0, true},
	} {
		got, err := CheckCost(c.in)
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("CheckCost(%d) = %d, %v; want %d, err %v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestHashAndVerify(t *testing.T) {
	const password = "an emergency password"
	h, err := Hash(password, MinCost) // MinCost: the test must not spend seconds
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, password) {
		t.Fatal("the hash must not contain the password")
	}
	if err := Verify(h, password); err != nil {
		t.Fatalf("Verify(correct) = %v", err)
	}
	if err := Verify(h, password+"x"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("Verify(wrong) = %v, want ErrBadPassword", err)
	}
	// "No password configured" is a DISTINCT internal error so the audit line can
	// name the cause, and the HTTP door deliberately renders it identically to a
	// wrong password (contract §5.2).
	if err := Verify("", password); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("Verify(no hash) = %v, want ErrNoPassword", err)
	}
	if err := Verify("   ", password); !errors.Is(err, ErrNoPassword) {
		t.Fatalf("Verify(blank hash) = %v, want ErrNoPassword", err)
	}
	// A corrupt hash must not be a way in.
	if err := Verify("not-a-bcrypt-hash", password); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("Verify(corrupt) = %v, want ErrBadPassword", err)
	}
	if c, err := HashCost(h); err != nil || c != MinCost {
		t.Fatalf("HashCost = %d, %v; want %d", c, err, MinCost)
	}
}

func TestHashRefusesAShortPassword(t *testing.T) {
	if _, err := Hash("short", MinCost); err == nil {
		t.Fatal("Hash must apply the same rules as CheckPassword")
	}
	if _, err := Hash(strings.Repeat("x", MinPasswordBytes), MaxCost+1); err == nil {
		t.Fatal("Hash must apply the cost bounds")
	}
}
