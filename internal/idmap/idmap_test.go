package idmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// The fixtures deliberately contain everything the parser must survive:
// comments, NIS +/- compat lines, a row with no colons, a non-numeric uid, a
// duplicate uid, a duplicate user name and a duplicate gid.
const passwdFixture = `# /etc/passwd
root:x:0:0:root:/root:/bin/sh
admin:x:0:0:administrator:/share/homes/admin:/bin/sh
alice:x:1001:100:Alice:/share/homes/alice:/bin/sh
bob:x:1002:100:Bob:/share/homes/bob:/bin/sh
+@sysadmins
+::::::
-baduser
brokenrow
carol:x:notanumber:100:Carol:/share/homes/carol:/bin/sh
dave:x:1003:101:Dave:/share/homes/dave:/bin/sh
eve:x:1001:100:Eve duplicate uid:/share/homes/eve:/bin/sh
alice:x:4444:100:Alice duplicate name:/tmp:/bin/sh
`

// alice's primary gid (100) is NOT repeated in the member list of gid 100 --
// the classic bug this package must not have. She is a member of three further
// groups: developers, media and share.
const groupFixture = `# /etc/group
administrators:x:0:admin
everyone:x:100:bob
users:x:100:duplicate-gid-ignored
developers:x:1050:alice,dave
media:x:1051:alice
share:x:1053:alice, bob
+
-
malformedrow
staff:x:notnum:alice
guests:x:1052:
`

// writeFixtures writes the passwd/group fixtures into a fresh temp dir.
func writeFixtures(t *testing.T, passwd, group string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "passwd")
	g := filepath.Join(dir, "group")
	if err := os.WriteFile(p, []byte(passwd), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(g, []byte(group), 0o644); err != nil {
		t.Fatal(err)
	}
	return p, g
}

// newTestMap opens a Map over the standard fixtures with staleness checking
// unthrottled, so tests do not have to sleep for a second.
func newTestMap(t *testing.T) *Map {
	t.Helper()
	p, g := writeFixtures(t, passwdFixture, groupFixture)
	m := Open(p, g)
	m.checkInterval = 0
	return m
}

func eqInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOpenDefaults(t *testing.T) {
	m := Open("", "")
	if m.PasswdPath() != DefaultPasswdPath || m.GroupPath() != DefaultGroupPath {
		t.Fatalf("defaults = %q, %q", m.PasswdPath(), m.GroupPath())
	}
	// Missing files (the normal case on Windows) must not panic.
	if got := m.User(0); got != "" && got != "root" {
		t.Fatalf("User(0) = %q", got)
	}
	if _, err := m.LookupUser("nobody-at-all"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LookupUser on missing files: %v", err)
	}
}

func TestParseTolerance(t *testing.T) {
	m := newTestMap(t)

	// Duplicate uid 1001: the first row (alice) wins over eve.
	if got := m.User(1001); got != "alice" {
		t.Errorf("User(1001) = %q, want alice", got)
	}
	// Duplicate gid 100: the first row (everyone) wins over users.
	if got := m.Group(100); got != "everyone" {
		t.Errorf("Group(100) = %q, want everyone", got)
	}
	if got := m.Group(0); got != AdminGroup {
		t.Errorf("Group(0) = %q, want %s", got, AdminGroup)
	}
	if got := m.User(9999); got != "" {
		t.Errorf("User(9999) = %q, want empty", got)
	}
	if got := m.Group(9999); got != "" {
		t.Errorf("Group(9999) = %q, want empty", got)
	}

	// Malformed and compat rows produced no entries.
	for _, bad := range []string{"brokenrow", "carol", "+@sysadmins", "-baduser", "+"} {
		if _, err := m.LookupUser(bad); err == nil {
			t.Errorf("LookupUser(%q) unexpectedly succeeded", bad)
		}
	}
	if _, ok := m.GroupGID("malformedrow"); ok {
		t.Error("malformed group row was parsed")
	}
	if _, ok := m.GroupGID("staff"); ok {
		t.Error("group with non-numeric gid was parsed")
	}

	// Users(): root, admin, alice, bob, dave, eve. carol and the duplicate
	// alice row are dropped.
	var names []string
	for _, u := range m.Users() {
		names = append(names, u.Name)
	}
	if want := "root,admin,alice,bob,dave,eve"; strings.Join(names, ",") != want {
		t.Errorf("Users() = %v, want %s", names, want)
	}

	// Groups(): duplicates are kept in the list (file order) but only the
	// first claims the gid.
	var gnames []string
	for _, g := range m.Groups() {
		gnames = append(gnames, g.Name)
	}
	if want := "administrators,everyone,users,developers,media,share,guests"; strings.Join(gnames, ",") != want {
		t.Errorf("Groups() = %v, want %s", gnames, want)
	}
	for _, g := range m.Groups() {
		if g.Name == "guests" && len(g.Members) != 0 {
			t.Errorf("guests members = %v, want none", g.Members)
		}
		if g.Name == "share" && len(g.Members) != 2 {
			t.Errorf("share members = %v, want alice and bob", g.Members)
		}
	}
}

func TestLookupUserGroups(t *testing.T) {
	m := newTestMap(t)

	alice, err := m.LookupUser("alice")
	if err != nil {
		t.Fatalf("LookupUser(alice): %v", err)
	}
	if alice.UID != 1001 || alice.GID != 100 {
		t.Errorf("alice ids = %d/%d, want 1001/100", alice.UID, alice.GID)
	}
	if alice.Home != "/share/homes/alice" {
		t.Errorf("alice home = %q", alice.Home)
	}
	if alice.Source != SourcePasswd || alice.Partial {
		t.Errorf("alice source = %q partial = %v", alice.Source, alice.Partial)
	}
	// Primary gid 100 is not in gid 100's member list, so it must have been
	// added from passwd; the three supplementary groups follow, sorted.
	if want := []int{100, 1050, 1051, 1053}; !eqInts(alice.Groups, want) {
		t.Errorf("alice groups = %v, want %v", alice.Groups, want)
	}
	if !alice.HasGroup(1051) || alice.HasGroup(0) {
		t.Error("HasGroup is wrong")
	}

	// bob is listed in gid 100 as well as being a member by primary gid: the
	// result must be deduped, not doubled.
	bob, err := m.LookupUser("bob")
	if err != nil {
		t.Fatalf("LookupUser(bob): %v", err)
	}
	if want := []int{100, 1053}; !eqInts(bob.Groups, want) {
		t.Errorf("bob groups = %v, want %v", bob.Groups, want)
	}

	// GroupsOf agrees with LookupUser, and reports nothing for a stranger.
	if want := []int{100, 1050, 1051, 1053}; !eqInts(m.GroupsOf("alice"), want) {
		t.Errorf("GroupsOf(alice) = %v, want %v", m.GroupsOf("alice"), want)
	}
	if got := m.GroupsOf("nosuchuser"); got != nil {
		t.Errorf("GroupsOf(nosuchuser) = %v, want nil", got)
	}
	if want := []int{101, 1050}; !eqInts(m.GroupsOf("dave"), want) {
		t.Errorf("GroupsOf(dave) = %v, want %v", m.GroupsOf("dave"), want)
	}

	// The caller cannot corrupt the map through the returned slice.
	alice.Groups[0] = -1
	if again, _ := m.LookupUser("alice"); again.Groups[0] != 100 {
		t.Error("returned Groups slice aliases internal state")
	}
}

func TestLookupUserUnknown(t *testing.T) {
	m := newTestMap(t)
	_, err := m.LookupUser("DOMAIN\\stranger")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestReloadOnChange(t *testing.T) {
	p, g := writeFixtures(t, passwdFixture, groupFixture)
	m := Open(p, g)
	m.checkInterval = 0

	if _, err := m.LookupUser("frank"); err == nil {
		t.Fatal("frank exists before the rewrite")
	}

	// Rewrite both files and push their mtimes forward, as a QTS user change
	// would.
	if err := os.WriteFile(p, []byte(passwdFixture+"frank:x:1004:102:Frank:/share/homes/frank:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(g, []byte(groupFixture+"newteam:x:1060:frank,alice\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Minute)
	for _, f := range []string{p, g} {
		if err := os.Chtimes(f, future, future); err != nil {
			t.Fatal(err)
		}
	}

	frank, err := m.LookupUser("frank")
	if err != nil {
		t.Fatalf("frank after reload: %v", err)
	}
	if frank.UID != 1004 || !eqInts(frank.Groups, []int{102, 1060}) {
		t.Errorf("frank = %+v", frank)
	}
	if want := []int{100, 1050, 1051, 1053, 1060}; !eqInts(m.GroupsOf("alice"), want) {
		t.Errorf("alice groups after reload = %v, want %v", m.GroupsOf("alice"), want)
	}
}

func TestReloadThrottled(t *testing.T) {
	p, g := writeFixtures(t, passwdFixture, groupFixture)
	m := Open(p, g) // default one-second throttle
	if _, err := m.LookupUser("alice"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("frank:x:1004:102:Frank:/home/frank:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Minute)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := m.LookupUser("frank"); err == nil {
		t.Fatal("reloaded within the throttle window")
	}
	m.checkInterval = 0
	if _, err := m.LookupUser("frank"); err != nil {
		t.Fatalf("did not reload once the throttle was lifted: %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	m := newTestMap(t) // checkInterval 0: every call re-stats
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if _, err := m.LookupUser("alice"); err != nil {
					t.Error(err)
					return
				}
				m.User(1002)
				m.Group(1050)
				m.Users()
				m.Groups()
				m.GroupsOf("bob")
			}
		}()
	}
	wg.Wait()
}

// stubExec records the helper calls it is given and replies from a table.
type stubExec struct {
	mu    sync.Mutex
	calls []string
	reply map[string]string // "id -u alice" -> output
	fail  map[string]bool
}

func (s *stubExec) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > nssTimeout+time.Second {
		return nil, fmt.Errorf("helper called without the %s deadline", nssTimeout)
	}
	key := strings.Join(append([]string{name}, args...), " ")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, key)
	if s.fail[key] {
		return nil, errors.New("applet not found")
	}
	out, ok := s.reply[key]
	if !ok {
		return nil, errors.New("applet not found")
	}
	return []byte(out), nil
}

func (s *stubExec) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.calls))
	copy(out, s.calls)
	return out
}

func TestLookupNSSRejectsBadNames(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{reply: map[string]string{}}
	m.Exec = s.run

	bad := []string{
		"bob;rm",
		"bob rm -rf /",
		"-u", // would be read as an option
		"bob$(whoami)",
		"bob`id`",
		"bob|cat",
		"bob\nalice",
		"bob/../root",
		"",
		strings.Repeat("a", 65),
		"héllo",
	}
	for _, name := range bad {
		if ValidName(name) {
			t.Errorf("ValidName(%q) = true", name)
		}
		if _, err := m.LookupNSS(context.Background(), name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("LookupNSS(%q) err = %v, want ErrInvalidName", name, err)
		}
		if _, err := m.Resolve(context.Background(), name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Resolve(%q) err = %v, want ErrInvalidName", name, err)
		}
	}
	if got := s.seen(); len(got) != 0 {
		t.Fatalf("a helper ran for a rejected name: %v", got)
	}

	for _, name := range []string{"alice", "WORKGROUP\\alice", "a.b_c-d@example.com", "A1"} {
		if !ValidName(name) {
			t.Errorf("ValidName(%q) = false", name)
		}
	}
}

func TestLookupNSSViaID(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{
		reply: map[string]string{
			"id -u DOMAIN\\jane": "20001\n",
			"id -g DOMAIN\\jane": "20000\n",
			// Unsorted, with the primary gid repeated: the result must be
			// sorted and deduped.
			"id -G DOMAIN\\jane": "20000 10513 20000 30001\n",
		},
	}
	m.Exec = s.run

	id, err := m.LookupNSS(context.Background(), `DOMAIN\jane`)
	if err != nil {
		t.Fatalf("LookupNSS: %v", err)
	}
	if id.Name != `DOMAIN\jane` || id.UID != 20001 || id.GID != 20000 {
		t.Errorf("id = %+v", id)
	}
	if want := []int{10513, 20000, 30001}; !eqInts(id.Groups, want) {
		t.Errorf("groups = %v, want %v", id.Groups, want)
	}
	if id.Source != SourceNSS || id.Partial {
		t.Errorf("source = %q partial = %v", id.Source, id.Partial)
	}
	// getent was tried first and only fell through to id.
	if got := s.seen(); got[0] != `getent passwd DOMAIN\jane` {
		t.Errorf("first call = %q, want getent", got[0])
	}
}

func TestLookupNSSPrefersGetent(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{
		reply: map[string]string{
			"getent passwd jane": "jane:x:20001:20000:Jane:/share/homes/jane:/bin/sh\n",
			"id -G jane":         "20000 10513\n",
		},
	}
	m.Exec = s.run

	id, err := m.LookupNSS(context.Background(), "jane")
	if err != nil {
		t.Fatalf("LookupNSS: %v", err)
	}
	if id.UID != 20001 || id.GID != 20000 || id.Home != "/share/homes/jane" {
		t.Errorf("id = %+v", id)
	}
	if want := []int{10513, 20000}; !eqInts(id.Groups, want) {
		t.Errorf("groups = %v, want %v", id.Groups, want)
	}
	// Exactly two execs: getent for the entry, id -G for the groups.
	if got := s.seen(); len(got) != 2 {
		t.Errorf("calls = %v, want getent + id -G only", got)
	}
}

func TestLookupNSSPartialWhenGroupsUnavailable(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{
		reply: map[string]string{
			"id -u jane": "20001",
			"id -g jane": "20000",
		},
		fail: map[string]bool{"id -G jane": true},
	}
	m.Exec = s.run

	id, err := m.LookupNSS(context.Background(), "jane")
	if err != nil {
		t.Fatalf("LookupNSS: %v", err)
	}
	if !id.Partial {
		t.Error("Partial = false, want true when id -G is unavailable")
	}
	if want := []int{20000}; !eqInts(id.Groups, want) {
		t.Errorf("groups = %v, want %v", id.Groups, want)
	}
}

func TestLookupNSSNonNumericOutput(t *testing.T) {
	m := newTestMap(t)
	cases := []struct {
		name  string
		reply map[string]string
		want  error
	}{
		{"jane", map[string]string{"id -u jane": "id: unknown user\n", "id -g jane": "20000"}, ErrBadOutput},
		{"jane", map[string]string{"id -u jane": "20001", "id -g jane": "no such user"}, ErrBadOutput},
		{"jane", map[string]string{"id -u jane": "20001 20002", "id -g jane": "20000"}, ErrBadOutput},
	}
	for i, tc := range cases {
		m.Exec = (&stubExec{reply: tc.reply}).run
		if _, err := m.LookupNSS(context.Background(), tc.name); !errors.Is(err, tc.want) {
			t.Errorf("case %d: err = %v, want %v", i, err, tc.want)
		}
	}

	// Non-numeric id -G output degrades to Partial rather than failing.
	m.Exec = (&stubExec{reply: map[string]string{
		"id -u jane": "20001", "id -g jane": "20000", "id -G jane": "20000 users\n",
	}}).run
	id, err := m.LookupNSS(context.Background(), "jane")
	if err != nil || !id.Partial || !eqInts(id.Groups, []int{20000}) {
		t.Errorf("id = %+v, err = %v", id, err)
	}
}

func TestLookupNSSNoHelper(t *testing.T) {
	m := newTestMap(t) // no Exec injected: the platform default runs
	_, err := m.LookupNSS(context.Background(), "jane")
	if err == nil {
		t.Fatal("expected an error with no helper available")
	}
	if runtimeIsWindows() && !errors.Is(err, ErrNoHelper) {
		t.Fatalf("windows err = %v, want ErrNoHelper", err)
	}
}

func TestResolvePrefersPasswd(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{reply: map[string]string{"id -u alice": "999"}}
	m.Exec = s.run

	id, err := m.Resolve(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.UID != 1001 || id.Source != SourcePasswd {
		t.Errorf("id = %+v, want the passwd entry", id)
	}
	if got := s.seen(); len(got) != 0 {
		t.Errorf("helpers ran for a local user: %v", got)
	}
}

func TestResolveRefusesRootFromNSS(t *testing.T) {
	m := newTestMap(t)
	m.Exec = (&stubExec{reply: map[string]string{
		"id -u evil": "0", "id -g evil": "0", "id -G evil": "0",
	}}).run

	if _, err := m.Resolve(context.Background(), "evil"); !errors.Is(err, ErrRootRefused) {
		t.Fatalf("err = %v, want ErrRootRefused", err)
	}

	// getent claiming uid 0 is refused the same way.
	m.Exec = (&stubExec{reply: map[string]string{
		"getent passwd evil": "evil:x:0:0::/root:/bin/sh", "id -G evil": "0",
	}}).run
	if _, err := m.Resolve(context.Background(), "evil"); !errors.Is(err, ErrRootRefused) {
		t.Fatalf("getent path err = %v, want ErrRootRefused", err)
	}

	// A name that passwd itself maps to uid 0 never reaches the NSS path.
	id, err := m.Resolve(context.Background(), "admin")
	if err != nil || id.UID != 0 || id.Source != SourcePasswd {
		t.Fatalf("admin = %+v, err = %v", id, err)
	}
}

// A user whose QTS name is all digits must never be resolved through the
// helpers: getent passwd 1000 and id -u 1000 are uid lookups and would answer
// with whoever owns uid 1000.
func TestLookupNSSRefusesNumericName(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{reply: map[string]string{
		// What the NAS would answer if these ever ran: alice, not the
		// authenticated LDAP user called "1000".
		"getent passwd 1000": "alice:x:1000:100:Alice:/share/homes/alice:/bin/sh\n",
		"id -u 1000":         "1000\n",
		"id -g 1000":         "100\n",
		"id -G 1000":         "100 1050\n",
	}}
	m.Exec = s.run

	for _, name := range []string{"1000", "0", "007", "99999999999999999999"} {
		if !ValidName(name) {
			t.Errorf("ValidName(%q) = false; the name itself is well formed", name)
		}
		if _, err := m.LookupNSS(context.Background(), name); !errors.Is(err, ErrNumericName) {
			t.Errorf("LookupNSS(%q) err = %v, want ErrNumericName", name, err)
		}
		if _, err := m.Resolve(context.Background(), name); !errors.Is(err, ErrNumericName) {
			t.Errorf("Resolve(%q) err = %v, want ErrNumericName", name, err)
		}
	}
	if got := s.seen(); len(got) != 0 {
		t.Fatalf("a helper ran for a numeric name: %v", got)
	}

	// The cache refuses it too, and caches nothing.
	c := NewCache(m, time.Minute)
	if _, err := c.Resolve(context.Background(), "1000"); !errors.Is(err, ErrNumericName) {
		t.Errorf("cached Resolve err = %v, want ErrNumericName", err)
	}
	if c.Len() != 0 {
		t.Error("a refused numeric name was cached")
	}

	// Unless /etc/passwd itself lists that exact name, which is name-keyed and
	// therefore unambiguous.
	p, g := writeFixtures(t, passwdFixture+"1000:x:1234:100:Numeric:/share/homes/1000:/bin/sh\n", groupFixture)
	m2 := Open(p, g)
	m2.checkInterval = 0
	m2.Exec = s.run
	id, err := m2.LookupNSS(context.Background(), "1000")
	if err != nil {
		t.Fatalf("LookupNSS(1000) with a passwd entry: %v", err)
	}
	if id.UID != 1234 || id.Name != "1000" || id.Source != SourcePasswd {
		t.Errorf("id = %+v, want the passwd entry for 1000", id)
	}
	if got := s.seen(); len(got) != 0 {
		t.Fatalf("a helper ran for a local numeric name: %v", got)
	}
}

// getent must answer for the name that was asked for, byte for byte.
func TestLookupNSSRefusesNameMismatch(t *testing.T) {
	m := newTestMap(t)

	// getent passwd <name> answering about somebody else.
	s := &stubExec{reply: map[string]string{
		"getent passwd jane": "alice:x:1000:100:Alice:/share/homes/alice:/bin/sh\n",
		"id -G jane":         "100 1050\n",
	}}
	m.Exec = s.run
	if _, err := m.LookupNSS(context.Background(), "jane"); !errors.Is(err, ErrNameMismatch) {
		t.Errorf("err = %v, want ErrNameMismatch", err)
	}

	// Case differences are a mismatch as well: NSS names are byte strings.
	s = &stubExec{reply: map[string]string{
		"getent passwd jane": "Jane:x:20001:20000:Jane:/share/homes/jane:/bin/sh\n",
	}}
	m.Exec = s.run
	if _, err := m.LookupNSS(context.Background(), "jane"); !errors.Is(err, ErrNameMismatch) {
		t.Errorf("case mismatch err = %v, want ErrNameMismatch", err)
	}

	// The id path is cross-checked against getent passwd <uid>.
	s = &stubExec{
		reply: map[string]string{
			"id -u jane":          "1000\n",
			"id -g jane":          "100\n",
			"id -G jane":          "100\n",
			"getent passwd 1000":  "alice:x:1000:100:Alice:/share/homes/alice:/bin/sh\n",
			"getent passwd 20001": "jane:x:20001:20000:Jane:/share/homes/jane:/bin/sh\n",
		},
		fail: map[string]bool{"getent passwd jane": true},
	}
	m.Exec = s.run
	if _, err := m.LookupNSS(context.Background(), "jane"); !errors.Is(err, ErrNameMismatch) {
		t.Errorf("id path err = %v, want ErrNameMismatch", err)
	}

	// A matching name on both paths still succeeds.
	s = &stubExec{reply: map[string]string{
		"getent passwd jane": "jane:x:20001:20000:Jane:/share/homes/jane:/bin/sh\n",
		"id -G jane":         "20000 10513\n",
	}}
	m.Exec = s.run
	id, err := m.LookupNSS(context.Background(), "jane")
	if err != nil {
		t.Fatalf("matching getent answer: %v", err)
	}
	if id.UID != 20001 || id.GID != 20000 || id.Source != SourceNSS {
		t.Errorf("id = %+v", id)
	}

	// And so does the id path when getent agrees about the uid.
	s = &stubExec{
		reply: map[string]string{
			"id -u jane":          "20001\n",
			"id -g jane":          "20000\n",
			"id -G jane":          "20000 10513\n",
			"getent passwd 20001": "jane:x:20001:20000:Jane:/share/homes/jane:/bin/sh\n",
		},
		fail: map[string]bool{"getent passwd jane": true},
	}
	m.Exec = s.run
	id, err = m.LookupNSS(context.Background(), "jane")
	if err != nil {
		t.Fatalf("agreeing cross-check: %v", err)
	}
	if id.UID != 20001 || !eqInts(id.Groups, []int{10513, 20000}) {
		t.Errorf("id = %+v", id)
	}
}

// The DOMAIN\user form, which is what actually reaches this package on a
// domain-joined NAS, is unaffected by the name binding.
func TestLookupNSSDomainNameUnaffected(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{reply: map[string]string{
		`getent passwd DOMAIN\alice`: `DOMAIN\alice:x:20003:20000:Alice:/share/homes/DOMAIN/alice:/bin/sh`,
		`id -G DOMAIN\alice`:         "20000 10513\n",
	}}
	m.Exec = s.run

	id, err := m.Resolve(context.Background(), `DOMAIN\alice`)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Name != `DOMAIN\alice` || id.UID != 20003 || id.GID != 20000 {
		t.Errorf("id = %+v", id)
	}
	if want := []int{10513, 20000}; !eqInts(id.Groups, want) {
		t.Errorf("groups = %v, want %v", id.Groups, want)
	}
	if got := s.seen(); len(got) != 2 {
		t.Errorf("calls = %v, want getent + id -G only", got)
	}
}

func TestCacheResolve(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{reply: map[string]string{
		"id -u jane": "20001", "id -g jane": "20000", "id -G jane": "20000 10513",
	}}
	m.Exec = s.run
	c := NewCache(m, 0)
	if c.TTL() != DefaultCacheTTL {
		t.Errorf("TTL = %v, want %v", c.TTL(), DefaultCacheTTL)
	}

	first, err := c.Resolve(context.Background(), "jane")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if first.Source != SourceNSS {
		t.Errorf("first source = %q, want %q", first.Source, SourceNSS)
	}
	nAfterFirst := len(s.seen())

	second, err := c.Resolve(context.Background(), "jane")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if second.Source != SourceCache {
		t.Errorf("second source = %q, want %q", second.Source, SourceCache)
	}
	if second.UID != 20001 || !eqInts(second.Groups, []int{10513, 20000}) {
		t.Errorf("cached id = %+v", second)
	}
	if got := len(s.seen()); got != nAfterFirst {
		t.Errorf("cache hit re-executed helpers: %d then %d calls", nAfterFirst, got)
	}

	// Local users bypass the cache entirely.
	local, err := c.Resolve(context.Background(), "bob")
	if err != nil || local.Source != SourcePasswd {
		t.Fatalf("bob = %+v, err = %v", local, err)
	}
	if c.Len() != 1 {
		t.Errorf("cache holds %d entries, want 1", c.Len())
	}

	c.Forget("jane")
	if c.Len() != 0 {
		t.Errorf("Forget left %d entries", c.Len())
	}
}

func TestCacheExpiry(t *testing.T) {
	m := newTestMap(t)
	s := &stubExec{reply: map[string]string{
		"id -u jane": "20001", "id -g jane": "20000", "id -G jane": "20000",
	}}
	m.Exec = s.run

	c := NewCache(m, time.Nanosecond)
	if _, err := c.Resolve(context.Background(), "jane"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if c.Len() != 0 {
		t.Fatal("entry outlived its TTL")
	}
	if _, err := c.Resolve(context.Background(), "jane"); err != nil {
		t.Fatal(err)
	}
	// Two full resolutions: getent by name (fails), id -u, the getent uid
	// cross-check (fails), id -g and id -G each time.
	if got := len(s.seen()); got != 10 {
		t.Errorf("helper calls = %d, want 10", got)
	}
}

func TestCacheRefusesRoot(t *testing.T) {
	m := newTestMap(t)
	m.Exec = (&stubExec{reply: map[string]string{
		"id -u evil": "0", "id -g evil": "0", "id -G evil": "0",
	}}).run
	c := NewCache(m, time.Minute)
	if _, err := c.Resolve(context.Background(), "evil"); !errors.Is(err, ErrRootRefused) {
		t.Fatalf("err = %v, want ErrRootRefused", err)
	}
	if c.Len() != 0 {
		t.Error("a refused identity was cached")
	}
}

func TestDecideAdmin(t *testing.T) {
	m := newTestMap(t) // group administrators is gid 0, member: admin

	local := Ident{Name: "admin", UID: 0, GID: 0, Groups: []int{0}}
	byGroup := Ident{Name: "helper", UID: 1005, GID: 100, Groups: []int{0, 100}}
	plain := Ident{Name: "alice", UID: 1001, GID: 100, Groups: []int{100, 1050}}

	cases := []struct {
		name        string
		qts         bool
		id          Ident
		requireBoth bool
		wantAdmin   bool
		wantNote    bool
	}{
		{"both agree, requireBoth", true, local, true, true, false},
		{"both agree, trust qts", true, local, false, true, false},
		{"admin by group, requireBoth", true, byGroup, true, true, false},
		{"qts only, requireBoth lowers", true, plain, true, false, true},
		{"qts only, trust qts grants", true, plain, false, true, true},
		{"local only, requireBoth lowers", false, local, true, false, true},
		{"local only, trust qts lowers", false, local, false, false, true},
		{"neither, requireBoth", false, plain, true, false, false},
		{"neither, trust qts", false, plain, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			admin, note := DecideAdmin(tc.qts, tc.id, m, tc.requireBoth)
			if admin != tc.wantAdmin {
				t.Errorf("admin = %v, want %v (note %q)", admin, tc.wantAdmin, note)
			}
			if (note != "") != tc.wantNote {
				t.Errorf("note = %q, want note = %v", note, tc.wantNote)
			}
		})
	}
}

func TestIsLocalAdmin(t *testing.T) {
	m := newTestMap(t)

	if !IsLocalAdmin(Ident{Name: "root", UID: 0}, nil) {
		t.Error("uid 0 must be admin even without a Map")
	}
	if IsLocalAdmin(Ident{Name: "alice", UID: 1001, Groups: []int{100}}, nil) {
		t.Error("no Map must not grant admin")
	}
	// Partial identity: groups were not enumerated, but the group file lists
	// the name as a member.
	partial := Ident{Name: "admin", UID: 1500, GID: 100, Groups: []int{100}, Partial: true}
	if !IsLocalAdmin(partial, m) {
		t.Error("member list of administrators was not consulted")
	}
	if IsLocalAdmin(Ident{Name: "alice", UID: 1001, Groups: []int{100, 1050}}, m) {
		t.Error("alice is not an administrator")
	}

	// A NAS whose group file has no administrators group at all.
	p, g := writeFixtures(t, passwdFixture, "everyone:x:100:alice\n")
	m2 := Open(p, g)
	m2.checkInterval = 0
	if IsLocalAdmin(Ident{Name: "alice", UID: 1001, Groups: []int{100}}, m2) {
		t.Error("admin granted without an administrators group")
	}
	admin, note := DecideAdmin(true, Ident{Name: "alice", UID: 1001, Groups: []int{100}}, m2, true)
	if admin || note == "" {
		t.Errorf("admin = %v, note = %q", admin, note)
	}
}

func runtimeIsWindows() bool { return runtime.GOOS == "windows" }
