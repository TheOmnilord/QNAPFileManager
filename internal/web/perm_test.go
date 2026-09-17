package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/idmap"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The M3 route tests (contract §15, "web"): all four routes against the fakes,
// the guard on both spellings, the ordered token parts and their redemption, the
// aclmode ladder driven by an INJECTED platform table built from the golden hero
// mountinfo, the two hard refusals, the audit pairing and the forced chown
// milestone, /api/ids bounds and narrowing, the properties shape, and the
// read-only blanket over all four.
//
// Nothing here exercises kernel permission semantics — the fake applies a mode
// change arithmetically (server_test.go) and INV-2 forbids simulating the
// kernel. What IS exercised is every decision the route makes before and after
// the kernel is involved, which is where M3's risk lives.

// --- fixtures -----------------------------------------------------------------

// permFixture is jobsFixture with an IDENTITY path mapping, so an API path is
// its own OS path and an injected mount table is consulted exactly as
// production's is (mountFacts → Platform.For). The fake backend keeps serving
// out of its own temp dir, which is independent of Server.Root.
func permFixture(t *testing.T) (*Server, *fakeBackend, *fakeJobs) {
	t.Helper()
	s, b, fj := jobsFixture(t, jobs.Limits{})
	s.Root = fsx.Root{}
	return s, b, fj
}

// mkAPIDir/mkAPIFile create the backing entry for an API path inside the fake.
func mkAPIDir(t *testing.T, b *fakeBackend, apiPath string) {
	t.Helper()
	if err := os.MkdirAll(b.osPath(apiPath), 0o755); err != nil {
		t.Fatal(err)
	}
}

func mkAPIFile(t *testing.T, b *fakeBackend, apiPath, data string) {
	t.Helper()
	mkAPIDir(t, b, fsx.Parent(apiPath))
	if err := os.WriteFile(b.osPath(apiPath), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sessionFlags rewrites the live session's privilege flags. The fixture's pinned
// principal is deliberately neither root nor admin (New strips Root), so a test
// that needs either says so explicitly — and says it under the session lock,
// which is where a forced revalidation would write them.
func sessionFlags(t *testing.T, s *Server, id string, root, admin bool) {
	t.Helper()
	s.mu.Lock()
	sess := s.sessions[id]
	s.mu.Unlock()
	if sess == nil {
		t.Fatalf("no session %q", id)
	}
	sess.mu.Lock()
	sess.who.Root, sess.admin = root, admin
	sess.mu.Unlock()
}

// heroPlatform builds the injected mount table: the captured QuTS hero
// mountinfo, an xattr probe that answers nfs4, and a `zfs get` that returns the
// given aclmode. Nothing branches on family — the ladder asks Platform.For, and
// this is how that answer is made deterministic on a Windows dev box
// (PLAN decision 15).
func heroPlatform(t *testing.T, aclmode string) *platform.Platform {
	t.Helper()
	return heroPlatformPerDataset(t, nil, func(string) string { return aclmode })
}

// heroPlatformPerDataset is heroPlatform with the two probes answering PER
// MOUNT, which is what a hero pool actually looks like: one dataset per share
// (and often per sub-folder), each with its own aclmode. backendFor may be nil,
// in which case every storage mount is NFSv4. The golden mountinfo already
// nests — /share/ZFS530_DATA/Public is a dataset inside /share/ZFS530_DATA — so
// no synthetic row is needed to exercise a crossing walk.
func heroPlatformPerDataset(t *testing.T, backendFor func(mountRoot string) string, aclmodeFor func(dataset string) string) *platform.Platform {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "platform", "testdata", "hero_mountinfo.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := platform.FromMountinfo(f)
	if err != nil {
		t.Fatal(err)
	}
	p.SetXattrProbe(func(path, name string) (int, error) {
		want := platform.XattrNFS4ACL
		if backendFor != nil && backendFor(path) == platform.ACLPosix {
			want = platform.XattrPosixACL
		}
		if name == want {
			return 88, nil
		}
		return 0, platform.ErrNotSupported
	})
	p.SetCommandRunner(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		// `zfs get -Hp -o value aclmode <dataset>`: the dataset is the last arg.
		mode := aclmodeFor(args[len(args)-1])
		if mode == "" {
			return nil, fmt.Errorf("zfs: not available")
		}
		return []byte(mode + "\n"), nil
	})
	p.Probe()
	return p
}

// decodeConfirm reads a 409 challenge (confirmEnvelope, jobs_test.go) — the
// token, the path-free summary, and M3's explicit grade.
func decodeConfirm(t *testing.T, resp *http.Response) confirmEnvelope {
	t.Helper()
	var out confirmEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// modeEnvelope is the 200 body of a completed chmod/chown.
type modeEnvelope struct {
	Before   fsx.Entry   `json:"before"`
	Entry    fsx.Entry   `json:"entry"`
	Diffs    []perm.Diff `json:"diffs"`
	Warnings []string    `json:"warnings"`
}

// --- POST /api/fs/chmod --------------------------------------------------------

// TestChmodDispatchesResolvedSpellingAndAnswersTheDiff is the happy path: the
// worker is called with the RESOLVED spelling and the spec that was asked for,
// and the client is answered with the REQUESTED spelling in both entries.
func TestChmodDispatchesResolvedSpellingAndAnswersTheDiff(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/file.txt","mask":511,"value":493}`)
	if resp.StatusCode != 200 {
		t.Fatalf("chmod status %d: %s", resp.StatusCode, readBody(resp))
	}
	var body modeEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Entry.Path != "/data/file.txt" || body.Before.Path != "/data/file.txt" {
		t.Fatalf("the client must see the requested spelling: before=%q entry=%q", body.Before.Path, body.Entry.Path)
	}
	if body.Entry.Mode != "0755" {
		t.Fatalf("entry mode %q, want 0755", body.Entry.Mode)
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("chmod calls %d, want 1", len(b.chmodReqs))
	}
	got := b.chmodReqs[0]
	if string(got.Path) != "/data/file.txt" {
		t.Fatalf("dispatched path %q", got.Path)
	}
	if got.Spec.Mask != 0o777 || got.Spec.Value != 0o755 {
		t.Fatalf("dispatched spec %+v, want mask 0777 value 0755", got.Spec)
	}
	if got.Follow {
		t.Fatal("follow must default to false: a chmod acts on the named entry")
	}
}

// TestChmodRejectsAnUnusableSpec: bits chmod cannot set, and a request that
// changes nothing, are bad_request rather than silently-narrowed no-ops.
func TestChmodRejectsAnUnusableSpec(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	c, csrf := sessionCookie(t, s)
	for name, body := range map[string]string{
		"mask outside 07777":  `{"path":"/data/file.txt","mask":61440,"value":0}`,
		"value outside 07777": `{"path":"/data/file.txt","mask":511,"value":61440}`,
		"empty mask":          `{"path":"/data/file.txt","mask":0,"value":493}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := post(s, "/api/fs/chmod", c, csrf, body)
			if resp.StatusCode != 400 {
				t.Fatalf("status %d, want 400: %s", resp.StatusCode, readBody(resp))
			}
		})
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("a refused spec must never reach the worker")
	}
}

// TestChmodGuardsBothSpellings proves the §2.1 rule on the half that resolution
// can HIDE: a path that looks ordinary but resolves into the firmware config is
// confirmable, and the confirmation carries the guard's path-free reason — never
// the resolved spelling.
func TestChmodGuardsBothSpellings(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/etc/config")
	mkAPIFile(t, b, "/etc/config/thing", "x")
	mkAPIDir(t, b, "/data")
	s.backend = &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/alias": "/etc/config"}}
	s.mutator = s.backend.(*resolveStub)
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/alias/thing","mask":511,"value":493}`)
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want 409 confirm_required: %s", resp.StatusCode, readBody(resp))
	}
	env := decodeConfirm(t, resp)
	if env.Error.Code != "confirm_required" || env.Confirm.Token == "" {
		t.Fatalf("envelope %+v", env)
	}
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("a warn-class path is L2: grade %d", env.Confirm.Grade)
	}
	joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, "QTS firmware configuration") {
		t.Fatalf("the guard's reason must be shown: %q", joined)
	}
	if strings.Contains(readBody(resp)+joined, "/etc/config") {
		t.Fatal("the resolved spelling must never reach the client")
	}
}

// TestChmodRefusesAProtectedResolvedSpelling: a never-write region reached
// through an alias is refused outright, and the worker is never called.
func TestChmodRefusesAProtectedResolvedSpelling(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/data")
	mkAPIDir(t, b, "/proc")
	mkAPIFile(t, b, "/proc/thing", "x")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/alias": "/proc"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/alias/thing","mask":511,"value":493}`)
	if resp.StatusCode != 403 {
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, readBody(resp))
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q, want protected", e.Error.Code)
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("a protected chmod must never reach the worker")
	}
}

// TestChmodFollowReGuardsTheTarget is contract §1.4: follow:true makes the
// change land on the link's TARGET, which is a different object in a different
// place, so the route guards that target as a path of its own. Without it a
// symlink in an ordinary folder would be a way to chmod a protected location.
func TestChmodFollowReGuardsTheTarget(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/link", "x")
	mkAPIDir(t, b, "/proc")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/link": "/proc/thing"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	followed := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/link","mask":511,"value":493,"follow":true}`)
	if followed.StatusCode != 403 {
		t.Fatalf("status %d, want 403: %s", followed.StatusCode, readBody(followed))
	}
	var e apiEnvelope
	json.NewDecoder(followed.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q, want protected", e.Error.Code)
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("nothing may reach the worker")
	}
	// The very same request WITHOUT follow acts on the link itself, which is
	// ordinary — and the worker is given that spelling.
	plain := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/link","mask":511,"value":493}`)
	if plain.StatusCode != 200 {
		t.Fatalf("unfollowed status %d: %s", plain.StatusCode, readBody(plain))
	}
	if len(b.chmodReqs) != 1 || b.chmodReqs[0].Follow || string(b.chmodReqs[0].Path) != "/data/link" {
		t.Fatalf("dispatched %+v", b.chmodReqs)
	}
}

// TestChmodFollowDispatchesTheTarget is the success arm of §1.4: with follow the
// worker is handed the RESOLVED TARGET, not the link. Handing it the link plus a
// Follow flag could only ever answer unsupported — the worker walks O_NOFOLLOW
// and there is no lchmod — so the spelling the guard cleared, the spelling the
// token is bound to and the spelling dispatched are all the same one.
func TestChmodFollowDispatchesTheTarget(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/link", "x")
	mkAPIFile(t, b, "/data/real.txt", "x")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/link": "/data/real.txt"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/link","mask":511,"value":493,"follow":true}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d, want 200: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("chmod calls %d, want 1", len(b.chmodReqs))
	}
	if got := string(b.chmodReqs[0].Path); got != "/data/real.txt" {
		t.Fatalf("dispatched %q, want the resolved target", got)
	}
	if b.chmodReqs[0].Follow {
		t.Fatal("Follow is inert in M3 and must never go on the wire")
	}
	// The client still sees only the spelling it named.
	var body modeEnvelope
	json.NewDecoder(resp.Body).Decode(&body)
	if body.Entry.Path != "/data/link" {
		t.Fatalf("entry path %q, want the requested spelling", body.Entry.Path)
	}
}

// TestChmodSurfacesTheWorkerRefusalUnchanged: a symlink leaf without follow is
// the worker's unsupported (415), not a route-invented error.
func TestChmodSurfacesTheWorkerRefusalUnchanged(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	b.chmodErr = fsx.ErrUnsupported
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/file.txt","mask":511,"value":493}`)
	if resp.StatusCode != 415 {
		t.Fatalf("status %d, want 415: %s", resp.StatusCode, readBody(resp))
	}
}

// TestChmodDiffIsAWarningNotAnError is contract §3.3: a call the kernel
// completed DIFFERENTLY is a 200 carrying warnings, never an error.
func TestChmodDiffIsAWarningNotAnError(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	landed := uint32(0o755)
	b.chmodLands = &landed // the kernel dropped the setgid bit
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, `{"path":"/data/file.txt","mask":4095,"value":1517}`)
	if resp.StatusCode != 200 {
		t.Fatalf("a diff must not be an error: %d %s", resp.StatusCode, readBody(resp))
	}
	var body modeEnvelope
	json.NewDecoder(resp.Body).Decode(&body)
	if len(body.Diffs) == 0 || len(body.Warnings) == 0 {
		t.Fatalf("expected diffs and warnings: %+v", body)
	}
	if !strings.Contains(strings.Join(body.Warnings, " "), "setgid") {
		t.Fatalf("warnings %v", body.Warnings)
	}
}

// --- the confirmation token (contract §7) --------------------------------------

// TestPermTokenPartsAreOrderedAndComplete pins the exact descriptor a token
// binds, in the exact order the contract fixes. It is what makes a token issued
// for 0755 unredeemable for 4755 and a non-recursive one unredeemable
// recursively — and, since round 6, one issued for an L1 passthrough sentence
// unredeemable once the same path grades L2 discard (Astra r6 #3). The ACL part
// is the folded pair over a fixed-width digest of the per-dataset table (r7 #1),
// so it stays in one position however many datasets the ladder reached.
func TestPermTokenPartsAreOrderedAndComplete(t *testing.T) {
	var acl aclVerdict
	acl.fold(aclFacts{dataset: "zpool1/a", aclmode: "discard"}, gradeTyped, true)
	acl.fold(aclFacts{dataset: "zpool1/b", aclmode: ""}, gradeTyped, true)
	if !strings.HasPrefix(acl.part(), "acl=2/true/") || len(acl.part()) != len("acl=2/true/")+32 {
		t.Fatalf("acl part %q, want the folded pair over a 16-byte digest in hex", acl.part())
	}
	got := permTokenParts(tokenKindJob, "chmod",
		perm.ModeSpec{Mask: 0o777, Value: 0o755},
		perm.ModeSpec{Mask: 0o7777, Value: 0o2755},
		-1, 100, true, true,
		acl,
		[]string{"/b", "/a"})
	want := []string{
		"kind=job", "op=chmod", "mask=0777", "value=0755", "dirs=7777/2755",
		"uid=-1", "gid=100", "recursive=true", "cross=true",
		acl.part(),
		"/a", "/b", // only the roots are sorted
	}
	if len(got) != len(want) {
		t.Fatalf("parts %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("part %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
}

// TestChmodTokenIsBoundToTheSpec: the token minted for one mode change does not
// redeem for another, so a confirmed 0755 cannot become a 4755.
func TestChmodTokenIsBoundToTheSpec(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/etc/config")
	mkAPIFile(t, b, "/etc/config/thing", "x")
	c, csrf := sessionCookie(t, s)
	first := post(s, "/api/fs/chmod", c, csrf, `{"path":"/etc/config/thing","mask":511,"value":493}`)
	if first.StatusCode != 409 {
		t.Fatalf("first status %d, want 409: %s", first.StatusCode, readBody(first))
	}
	token := decodeConfirm(t, first).Confirm.Token
	if token == "" {
		t.Fatal("no token")
	}
	// The same token, a different value: refused with a fresh challenge.
	swapped := post(s, "/api/fs/chmod", c, csrf, fmt.Sprintf(`{"path":"/etc/config/thing","mask":4095,"value":2477,"confirm":%q}`, token))
	if swapped.StatusCode != 409 {
		t.Fatalf("a token must not redeem for a different spec: %d %s", swapped.StatusCode, readBody(swapped))
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("nothing may have been dispatched")
	}
	// The identical request does redeem.
	same := post(s, "/api/fs/chmod", c, csrf, fmt.Sprintf(`{"path":"/etc/config/thing","mask":511,"value":493,"confirm":%q}`, token))
	if same.StatusCode != 200 {
		t.Fatalf("the matching re-post must succeed: %d %s", same.StatusCode, readBody(same))
	}
}

// TestPermTokenIsSingleUse: a redeemed token does not redeem twice.
func TestPermTokenIsSingleUse(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/etc/config")
	mkAPIFile(t, b, "/etc/config/thing", "x")
	c, csrf := sessionCookie(t, s)
	token := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, `{"path":"/etc/config/thing","mask":511,"value":493}`)).Confirm.Token
	body := fmt.Sprintf(`{"path":"/etc/config/thing","mask":511,"value":493,"confirm":%q}`, token)
	if resp := post(s, "/api/fs/chmod", c, csrf, body); resp.StatusCode != 200 {
		t.Fatalf("first redemption %d", resp.StatusCode)
	}
	if resp := post(s, "/api/fs/chmod", c, csrf, body); resp.StatusCode != 409 {
		t.Fatalf("a spent token must not redeem again: %d", resp.StatusCode)
	}
	if len(b.chmodReqs) != 1 {
		t.Fatalf("dispatches %d, want 1", len(b.chmodReqs))
	}
}

// TestSyncAndJobTokensDoNotInterchange is round-3 finding 4. For one
// non-recursive item the two routes' descriptors would otherwise coincide
// exactly — and they do not grade the request the same way: the sync route
// PROBES the entry's ACL state, while a job cannot and reads the mount
// pessimistically. A client must not be able to take the cheaper confirmation
// and spend it on the route that would have demanded the typed phrase.
func TestSyncAndJobTokensDoNotInterchange(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/etc/config")
	mkAPIFile(t, b, "/etc/config/thing", "x")
	c, csrf := sessionCookie(t, s)
	syncBody := `{"path":"/etc/config/thing","mask":511,"value":493}`
	jobBody := `{"paths":[{"path":"/etc/config/thing"}],"files":{"mask":511,"value":493}}`
	syncToken := decodeConfirm(t, post(s, "/api/fs/chmod", c, csrf, syncBody)).Confirm.Token
	jobToken := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, jobBody)).Confirm.Token
	if syncToken == "" || jobToken == "" {
		t.Fatal("both routes must challenge on a warn-class path")
	}
	if resp := post(s, "/api/jobs/chmod", c, csrf, withToken(jobBody, syncToken)); resp.StatusCode != 409 {
		t.Fatalf("a sync token redeemed at the job route: %d %s", resp.StatusCode, readBody(resp))
	}
	if resp := post(s, "/api/fs/chmod", c, csrf, withToken(syncBody, jobToken)); resp.StatusCode != 409 {
		t.Fatalf("a job token redeemed at the sync route: %d %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chmodReqs) != 0 || len(fj.requests()) != 0 {
		t.Fatal("nothing may have been dispatched")
	}
	// Each still redeems at its own route.
	if resp := post(s, "/api/fs/chmod", c, csrf, withToken(syncBody, syncToken)); resp.StatusCode != 200 {
		t.Fatalf("sync token at the sync route: %d %s", resp.StatusCode, readBody(resp))
	}
	if resp := post(s, "/api/jobs/chmod", c, csrf, withToken(jobBody, jobToken)); resp.StatusCode != 202 {
		t.Fatalf("job token at the job route: %d %s", resp.StatusCode, readBody(resp))
	}
}

// --- the aclmode ladder (contract §7) ------------------------------------------

// TestACLLadderOverHeroMountinfo is the §14 promise made good: the riskiest new
// judgement in M3 is decided by a data table, so it is tested exhaustively on a
// dev box — the captured hero mountinfo × every aclmode × every ACL state.
//
// The mount half of the facts comes from the REAL injected platform table, so
// this also covers the plumbing (Root.OS → Platform.For → FSCaps), not just the
// table lookup.
func TestACLLadderOverHeroMountinfo(t *testing.T) {
	const dataset = "zpool1/zfs530_data/Public"
	const shareAPI = "/share/ZFS530_DATA/Public"
	for _, aclmode := range []string{"discard", "groupmask", "passthrough", "restricted", ""} {
		t.Run("aclmode="+orUnknown(aclmode), func(t *testing.T) {
			s, _, _ := permFixture(t)
			s.platform = heroPlatform(t, aclmode)
			facts := s.mountFacts(shareAPI)
			if facts.backend != platform.ACLNFS4 {
				t.Fatalf("backend %q, want nfs4 — the injected table is not being consulted", facts.backend)
			}
			if facts.aclmode != aclmode {
				t.Fatalf("aclmode %q, want %q", facts.aclmode, aclmode)
			}
			if facts.dataset != dataset {
				t.Fatalf("dataset %q, want %q", facts.dataset, dataset)
			}
			for _, state := range []string{fsx.ACLNone, fsx.ACLNFS4Trivial, fsx.ACLNFS4, fsx.ACLUnknown, ""} {
				f := facts
				f.state = state
				grade, notice, discards := chmodACLNotice(f)
				trivial := state == fsx.ACLNone || state == fsx.ACLNFS4Trivial
				switch {
				case trivial:
					// Nothing the mode does not already describe: no promotion,
					// not even under aclmode=discard.
					if grade != gradeNone || notice != "" || discards {
						t.Fatalf("state %q: grade %d notice %q discards %v, want no rung", state, grade, notice, discards)
					}
				case aclmode == "discard" || aclmode == "":
					// "" is READ as discard, never as passthrough.
					if grade != gradeTyped || !discards {
						t.Fatalf("state %q aclmode %q: grade %d discards %v, want L2", state, aclmode, grade, discards)
					}
					if !strings.Contains(notice, dataset) {
						t.Fatalf("the L2 sentence must name the dataset: %q", notice)
					}
					if (aclmode == "") != strings.Contains(notice, "could not be read") {
						t.Fatalf("an unreadable aclmode must say so: %q", notice)
					}
				default:
					if grade != gradeConfirm || notice == "" || discards {
						t.Fatalf("state %q aclmode %q: grade %d notice %q", state, aclmode, grade, notice)
					}
				}
			}
		})
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unreadable"
	}
	return s
}

// TestACLLadderPosixBackend covers the other backend row: the POSIX mask
// rewrite is L1 when the entry carries a POSIX ACL — and equally when nobody
// LOOKED, which is Astra round-1 finding 9. A chmod job grades every entry
// unknown because it cannot probe a tree it has not walked, and an uninspected
// POSIX ACL is not a harmless one: the same change through the sync route, which
// does probe, asks for the acknowledgement.
func TestACLLadderPosixBackend(t *testing.T) {
	for state, wantGrade := range map[string]int{
		fsx.ACLPosix:   gradeConfirm,
		fsx.ACLNone:    gradeNone,
		fsx.ACLUnknown: gradeConfirm,
		"":             gradeConfirm,
	} {
		grade, notice, discards := chmodACLNotice(aclFacts{backend: platform.ACLPosix, state: state})
		if grade != wantGrade || discards {
			t.Fatalf("posix state %q: grade %d (want %d) discards %v", state, grade, wantGrade, discards)
		}
		if wantGrade == gradeConfirm && notice != aclPosixMaskNotice {
			t.Fatalf("posix notice %q", notice)
		}
	}
	// A mount with no ACL backend never produces a rung, whatever the state.
	if grade, _, _ := chmodACLNotice(aclFacts{backend: platform.ACLNone, state: fsx.ACLNFS4}); grade != gradeNone {
		t.Fatalf("no backend must produce no rung, got grade %d", grade)
	}
}

// TestChmodOnDiscardDatasetDemandsATypedConfirm drives the whole ladder through
// the HTTP route: the 409 carries grade 2 and names the dataset.
func TestChmodOnDiscardDatasetDemandsATypedConfirm(t *testing.T) {
	s, b, _ := permFixture(t)
	s.platform = heroPlatform(t, "discard")
	const p = "/share/ZFS530_DATA/Public/file.txt"
	mkAPIFile(t, b, p, "x")
	b.aclState = map[string]string{p: fsx.ACLNFS4}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/fs/chmod", c, csrf, fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p))
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want 409: %s", resp.StatusCode, readBody(resp))
	}
	env := decodeConfirm(t, resp)
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want %d", env.Confirm.Grade, gradeTyped)
	}
	joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, "zpool1/zfs530_data/Public") || !strings.Contains(joined, "DESTROY") {
		t.Fatalf("warnings %q", joined)
	}
	if len(b.chmodReqs) != 0 {
		t.Fatal("nothing may be dispatched before the confirmation is redeemed")
	}
	// A trivial ACL on the same dataset is not promoted: there is nothing to
	// destroy, so the normal rules apply and the chmod goes straight through.
	b.aclState[p] = fsx.ACLNFS4Trivial
	if again := post(s, "/api/fs/chmod", c, csrf, fmt.Sprintf(`{"path":%q,"mask":511,"value":493}`, p)); again.StatusCode != 200 {
		t.Fatalf("a trivial ACL must not be promoted: %d %s", again.StatusCode, readBody(again))
	}
}

// TestCrossingLadderGradesEveryDatasetBelowTheRoot is round-4's finding. A hero
// pool is one dataset per share and often per sub-folder, and crossMounts sends
// the walk into every child. Grading the selected ROOT alone let a passthrough
// parent promise "other entries are kept" and then destroy the ACLs of a discard
// child one directory down — with discards false, so the change was not even a
// milestone. The rung is now the worst of every dataset the walk can reach.
func TestCrossingLadderGradesEveryDatasetBelowTheRoot(t *testing.T) {
	const parent = "/share/ZFS530_DATA"
	const childDataset = "zpool1/zfs530_data/Public"
	// The golden table nests: zpool1/zfs530_data is the parent of
	// zpool1/zfs530_data/{Public,Media,Publication,Home Videos}.
	discardChild := func(dataset string) string {
		if dataset == childDataset {
			return "discard"
		}
		return "passthrough"
	}

	t.Run("passthrough parent, discard child, crossing", func(t *testing.T) {
		s, b, _ := permFixture(t)
		s.platform = heroPlatformPerDataset(t, nil, discardChild)
		mkAPIDir(t, b, parent)
		c, csrf := sessionCookie(t, s)
		env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
			`{"paths":[{"path":"`+parent+`"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`))
		if env.Confirm.Grade != gradeTyped {
			t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
		}
		joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
		if !strings.Contains(joined, childDataset) || !strings.Contains(joined, "DESTROY") {
			t.Fatalf("the discarding child must be named: %q", joined)
		}
	})

	t.Run("same tree without crossing stays L1", func(t *testing.T) {
		s, b, _ := permFixture(t)
		s.platform = heroPlatformPerDataset(t, nil, discardChild)
		mkAPIDir(t, b, parent)
		c, csrf := sessionCookie(t, s)
		env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
			`{"paths":[{"path":"`+parent+`"}],"files":{"mask":511,"value":493},"recursive":true}`))
		if env.Confirm.Grade != gradeConfirm {
			t.Fatalf("grade %d, want L1: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
		}
		joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
		if !strings.Contains(joined, "passthrough") || strings.Contains(joined, "DESTROY") {
			t.Fatalf("a walk that stays on the parent grades on the parent: %q", joined)
		}
	})

	t.Run("crossing without recursion is inert", func(t *testing.T) {
		// A non-recursive job never descends, so grading it on child datasets
		// would promote a plain multi-select to L2 — and to a milestone — over
		// ACLs it will not touch (round-5 nit 1).
		s, b, _ := permFixture(t)
		s.platform = heroPlatformPerDataset(t, nil, discardChild)
		mkAPIDir(t, b, parent)
		c, csrf := sessionCookie(t, s)
		env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
			`{"paths":[{"path":"`+parent+`"}],"files":{"mask":511,"value":493},"crossMounts":true}`))
		if env.Confirm.Grade != gradeConfirm {
			t.Fatalf("grade %d, want L1: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
		}
		joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
		if strings.Contains(joined, childDataset) || strings.Contains(joined, "DESTROY") {
			t.Fatalf("a non-recursive job must not be graded on datasets it cannot reach: %q", joined)
		}
	})

	t.Run("every discarding dataset is named, not just the first", func(t *testing.T) {
		// The fold de-duplicates by dataset identity, so two distinct children
		// are two — a collapse here would under-state what is about to be
		// destroyed.
		s, b, _ := permFixture(t)
		discarders := map[string]bool{childDataset: true, "zpool1/zfs530_data/Media": true}
		s.platform = heroPlatformPerDataset(t, nil, func(dataset string) string {
			if discarders[dataset] {
				return "discard"
			}
			return "passthrough"
		})
		mkAPIDir(t, b, parent)
		c, csrf := sessionCookie(t, s)
		env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
			`{"paths":[{"path":"`+parent+`"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`))
		joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
		if !strings.Contains(joined, "datasets ") {
			t.Fatalf("two datasets must read as plural: %q", joined)
		}
		for dataset := range discarders {
			if !strings.Contains(joined, dataset) {
				t.Fatalf("%s is missing from %q", dataset, joined)
			}
		}
	})

	t.Run("posix parent, nfs4 child, crossing", func(t *testing.T) {
		s, b, _ := permFixture(t)
		s.platform = heroPlatformPerDataset(t,
			func(mountRoot string) string {
				if mountRoot == parent {
					return platform.ACLPosix
				}
				return platform.ACLNFS4
			},
			func(string) string { return "discard" })
		mkAPIDir(t, b, parent)
		c, csrf := sessionCookie(t, s)
		env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf,
			`{"paths":[{"path":"`+parent+`"}],"files":{"mask":511,"value":493},"recursive":true,"crossMounts":true}`))
		if env.Confirm.Grade != gradeTyped {
			t.Fatalf("grade %d, want L2: %v", env.Confirm.Grade, env.Confirm.Summary.Warnings)
		}
		if !strings.Contains(strings.Join(env.Confirm.Summary.Warnings, " | "), childDataset) {
			t.Fatalf("warnings %v", env.Confirm.Summary.Warnings)
		}
	})
}

// TestDatasetListIsBounded: a crossing walk can reach every dataset of a pool,
// and a dialog that spells forty of them is one nobody reads. What the sentence
// cannot show, it counts.
func TestDatasetListIsBounded(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{nil, "this dataset"},
		{[]string{""}, "this dataset"},
		{[]string{"", ""}, "these datasets"},
		{[]string{"p/a"}, "dataset p/a"},
		{[]string{"p/a", "p/b"}, "datasets p/a, p/b"},
		{[]string{"p/a", "p/b", "p/c", "p/d", "p/e"}, "datasets p/a, p/b, p/c and 2 more"},
		{[]string{"p/a", ""}, "datasets p/a and 1 more"},
		{[]string{"", "", ""}, "these datasets"},
		{[]string{"p/a", "", ""}, "datasets p/a and 2 more"},
	} {
		if got := datasetList(tc.in); got != tc.want {
			t.Errorf("datasetList(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The fold's de-dup key is what keeps those counts honest: several datasets
	// the mount table does not name are several, not one (round-5 nit 2).
	keys := map[string]bool{}
	for _, f := range []aclFacts{
		{dataset: "", mount: "/share/A"},
		{dataset: "", mount: "/share/B"},
		{dataset: "p/a", mount: "/share/C"},
		{dataset: "p/a", mount: "/share/D"}, // one dataset, mounted twice
	} {
		keys[f.key()] = true
	}
	if len(keys) != 3 {
		t.Fatalf("de-dup keys %v, want two unnamed datasets plus one named", keys)
	}
}

// --- POST /api/fs/chown --------------------------------------------------------

// TestChownIsAlwaysConfirmableAndAudited: any chown is L1 at minimum, says why,
// and leaves a paired intent/result in the durable record.
func TestChownIsAlwaysConfirmableAndAudited(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	events := withAudit(t, s)
	c, csrf := sessionCookie(t, s)
	first := post(s, "/api/fs/chown", c, csrf, `{"path":"/data/file.txt","uid":1003}`)
	if first.StatusCode != 409 {
		t.Fatalf("a chown always confirms first: %d %s", first.StatusCode, readBody(first))
	}
	env := decodeConfirm(t, first)
	if env.Confirm.Grade != gradeConfirm {
		t.Fatalf("grade %d, want %d", env.Confirm.Grade, gradeConfirm)
	}
	if !strings.Contains(strings.Join(env.Confirm.Summary.Warnings, " "), "setuid") {
		t.Fatalf("the setuid/setgid warning is mandatory: %v", env.Confirm.Summary.Warnings)
	}
	resp := post(s, "/api/fs/chown", c, csrf, fmt.Sprintf(`{"path":"/data/file.txt","uid":1003,"confirm":%q}`, env.Confirm.Token))
	if resp.StatusCode != 200 {
		t.Fatalf("confirmed chown %d: %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chownReqs) != 1 || b.chownReqs[0].UID != 1003 || b.chownReqs[0].GID != -1 {
		t.Fatalf("dispatched %+v, want uid 1003 gid -1", b.chownReqs)
	}
	recorded := events()
	var intent, result *audit.Event
	for i := range recorded {
		ev := &recorded[i]
		if ev.Op != "chown" {
			continue
		}
		if ev.Phase == "intent" && ev.Result == "" {
			intent = ev
		}
		if ev.Phase == "result" && ev.Result == "ok" {
			result = ev
		}
	}
	if intent == nil || result == nil {
		t.Fatalf("intent/result pair missing: %+v", recorded)
	}
	if !strings.Contains(intent.Detail, "uid=1003") {
		t.Fatalf("intent detail %q must say what was asked", intent.Detail)
	}
	if !strings.Contains(result.Detail, "uid ") || !strings.Contains(result.Detail, "->1003") {
		t.Fatalf("result detail %q must say what landed", result.Detail)
	}
	for _, ev := range recorded {
		if strings.Contains(ev.Detail, "/data/file.txt") {
			t.Fatalf("the M3 audit Detail is path-free: %q", ev.Detail)
		}
	}
}

// TestChownRejectsAnEmptyOrNegativeRequest: a chown that names neither half
// changes nothing, and a negative id must not be smuggled in as chown(2)'s
// "leave this alone" sentinel.
func TestChownRejectsAnEmptyOrNegativeRequest(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	c, csrf := sessionCookie(t, s)
	for name, body := range map[string]string{
		"neither half": `{"path":"/data/file.txt"}`,
		"negative uid": `{"path":"/data/file.txt","uid":-1}`,
		"negative gid": `{"path":"/data/file.txt","gid":-5}`,
		// uid_t is 32 bits and everything below the wire narrows to it, so an id
		// past the end truncates: 4294967296 would become 0 — ROOT — while the
		// audit line and the token both recorded the number that was typed. And
		// 4294967295 is (uid_t)-1, chown(2)'s own "leave this half alone", which
		// is not an id anybody may ask for (round-3 finding 1).
		"uid wraps to root":  `{"path":"/data/file.txt","uid":4294967296}`,
		"uid is the -1 flag": `{"path":"/data/file.txt","uid":4294967295}`,
		"gid wraps":          `{"path":"/data/file.txt","gid":4294967296}`,
		"gid is the -1 flag": `{"path":"/data/file.txt","gid":4294967295}`,
	} {
		t.Run(name, func(t *testing.T) {
			if resp := post(s, "/api/fs/chown", c, csrf, body); resp.StatusCode != 400 {
				t.Fatalf("status %d, want 400: %s", resp.StatusCode, readBody(resp))
			}
		})
	}
	// The largest id that is an id, and the smallest, are both accepted.
	for name, body := range map[string]string{
		"uid 0":          `{"path":"/data/file.txt","uid":0}`,
		"uid at the cap": `{"path":"/data/file.txt","uid":4294967294}`,
	} {
		t.Run(name, func(t *testing.T) {
			if resp := post(s, "/api/fs/chown", c, csrf, body); resp.StatusCode != 409 {
				t.Fatalf("status %d, want the 409 challenge: %s", resp.StatusCode, readBody(resp))
			}
		})
	}
	// follow is not a field of the chown API at all: M3 has exactly one chown
	// semantics (§1.4), and an unknown field is a refusal, not a silent no-op.
	if resp := post(s, "/api/fs/chown", c, csrf, `{"path":"/data/file.txt","uid":1,"follow":true}`); resp.StatusCode != 400 {
		t.Fatalf("follow must not be accepted: %d %s", resp.StatusCode, readBody(resp))
	}
	if len(b.chownReqs) != 0 {
		t.Fatal("nothing may reach the worker")
	}
}

// TestChownNeverSendsCreateAs is contract §5.3: ownership is not CreateAs. The
// admin-as-real-user rule applies to content an admin CREATES; chown is the
// ownership operation itself, so an admin's chown is a plain root chown.
func TestChownNeverSendsCreateAs(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	c, csrf := sessionCookie(t, s)
	sessionFlags(t, s, c.Value, true, true)
	env := decodeConfirm(t, post(s, "/api/fs/chown", c, csrf, `{"path":"/data/file.txt","gid":100}`))
	if resp := post(s, "/api/fs/chown", c, csrf, fmt.Sprintf(`{"path":"/data/file.txt","gid":100,"confirm":%q}`, env.Confirm.Token)); resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, readBody(resp))
	}
	if b.lastAs != nil {
		t.Fatalf("a chown must not carry CreateAs: %+v", b.lastAs)
	}
	if b.chownReqs[0].UID != -1 || b.chownReqs[0].GID != 100 {
		t.Fatalf("dispatched %+v", b.chownReqs[0])
	}
}

// --- the two hard refusals ------------------------------------------------------

// TestRecursiveSpecialBitSetIsRefused is contract §1.3: a recursive chmod may
// CLEAR setuid/setgid/sticky and may never SET one. It is a refusal, not a
// confirmation, because no legitimate workflow needs it in a single call.
func TestRecursiveSpecialBitSetIsRefused(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	c, csrf := sessionCookie(t, s)
	for name, body := range map[string]string{
		"setuid on files": `{"paths":[{"path":"/data/tree"}],"files":{"mask":4095,"value":2493},"recursive":true}`,
		"setgid on dirs":  `{"paths":[{"path":"/data/tree"}],"dirs":{"mask":4095,"value":1517},"recursive":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			resp := post(s, "/api/jobs/chmod", c, csrf, body)
			if resp.StatusCode != 400 {
				t.Fatalf("status %d, want 400: %s", resp.StatusCode, readBody(resp))
			}
			var e apiEnvelope
			json.NewDecoder(resp.Body).Decode(&e)
			if e.Error.Code != "bad_request" {
				t.Fatalf("code %q", e.Error.Code)
			}
		})
	}
	// Clearing them recursively is the cleanup that DOES get needed, and stays.
	job := acceptedJob(t, post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/tree"}],"files":{"mask":4095,"value":493},"recursive":true}`))
	awaitTerminal(t, s, job.ID)
	var dispatched bool
	for _, req := range fj.requests() {
		if req.Kind == wproto.JobChmod {
			dispatched = true
		}
	}
	if !dispatched {
		t.Fatal("the permitted recursion must have been dispatched")
	}
}

// TestShallowRecursiveRootIsRefused is contract §4.5: a recursive apply rooted
// at / or at any depth-1 path is refused for EVERY session, root included. It is
// the one place M3 adds a hard refusal rather than a confirmation.
func TestShallowRecursiveRootIsRefused(t *testing.T) {
	for _, root := range []bool{false, true} {
		t.Run(fmt.Sprintf("root=%v", root), func(t *testing.T) {
			s, b, fj := permFixture(t)
			mkAPIDir(t, b, "/data")
			c, csrf := sessionCookie(t, s)
			sessionFlags(t, s, c.Value, root, root)
			resp := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data"}],"files":{"mask":511,"value":493},"recursive":true}`)
			if resp.StatusCode != 403 {
				t.Fatalf("status %d, want 403: %s", resp.StatusCode, readBody(resp))
			}
			var e apiEnvelope
			json.NewDecoder(resp.Body).Decode(&e)
			if e.Error.Code != "protected" {
				t.Fatalf("code %q, want protected", e.Error.Code)
			}
			if len(fj.requests()) != 0 {
				t.Fatal("nothing may be dispatched")
			}
			// Depth 2 is ordinary and proceeds.
			mkAPIDir(t, b, "/data/tree")
			if ok := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/tree"}],"files":{"mask":511,"value":493},"recursive":true}`); ok.StatusCode != 202 {
				t.Fatalf("a depth-2 root must be allowed: %d %s", ok.StatusCode, readBody(ok))
			}
		})
	}
}

// TestPathDepth pins the arithmetic the refusal turns on.
func TestPathDepth(t *testing.T) {
	for p, want := range map[string]int{"/": 0, "": 0, "/etc": 1, "/share": 1, "/share/X": 2, "/a/b/c": 3} {
		if got := pathDepth(p); got != want {
			t.Errorf("pathDepth(%q) = %d, want %d", p, got, want)
		}
	}
}

// TestRecursiveIsNotRefusedWhenNotRecursive: the refusal is about RECURSION, so
// a non-recursive job over a depth-1 path is an ordinary request.
func TestRecursiveIsNotRefusedWhenNotRecursive(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/data")
	c, csrf := sessionCookie(t, s)
	if resp := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data"}],"files":{"mask":511,"value":493}}`); resp.StatusCode != 202 {
		t.Fatalf("status %d, want 202: %s", resp.StatusCode, readBody(resp))
	}
}

// --- the recursive jobs ---------------------------------------------------------

// TestRecursiveScaleDemandsATypedConfirm: the L2 rung takes the MEASURED count
// from the pre-scan, run through the user's own worker.
func TestRecursiveScaleDemandsATypedConfirm(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	fj.result = wproto.JobResult{Files: 8000, Dirs: 3}
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/tree"}],"files":{"mask":511,"value":493},"recursive":true}`)
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want 409: %s", resp.StatusCode, readBody(resp))
	}
	env := decodeConfirm(t, resp)
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want %d", env.Confirm.Grade, gradeTyped)
	}
	joined := strings.Join(env.Confirm.Summary.Warnings, " | ")
	if !strings.Contains(joined, "8003 items") || !strings.Contains(joined, "cannot be undone") {
		t.Fatalf("the measured count must be shown: %q", joined)
	}
	job := acceptedJob(t, post(s, "/api/jobs/chmod", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/data/tree"}],"files":{"mask":511,"value":493},"recursive":true,"confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	var chmodReq *wproto.JobReq
	for i, req := range fj.requests() {
		if req.Kind == wproto.JobChmod {
			chmodReq = &fj.requests()[i]
		}
	}
	if chmodReq == nil {
		t.Fatalf("no chmod job dispatched: %+v", fj.requests())
	}
	var wire wproto.ChmodJobReq
	if err := json.Unmarshal(chmodReq.Body, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Paths) != 1 || string(wire.Paths[0]) != "/data/tree" || !wire.Recursive {
		t.Fatalf("dispatched %+v", wire)
	}
	if wire.Files.Mask != 0o777 || wire.Files.Value != 0o755 || wire.Dirs.Mask != 0 {
		t.Fatalf("specs %+v (a zero dirs mask is folders-untouched)", wire)
	}
}

// TestRecursiveRootFollowsTheShareSymlink is round-2 finding 1: every share on a
// QTS box is reached through a symlink, and the worker walks the canonical
// spelling O_NOFOLLOW. A recursive job handed the LINK is not handed a tree —
// chmod would skip it and chown would lchown the link and report success for a
// tree it never entered. The target is what must be dispatched.
func TestRecursiveRootFollowsTheShareSymlink(t *testing.T) {
	for _, route := range []string{"/api/jobs/chmod", "/api/jobs/chown"} {
		t.Run(route, func(t *testing.T) {
			s, b, fj := permFixture(t)
			mkAPIDir(t, b, "/share/CACHEDEV1_DATA/Public")
			mkAPIDir(t, b, "/share")
			stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/share/Public": "/share/CACHEDEV1_DATA/Public"}}
			s.backend, s.mutator = stub, stub
			c, csrf := sessionCookie(t, s)
			body := `{"paths":[{"path":"/share/Public"}],"files":{"mask":511,"value":493},"recursive":true}`
			if route == "/api/jobs/chown" {
				body = `{"paths":[{"path":"/share/Public"}],"uid":1003,"recursive":true}`
			}
			awaitTerminal(t, s, submitPerm(t, s, c, csrf, route, body).ID)
			var dispatched []string
			for _, req := range fj.requests() {
				if req.Kind != wproto.JobChmod && req.Kind != wproto.JobChown {
					continue
				}
				var wire struct {
					Paths [][]byte `json:"p"`
				}
				if err := json.Unmarshal(req.Body, &wire); err != nil {
					t.Fatal(err)
				}
				for _, p := range wire.Paths {
					dispatched = append(dispatched, string(p))
				}
			}
			if len(dispatched) != 1 || dispatched[0] != "/share/CACHEDEV1_DATA/Public" {
				t.Fatalf("dispatched %v, want the followed target", dispatched)
			}
		})
	}
}

// TestJobChownBoundsItsIDs: the same 32-bit truncation trap on the job route.
func TestJobChownBoundsItsIDs(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	c, csrf := sessionCookie(t, s)
	for name, body := range map[string]string{
		"uid wraps to root":  `{"paths":[{"path":"/data/tree"}],"uid":4294967296}`,
		"uid is the -1 flag": `{"paths":[{"path":"/data/tree"}],"uid":4294967295}`,
		"gid wraps":          `{"paths":[{"path":"/data/tree"}],"gid":4294967296}`,
	} {
		t.Run(name, func(t *testing.T) {
			if resp := post(s, "/api/jobs/chown", c, csrf, body); resp.StatusCode != 400 {
				t.Fatalf("status %d, want 400: %s", resp.StatusCode, readBody(resp))
			}
		})
	}
	if len(fj.requests()) != 0 {
		t.Fatal("an out-of-range id must never reach a worker")
	}
	if resp := post(s, "/api/jobs/chown", c, csrf, `{"paths":[{"path":"/data/tree"}],"uid":4294967294}`); resp.StatusCode != 409 {
		t.Fatalf("the cap itself is an id: %d %s", resp.StatusCode, readBody(resp))
	}
}

// TestRecursiveRootTargetIsGuarded: a root that looks ordinary but whose target
// is protected is refused, and the worker never sees it.
func TestRecursiveRootTargetIsGuarded(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/link")
	mkAPIDir(t, b, "/proc/sys")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/link": "/proc/sys"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/link"}],"files":{"mask":511,"value":493},"recursive":true}`)
	if resp.StatusCode != 403 {
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, readBody(resp))
	}
	var e apiEnvelope
	json.NewDecoder(resp.Body).Decode(&e)
	if e.Error.Code != "protected" {
		t.Fatalf("code %q", e.Error.Code)
	}
	if strings.Contains(readBody(resp), "/proc") {
		t.Fatal("the resolved target must not reach the client")
	}
	if len(fj.requests()) != 0 {
		t.Fatal("nothing may be dispatched, not even a pre-scan")
	}
	// A NON-recursive job over the same root keeps the leaf literal: it acts on
	// the link itself, which is ordinary.
	if ok := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/link"}],"files":{"mask":511,"value":493}}`); ok.StatusCode != 202 {
		t.Fatalf("non-recursive over the link: %d %s", ok.StatusCode, readBody(ok))
	}
}

// TestRecursiveTokenIsBoundToTheTarget: the token binds the spelling the work
// LANDS on, so one issued while a link pointed at A cannot be redeemed once it
// points at B.
func TestRecursiveTokenIsBoundToTheTarget(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/a")
	mkAPIDir(t, b, "/data/b")
	mkAPIDir(t, b, "/data/link")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/link": "/data/a"}}
	s.backend, s.mutator = stub, stub
	fj.result = wproto.JobResult{Files: 8000}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/data/link"}],"files":{"mask":511,"value":493},"recursive":true}`
	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Token == "" {
		t.Fatal("no token")
	}
	// The link is re-pointed between the challenge and the re-post.
	stub.aliases["/data/link"] = "/data/b"
	if again := post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)); again.StatusCode != 409 {
		t.Fatalf("a token bound to /data/a must not redeem for /data/b: %d %s", again.StatusCode, readBody(again))
	}
	for _, req := range fj.requests() {
		if req.Kind == wproto.JobChmod {
			t.Fatal("nothing may have been dispatched")
		}
	}
}

// TestRedemptionReusesTheMeasuredCount is round-2 finding 3: the pre-scan walks
// the tree to state how many items the change touches, and the re-post must not
// walk it again. The count is remembered against the unforgeable token and read
// back on redemption.
func TestRedemptionReusesTheMeasuredCount(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	fj.result = wproto.JobResult{Files: 8000, Dirs: 3}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/data/tree"}],"files":{"mask":511,"value":493},"recursive":true}`
	env := decodeConfirm(t, post(s, "/api/jobs/chmod", c, csrf, body))
	if env.Confirm.Summary.Files != 8003 {
		t.Fatalf("the challenge must carry the measured count: %+v", env.Confirm.Summary)
	}
	scansAfterChallenge := countSizeJobs(fj)
	if scansAfterChallenge == 0 {
		t.Fatal("the challenge must have measured something")
	}
	job := acceptedJob(t, post(s, "/api/jobs/chmod", c, csrf, withToken(body, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	if got := countSizeJobs(fj); got != scansAfterChallenge {
		t.Fatalf("the redemption re-scanned: %d size jobs, want %d", got, scansAfterChallenge)
	}
}

// submitPerm posts a permissions job and, when the ladder demands one, redeems
// the confirmation for it — which is exactly what the client does. It exists
// because whether a given request is confirmable is the thing under test
// elsewhere, and a test about dispatch should not have to know.
func submitPerm(t *testing.T, s *Server, c *http.Cookie, csrf, route, body string) jobs.Job {
	t.Helper()
	resp := post(s, route, c, csrf, body)
	if resp.StatusCode == http.StatusConflict {
		env := decodeConfirm(t, resp)
		if env.Confirm.Token == "" {
			t.Fatalf("%s: 409 without a token", route)
		}
		resp = post(s, route, c, csrf, withToken(body, env.Confirm.Token))
	}
	return acceptedJob(t, resp)
}

// countSizeJobs counts the pre-scan round trips the fake worker was asked for.
func countSizeJobs(fj *fakeJobs) int {
	n := 0
	for _, req := range fj.requests() {
		if req.Kind == wproto.JobSize {
			n++
		}
	}
	return n
}

// TestPermScanRespectsTheRequestBudget: the scan is bounded by the handler
// context, not by a timeout of its own, and a request with no room left does not
// start a walk it cannot finish — it reports -1, which the ladder reads as large.
func TestPermScanRespectsTheRequestBudget(t *testing.T) {
	s, _, fj := permFixture(t)
	fj.result = wproto.JobResult{Files: 5}
	spent, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-spent.Done()
	if got := s.permScan(spent, backend.Principal{}, []string{"/data/tree"}, false); got != -1 {
		t.Fatalf("an exhausted budget must measure nothing: %d", got)
	}
	if n := countSizeJobs(fj); n != 0 {
		t.Fatalf("no walk may be started with no budget: %d size jobs", n)
	}
	// With room, it measures.
	roomy, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	if got := s.permScan(roomy, backend.Principal{}, []string{"/data/tree"}, false); got != 5 {
		t.Fatalf("permScan = %d, want 5", got)
	}
}

// TestUnmeasurableRecursionIsTreatedAsLarge: a pre-scan that fails leaves the
// daemon unable to say the operation is small, so it says so and asks for the
// typed phrase.
func TestUnmeasurableRecursionIsTreatedAsLarge(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	fj.err = fsx.ErrWorkerGone
	c, csrf := sessionCookie(t, s)
	resp := post(s, "/api/jobs/chmod", c, csrf, `{"paths":[{"path":"/data/tree"}],"files":{"mask":511,"value":493},"recursive":true}`)
	if resp.StatusCode != 409 {
		t.Fatalf("status %d, want 409: %s", resp.StatusCode, readBody(resp))
	}
	env := decodeConfirm(t, resp)
	if env.Confirm.Grade != gradeTyped {
		t.Fatalf("grade %d, want %d", env.Confirm.Grade, gradeTyped)
	}
	if !strings.Contains(strings.Join(env.Confirm.Summary.Warnings, " | "), "unknown number of items") {
		t.Fatalf("warnings %v", env.Confirm.Summary.Warnings)
	}
}

// TestJobChownDispatchesAndPairsItsAudit: the chown job carries its ids, is a
// forced milestone, and leaves an intent naming what it will do.
func TestJobChownDispatchesAndPairsItsAudit(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	events := withAudit(t, s)
	c, csrf := sessionCookie(t, s)
	env := decodeConfirm(t, post(s, "/api/jobs/chown", c, csrf, `{"paths":[{"path":"/data/tree"}],"uid":1003,"gid":100}`))
	if env.Confirm.Grade != gradeConfirm {
		t.Fatalf("grade %d", env.Confirm.Grade)
	}
	job := acceptedJob(t, post(s, "/api/jobs/chown", c, csrf, fmt.Sprintf(`{"paths":[{"path":"/data/tree"}],"uid":1003,"gid":100,"confirm":%q}`, env.Confirm.Token)))
	awaitTerminal(t, s, job.ID)
	var wire wproto.ChownJobReq
	for _, req := range fj.requests() {
		if req.Kind == wproto.JobChown {
			if err := json.Unmarshal(req.Body, &wire); err != nil {
				t.Fatal(err)
			}
		}
	}
	if wire.UID != 1003 || wire.GID != 100 {
		t.Fatalf("dispatched %+v", wire)
	}
	var sawIntent, sawResult bool
	for _, ev := range events() {
		if ev.Op != "chown" {
			continue
		}
		if ev.Phase == "intent" && strings.Contains(ev.Detail, "uid=1003 gid=100") {
			sawIntent = true
		}
		if ev.Phase == "result" && ev.Job != "" {
			sawResult = true
		}
	}
	if !sawIntent || !sawResult {
		t.Fatalf("intent %v result %v: %+v", sawIntent, sawResult, events())
	}
}

// TestPermMilestoneClassification is the §11 rule, stated once and tested once —
// the same shape as TestJobMilestoneClassification for the job hook.
func TestPermMilestoneClassification(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		op                            string
		discards, ordinary, recursive bool
		scanned                       int64
		want                          bool
	}{
		{name: "any chown is forced", op: "chown", ordinary: true, want: true},
		{name: "a recursive chown is forced too", op: "chown", ordinary: true, recursive: true, scanned: 1, want: true},
		{name: "an ordinary small chmod is not", op: "chmod", ordinary: true, want: false},
		{name: "a discarded ACL is", op: "chmod", ordinary: true, discards: true, want: true},
		{name: "a warn-class path is", op: "chmod", ordinary: false, want: true},
		{name: "a small recursion is not", op: "chmod", ordinary: true, recursive: true, scanned: 99, want: false},
		{name: "a large recursion is", op: "chmod", ordinary: true, recursive: true, scanned: 100, want: true},
		{name: "an unmeasurable recursion is", op: "chmod", ordinary: true, recursive: true, scanned: -1, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := permMilestone(tc.op, tc.discards, tc.ordinary, tc.recursive, tc.scanned); got != tc.want {
				t.Fatalf("permMilestone = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- the per-entry diff a recursive job reports (contract §3.3, §4.4) ------------

// TestModeJobPublishesTheWorkerSDiffSentence is round-3 finding 2. A recursive
// chmod's per-entry finding is "the kernel did it, but not as asked" — and the
// sentence IS the finding. Substituting a code-derived wording turned 400
// setgid-dropped warnings into "The request could not be completed", which is
// exactly the inversion §3.3 forbids: a call that succeeded, reported as one
// that did not.
func TestModeJobPublishesTheWorkerSDiffSentence(t *testing.T) {
	const sentence = "The setgid bit was not applied: you are not a member of group team."
	s, b, fj := permFixture(t)
	mkAPIDir(t, b, "/data/tree")
	fj.warns = []wproto.Warn{{Path: []byte("/data/tree/a"), Code: "unchanged", Message: sentence}}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/data/tree"}],"files":{"mask":4095,"value":493},"recursive":true}`
	job := submitPerm(t, s, c, csrf, "/api/jobs/chmod", body)
	awaitTerminal(t, s, job.ID)
	final, ok := s.jobMgr.Get(job.ID)
	if !ok {
		t.Fatal("job gone")
	}
	var found bool
	for _, line := range final.Warnings {
		if strings.Contains(line, sentence) && strings.Contains(line, "(unchanged)") {
			found = true
		}
		if strings.Contains(line, "The request could not be completed") {
			t.Fatalf("a diff was published as a failure: %q", line)
		}
	}
	if !found {
		t.Fatalf("the worker's own sentence must be published: %q", final.Warnings)
	}
	// The path in the warning line is the caller's own spelling, as everywhere.
	for _, line := range final.Warnings {
		if !strings.HasPrefix(line, "/data/tree/a: ") {
			t.Fatalf("warning line %q does not name the requested spelling", line)
		}
	}
}

// TestModeWarnMessageIsFencedAndKindAware covers the wordings themselves: the
// permissions kinds get sentences that describe a permissions walk, the copy
// kinds are untouched, and a worker sentence that could carry a path is refused
// rather than served.
func TestModeWarnMessageIsFencedAndKindAware(t *testing.T) {
	for _, tc := range []struct{ op, code, want string }{
		{"chmod", "unsupported", "This item was skipped: a symbolic link has no permissions of its own, or it is hard-linked elsewhere — change it by naming it directly."},
		{"chown", "unsupported", "This item was skipped: a symbolic link has no permissions of its own, or it is hard-linked elsewhere — change it by naming it directly."},
		{"chmod", "changed", "This item changed while the job was running and was skipped."},
		{"copy", "unsupported", "This kind of item cannot be copied."},
		{"copy", "changed", "This file changed while it was being copied."},
		{"move", "unsupported", "This kind of item cannot be copied."},
		{"delete", "protected", "This location is protected and was skipped."},
	} {
		if got := jobWarnMessage(tc.op, tc.code); got != tc.want {
			t.Errorf("jobWarnMessage(%q, %q) = %q, want %q", tc.op, tc.code, got, tc.want)
		}
	}
	const fallback = "The kernel did not apply this item's change exactly as asked."
	for name, raw := range map[string]string{
		"empty":             "",
		"carries a path":    "could not change /share/CACHEDEV1_DATA/Public/a",
		"carries a UNC-ish": `something \\server\share`,
	} {
		if got := modeWarnMessage(raw); got != fallback {
			t.Errorf("%s: modeWarnMessage(%q) = %q, want the fallback", name, raw, got)
		}
	}
	long := strings.Repeat("é", 400)
	if got := modeWarnMessage(long); len(got) > maxModeWarnBytes {
		t.Fatalf("an unbounded sentence was published: %d bytes", len(got))
	}
	plain := "The setuid bit was cleared by the change of owner."
	if got := modeWarnMessage(plain); got != plain {
		t.Fatalf("a path-free sentence must be served verbatim: %q", got)
	}
}

// --- the read-only blanket ------------------------------------------------------

// TestReadOnlyBlocksEveryPermissionRoute is the blanket test the contract asks
// all four new mutations to join: read-only mode refuses them whatever the path,
// and nothing reaches a worker.
func TestReadOnlyBlocksEveryPermissionRoute(t *testing.T) {
	s, b, fj := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	s.guard.SetReadOnly(true)
	c, csrf := sessionCookie(t, s)
	for route, body := range map[string]string{
		"/api/fs/chmod":   `{"path":"/data/file.txt","mask":511,"value":493}`,
		"/api/fs/chown":   `{"path":"/data/file.txt","uid":1000}`,
		"/api/jobs/chmod": `{"paths":[{"path":"/data/file.txt"}],"files":{"mask":511,"value":493}}`,
		"/api/jobs/chown": `{"paths":[{"path":"/data/file.txt"}],"uid":1000}`,
	} {
		t.Run(route, func(t *testing.T) {
			resp := post(s, route, c, csrf, body)
			if resp.StatusCode != 403 {
				t.Fatalf("status %d, want 403: %s", resp.StatusCode, readBody(resp))
			}
			var e apiEnvelope
			json.NewDecoder(resp.Body).Decode(&e)
			if e.Error.Code != "read_only" {
				t.Fatalf("code %q, want read_only", e.Error.Code)
			}
		})
	}
	if len(b.chmodReqs)+len(b.chownReqs)+len(fj.requests()) != 0 {
		t.Fatal("read-only mode must stop every dispatch")
	}
}

// TestPermissionRoutesAreMutationRoutes keeps the four in the set whose
// unauthenticated POST is audited as a denial (adv 10).
func TestPermissionRoutesAreMutationRoutes(t *testing.T) {
	for _, route := range []string{"/api/fs/chmod", "/api/fs/chown", "/api/jobs/chmod", "/api/jobs/chown"} {
		if !isMutationRoute(route) {
			t.Errorf("%s is missing from isMutationRoute", route)
		}
		if _, ok := routes[route]; !ok {
			t.Errorf("%s is not registered", route)
		}
	}
	if _, ok := routes["/api/fs/properties"]; !ok {
		t.Error("/api/fs/properties is not registered")
	}
}

// --- GET /api/fs/properties -------------------------------------------------------

// TestPropertiesShape pins the response the dialog reads, including the two
// things the ROUTE adds to what the worker returns: the capability hints and the
// guard's own classification.
func TestPropertiesShape(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	b.propsFS = wproto.FSInfo{FSType: "zfs", Mount: "/share/ZFS530_DATA", Avail: 7, Total: 9}
	b.propsACL = wproto.ACLInfo{Backend: platform.ACLNFS4, State: fsx.ACLNFS4Trivial, Aclmode: "discard", Dataset: "zpool1/x"}
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/data/file.txt", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var body struct {
		Entry fsx.Entry      `json:"entry"`
		FS    wproto.FSInfo  `json:"fs"`
		ACL   wproto.ACLInfo `json:"acl"`
		Caps  perm.Caps      `json:"caps"`
		Class string         `json:"class"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Entry.Path != "/data/file.txt" {
		t.Fatalf("entry path %q", body.Entry.Path)
	}
	if body.FS.FSType != "zfs" || body.ACL.State != fsx.ACLNFS4Trivial || body.ACL.Aclmode != "discard" {
		t.Fatalf("fs %+v acl %+v", body.FS, body.ACL)
	}
	if body.Class != "normal" {
		t.Fatalf("class %q, want normal", body.Class)
	}
	// The fake's entries are uid 0 and the session is uid 1000, so the hints say
	// "not yours" — and they are HINTS: nothing was refused.
	if body.Caps.Chmod || body.Caps.ChownUID || body.Caps.Reason == "" {
		t.Fatalf("caps %+v, want a non-owner's hints with a reason", body.Caps)
	}
	if len(b.propsReqs) != 1 || string(b.propsReqs[0].Path) != "/data/file.txt" {
		t.Fatalf("props calls %+v", b.propsReqs)
	}
}

// TestPropertiesDispatchesTheResolvedSpelling: fsops.Props walks the canonical
// spelling O_NOFOLLOW and never resolves for itself, so a route that dispatched
// what the client typed would answer 409 changed for every item under a
// symlinked share — which is every share on a real NAS. The worker must be given
// the resolved spelling, and the client must still see its own.
func TestPropertiesDispatchesTheResolvedSpelling(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/share/CACHEDEV1_DATA/Public")
	mkAPIFile(t, b, "/share/CACHEDEV1_DATA/Public/file.txt", "x")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/share/Public": "/share/CACHEDEV1_DATA/Public"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/share/Public/file.txt", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(b.propsReqs) != 1 {
		t.Fatalf("props calls %d, want 1", len(b.propsReqs))
	}
	if got := string(b.propsReqs[0].Path); got != "/share/CACHEDEV1_DATA/Public/file.txt" {
		t.Fatalf("dispatched %q, want the resolved spelling", got)
	}
	var body struct {
		Entry fsx.Entry `json:"entry"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Entry.Path != "/share/Public/file.txt" {
		t.Fatalf("entry path %q, want the requested spelling", body.Entry.Path)
	}
}

// TestPropertiesGuardsTheResolvedSpelling: resolution can reveal a protected
// target behind an ordinary-looking alias, and the refusal must not echo it.
func TestPropertiesGuardsTheResolvedSpelling(t *testing.T) {
	s, b, _ := permFixture(t)
	s.guard = guard.New("/data/app", false)
	mkAPIFile(t, b, "/data/app/config/settings.json", "{}")
	mkAPIDir(t, b, "/data/ordinary")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/ordinary": "/data/app/config"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/data/ordinary/settings.json", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"protected"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "/data/app") {
		t.Fatalf("the resolved spelling must never reach the client: %s", w.Body)
	}
	if len(b.propsReqs) != 0 {
		t.Fatal("a protected read must never reach the worker")
	}
}

// TestPropertiesGuardsTheFollowedTarget is round-2 finding 2: follow describes a
// DIFFERENT object, so that object is guarded as a path of its own. Without it a
// link into the app's config would report its mode, owner and size through a
// route that refuses that path when it is named.
func TestPropertiesGuardsTheFollowedTarget(t *testing.T) {
	s, b, _ := permFixture(t)
	s.guard = guard.New("/data/app", false)
	mkAPIFile(t, b, "/data/app/config/settings.json", "{}")
	mkAPIFile(t, b, "/data/link", "x")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/link": "/data/app/config/settings.json"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/data/link&follow=1", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 403 || !strings.Contains(w.Body.String(), `"code":"protected"`) {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "/data/app") {
		t.Fatalf("the target spelling must not reach the client: %s", w.Body)
	}
	if len(b.propsReqs) != 0 {
		t.Fatal("a refused follow must never reach the worker")
	}
	// The same link WITHOUT follow describes the link itself, which is ordinary.
	if ok := request(s, "GET", "/api/fs/properties?path=/data/link", c, map[string]string{"X-QFM-CSRF": csrf}); ok.Code != 200 {
		t.Fatalf("unfollowed: %d %s", ok.Code, ok.Body)
	}
	if len(b.propsReqs) != 1 || b.propsReqs[0].Follow {
		t.Fatalf("props calls %+v", b.propsReqs)
	}
}

// TestPropertiesSendsTheGuardedTarget is round-3 finding 3: the target travels
// as an already-resolved, already-guarded spelling rather than as a Follow flag
// the worker would honour by resolving the link a second time — a gap the client
// chooses, in which the link can be re-pointed at something the guard never saw.
// The described target is then published under the spelling this daemon
// authorised, never whatever the worker's own walk spelled it as.
func TestPropertiesSendsTheGuardedTarget(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/real.txt", "x")
	mkAPIFile(t, b, "/data/link", "x")
	stub := &resolveStub{fakeBackend: b, aliases: map[string]string{"/data/link": "/data/real.txt"}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/data/link&follow=1", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if len(b.propsReqs) != 1 {
		t.Fatalf("props calls %+v", b.propsReqs)
	}
	req := b.propsReqs[0]
	if string(req.Target) != "/data/real.txt" {
		t.Fatalf("Target = %q, want the guarded spelling", req.Target)
	}
	if req.Follow {
		t.Fatal("Follow is inert and must never go on the wire")
	}
	var body struct {
		Entry  fsx.Entry  `json:"entry"`
		Target *fsx.Entry `json:"target"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body.Entry.Path != "/data/link" {
		t.Fatalf("entry path %q, want the requested spelling", body.Entry.Path)
	}
	if body.Target == nil || body.Target.Path != "/data/real.txt" || body.Target.Name != "real.txt" {
		t.Fatalf("target %+v, want the API spelling this daemon guarded", body.Target)
	}
}

// TestPropertiesDoesNotFollowWhatItCannotGuard: a dangling link is not an error
// for the dialog (§8.1 wants Target nil), but it is also not something this
// daemon can vouch for — so it simply is not followed.
func TestPropertiesDoesNotFollowWhatItCannotGuard(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/dangling", "x")
	stub := &resolveStub{fakeBackend: b, dangling: map[string]bool{"/data/dangling": true}}
	s.backend, s.mutator = stub, stub
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/data/dangling&follow=1", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 200 {
		t.Fatalf("a link whose target does not resolve must not fail the dialog: %d %s", w.Code, w.Body)
	}
	if len(b.propsReqs) != 1 || b.propsReqs[0].Follow {
		t.Fatalf("follow must be dropped when the target cannot be guarded: %+v", b.propsReqs)
	}
}

// TestPropertiesCapsForRootAndProtectedClass: a root session may do everything,
// and the class reported is the GUARD's, not the listing's display hint.
func TestPropertiesCapsForRootAndProtectedClass(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIDir(t, b, "/etc/config")
	mkAPIFile(t, b, "/etc/config/thing", "x")
	c, csrf := sessionCookie(t, s)
	sessionFlags(t, s, c.Value, true, true)
	w := request(s, "GET", "/api/fs/properties?path=/etc/config/thing", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var body struct {
		Caps  perm.Caps `json:"caps"`
		Class string    `json:"class"`
	}
	json.Unmarshal(w.Body.Bytes(), &body)
	if !body.Caps.Chmod || !body.Caps.ChownUID || body.Caps.ChgrpTo != nil {
		t.Fatalf("root caps %+v: chmod and chown yes, ChgrpTo nil meaning any", body.Caps)
	}
	if body.Class != "warn" {
		t.Fatalf("class %q, want the guard's warn", body.Class)
	}
}

// TestPropertiesRefusesAProtectedRead: the app's own config holds the
// break-glass password hash and its logs hold the audit trail, both declared
// OpRead denials. The properties route must not become a way around them.
func TestPropertiesRefusesAProtectedRead(t *testing.T) {
	s, b, _ := permFixture(t)
	s.guard = guard.New("/data/app", false)
	mkAPIFile(t, b, "/data/app/config/settings.json", "{}")
	mkAPIFile(t, b, "/data/ordinary.txt", "x")
	c, csrf := sessionCookie(t, s)
	w := request(s, "GET", "/api/fs/properties?path=/data/app/config/settings.json", c, map[string]string{"X-QFM-CSRF": csrf})
	if w.Code != 403 {
		t.Fatalf("status %d, want 403: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"code":"protected"`) {
		t.Fatalf("body %s", w.Body)
	}
	if len(b.propsReqs) != 0 {
		t.Fatal("a protected read must never reach the worker")
	}
	// A dot component never reaches the guard at all.
	if bad := request(s, "GET", "/api/fs/properties?path=/data/../etc", c, map[string]string{"X-QFM-CSRF": csrf}); bad.Code != 400 {
		t.Fatalf("dot component: %d %s", bad.Code, bad.Body)
	}
	if ok := request(s, "GET", "/api/fs/properties?path=/data/ordinary.txt", c, map[string]string{"X-QFM-CSRF": csrf}); ok.Code != 200 {
		t.Fatalf("an ordinary path must still answer: %d %s", ok.Code, ok.Body)
	}
}

// --- the ACL badge (contract §6.2) --------------------------------------------------

// TestListAsksForTheACLProbe: the badge is filled by the LISTING, and nothing
// else asks for it — so a listing that does not set ACLProbe leaves the badge
// permanently absent, which is exactly how M3 round 1 shipped. The worker gates
// the probe on the mount's ACL backend and bounds it per page, so asking always
// is the right default and costs nothing where there is nothing to read.
func TestListAsksForTheACLProbe(t *testing.T) {
	s, b, _ := permFixture(t)
	mkAPIFile(t, b, "/data/file.txt", "x")
	c, csrf := sessionCookie(t, s)
	if w := request(s, "GET", "/api/fs/list?path=/data", c, map[string]string{"X-QFM-CSRF": csrf}); w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if !b.opts.ACLProbe {
		t.Fatalf("the listing must ask for the ACL probe: %+v", b.opts)
	}
}

// --- GET /api/ids -----------------------------------------------------------------

// TestIdentitiesNarrowedForANonAdmin is contract §10: the picker offers exactly
// what the session may set. The full local user roster was a disclosure nobody
// asked for, so a non-admin sees only itself and its own groups.
func TestIdentitiesNarrowedForANonAdmin(t *testing.T) {
	s, _, _ := permFixture(t)
	s.ids = idmapFixture(t)
	c, csrf := sessionCookie(t, s)
	users := decodeIDs(t, request(s, "GET", "/api/ids?kind=users", c, map[string]string{"X-QFM-CSRF": csrf}))
	if len(users.Items) != 1 || users.Items[0].ID != 1000 || users.Items[0].Name != "dev" {
		t.Fatalf("a non-admin must see only itself: %+v", users.Items)
	}
	groups := decodeIDs(t, request(s, "GET", "/api/ids?kind=groups", c, map[string]string{"X-QFM-CSRF": csrf}))
	if len(groups.Items) != 2 {
		t.Fatalf("a non-admin must see only its own groups: %+v", groups.Items)
	}
	for _, item := range groups.Items {
		if item.ID != 100 && item.ID != 200 {
			t.Fatalf("gid %d is not one of the session's groups", item.ID)
		}
	}
}

// TestIdentitiesForAnAdminAreBoundedAndFilterable: the full local lists, the
// q= prefix filter, and the idsMax bound with truncated.
func TestIdentitiesForAnAdminAreBoundedAndFilterable(t *testing.T) {
	s, _, _ := permFixture(t)
	s.ids = idmapFixture(t)
	c, csrf := sessionCookie(t, s)
	sessionFlags(t, s, c.Value, false, true)
	all := decodeIDs(t, request(s, "GET", "/api/ids?kind=users", c, map[string]string{"X-QFM-CSRF": csrf}))
	if len(all.Items) != 3 || all.Truncated {
		t.Fatalf("admin users %+v truncated=%v", all.Items, all.Truncated)
	}
	filtered := decodeIDs(t, request(s, "GET", "/api/ids?kind=users&q=BA", c, map[string]string{"X-QFM-CSRF": csrf}))
	if len(filtered.Items) != 1 || filtered.Items[0].Name != "backup" {
		t.Fatalf("prefix filter is case-insensitive over names: %+v", filtered.Items)
	}
	byID := decodeIDs(t, request(s, "GET", "/api/ids?kind=users&q=100", c, map[string]string{"X-QFM-CSRF": csrf}))
	if len(byID.Items) == 0 {
		t.Fatalf("the prefix also matches the id a picker displays: %+v", byID.Items)
	}
	groups := decodeIDs(t, request(s, "GET", "/api/ids?kind=groups", c, map[string]string{"X-QFM-CSRF": csrf}))
	if len(groups.Items) != 2 {
		t.Fatalf("admin groups %+v", groups.Items)
	}
	if w := request(s, "GET", "/api/ids?kind=nonsense", c, map[string]string{"X-QFM-CSRF": csrf}); w.Code != 400 {
		t.Fatalf("unknown kind %d", w.Code)
	}
	if w := request(s, "GET", "/api/ids?kind=users&q="+strings.Repeat("x", idsQueryMax+1), c, map[string]string{"X-QFM-CSRF": csrf}); w.Code != 400 {
		t.Fatalf("an unbounded prefix %d", w.Code)
	}
}

// TestFilterIdentitiesBound is the idsMax half, stated directly so the test does
// not need to synthesise a 2000-line passwd file.
func TestFilterIdentitiesBound(t *testing.T) {
	in := make([]idItem, 0, 10)
	for i := 0; i < 10; i++ {
		in = append(in, idItem{Name: fmt.Sprintf("u%d", i), ID: i})
	}
	out, truncated := filterIdentities(in, "", 4)
	if len(out) != 4 || !truncated {
		t.Fatalf("out %d truncated %v, want 4 and true", len(out), truncated)
	}
	out, truncated = filterIdentities(in, "", 10)
	if len(out) != 10 || truncated {
		t.Fatalf("an exact fit is not truncated: %d %v", len(out), truncated)
	}
	if out, _ = filterIdentities(in, "u1", 10); len(out) != 1 {
		t.Fatalf("prefix filter %+v", out)
	}
}

type idsEnvelope struct {
	Items     []idItem `json:"items"`
	Truncated bool     `json:"truncated"`
}

func decodeIDs(t *testing.T, w *httptest.ResponseRecorder) idsEnvelope {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("/api/ids status %d: %s", w.Code, w.Body)
	}
	var out idsEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// idmapFixture writes a small passwd/group pair and opens a Map over it, so the
// admin listing has something deterministic to list on every OS.
func idmapFixture(t *testing.T) *idmap.Map {
	t.Helper()
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	group := filepath.Join(dir, "group")
	if err := os.WriteFile(passwd, []byte("root:x:0:0::/root:/bin/sh\ndev:x:1000:100::/home/dev:/bin/sh\nbackup:x:1003:100::/home/backup:/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(group, []byte("users:x:100:dev,backup\nteam:x:200:dev\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return idmap.Open(passwd, group)
}

// --- the code-coverage table (contract §9) ------------------------------------------

// TestStatusCodeCoversEveryWorkerErrorCode is the WEB half of the contract's
// code-coverage table: every code a worker can emit maps to a deliberate HTTP
// status, so a new code cannot quietly become a 500.
//
// The M2-C loop found that gap three separate times (owner_unset, too_large,
// changed), and a table is cheaper than a fourth.
//
// The enumeration is fsx.WorkerCodes, the SAME list workerpool asserts against
// for RemoteError.Unwrap, so the two halves of the socket cannot disagree about
// what a worker may say. The expected statuses below are stated independently:
// a table that only asserted "not 500" would pass for a code mapped to the
// wrong status.
func TestStatusCodeCoversEveryWorkerErrorCode(t *testing.T) {
	want := map[string]int{
		"bad_request": 400, "ramdisk": 400,
		"unauthorized": 401,
		"permission":   403, "protected": 403, "readonly": 403, "read_only": 403,
		"not_found": 404,
		"exists":    409, "not_empty": 409, "cross_device": 409, "conflict": 409,
		"invalid_target": 409, "changed": 409, "owner_unset": 409, "no_trash": 409,
		"too_large": 413, "unsupported": 415, "queue_full": 429,
		"cancelled": 408, "confirm_required": 428,
		"worker_gone": 503, "no_space": 507,
		"audit_unavailable": 500, "internal": 500,
	}
	for code, status := range want {
		if got := statusCode(code); got != status {
			t.Errorf("statusCode(%q) = %d, want %d", code, got, status)
		}
	}
	// Every code a worker can emit must have a deliberate status here: a code
	// that falls through to the 500 default is a real-NAS 500 that no
	// in-process test would ever show.
	if len(fsx.WorkerCodes) == 0 {
		t.Fatal("fsx.WorkerCodes is empty")
	}
	for _, code := range fsx.WorkerCodes {
		status, known := want[code]
		if !known {
			t.Errorf("fsx.WorkerCodes has %q, which this table does not state a status for", code)
			continue
		}
		if status == 500 {
			t.Errorf("%q falls through to the 500 default", code)
		}
	}
	// M3 adds no error codes: every refusal it can make is already above.
	for _, code := range []string{"changed", "unsupported", "permission", "protected", "readonly", "confirm_required", "bad_request", "not_found", "cancelled"} {
		if _, ok := want[code]; !ok {
			t.Errorf("M3 refusal code %q is not in the table", code)
		}
	}
}

// --- the diff sentences (contract §3.2) ----------------------------------------------

// TestDiffWarningSentences covers the three silent cases identity plan §3.1
// names, each of which gets a sentence the UI shows verbatim.
func TestDiffWarningSentences(t *testing.T) {
	before := fsx.Entry{GID: 200, Group: "team", UID: 0}
	t.Run("setgid silently dropped by chmod", func(t *testing.T) {
		got := diffWarnings("chmod", wproto.ModeResp{Before: before,
			Diffs: []perm.Diff{{Field: perm.FieldSetgid, Want: "on", Got: "off"}}}, false)
		if len(got) != 1 || !strings.Contains(got[0], "not a member of group team") {
			t.Fatalf("%q", got)
		}
	})
	t.Run("setuid cleared by chown", func(t *testing.T) {
		got := diffWarnings("chown", wproto.ModeResp{Before: before,
			Diffs: []perm.Diff{{Field: perm.FieldSetuid, Want: "on", Got: "off"}}}, false)
		if len(got) != 1 || !strings.Contains(got[0], "cleared by the change of owner") {
			t.Fatalf("%q", got)
		}
	})
	t.Run("groupmask rewrote the mode", func(t *testing.T) {
		got := diffWarnings("chmod", wproto.ModeResp{Before: before,
			Diffs: []perm.Diff{{Field: perm.FieldMode, Want: "0750", Got: "0700"}}}, true)
		if len(got) != 1 || !strings.Contains(got[0], "aclmode=groupmask") || !strings.Contains(got[0], "0700") {
			t.Fatalf("%q", got)
		}
	})
	t.Run("an unnamed group falls back to the number", func(t *testing.T) {
		got := diffWarnings("chmod", wproto.ModeResp{Before: fsx.Entry{GID: 4242},
			Diffs: []perm.Diff{{Field: perm.FieldSetgid, Want: "on", Got: "off"}}}, false)
		if len(got) != 1 || !strings.Contains(got[0], "4242") {
			t.Fatalf("%q", got)
		}
	})
	if got := diffWarnings("chmod", wproto.ModeResp{}, false); len(got) != 0 {
		t.Fatalf("no diffs, no warnings: %q", got)
	}
}

// TestDiffDetailIsBoundedAndPathFree keeps the audit line small and free of
// anything that could be a path.
func TestDiffDetailIsBoundedAndPathFree(t *testing.T) {
	if got := diffDetail(nil); got != "" {
		t.Fatalf("%q", got)
	}
	many := make([]perm.Diff, 0, 12)
	for i := 0; i < 12; i++ {
		many = append(many, perm.Diff{Field: fmt.Sprintf("f%d", i), Want: "on", Got: "off"})
	}
	got := diffDetail(many)
	if !strings.Contains(got, "and 6 more") || strings.Contains(got, "f7") {
		t.Fatalf("unbounded detail: %q", got)
	}
}
