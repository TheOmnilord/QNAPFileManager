package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"taproot/internal/backend"
	"taproot/internal/jobs"
	"taproot/internal/wproto"
)

// Stabilization contract §2.4: the confirmation pre-flights of copy, move,
// delete and permissions fit inside the route's deadline at the selection
// limit, and the measuring in them stops on its budget rather than on the
// deadline.

// preflightLimit is the contract's ceiling for one pre-flight request at the
// selection limit: half of the 15 s every ordinary JSON route is given.
const preflightLimit = 7500 * time.Millisecond

// scaleJobs is the route tests' fake worker with a worker's size walk: a
// JobSize request is answered by walking the fake backend's own directory and
// counting what is there the way fsops does — the named root included,
// directories apart from files, bytes from the files — honouring the entry
// budget the request carries (Capped when it is reached) and the context (a
// cancelled walk answers its partial counts beside the context's error, as the
// pool does). cost, when set, is what each root takes before its walk starts:
// a slow disk. Every other request is fakeJobs' own.
type scaleJobs struct {
	*fakeJobs
	base string
	cost time.Duration
}

var errScaleCapped = errors.New("the fake walk reached its bound")

func (j *scaleJobs) Job(ctx context.Context, who backend.Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	if req.Kind != wproto.JobSize {
		return j.fakeJobs.Job(ctx, who, req, onProg, onWarn)
	}
	j.mu.Lock()
	j.reqs = append(j.reqs, req)
	j.mu.Unlock()
	var size wproto.SizeReq
	if err := json.Unmarshal(req.Body, &size); err != nil {
		return wproto.JobResult{}, err
	}
	var res wproto.JobResult
	if j.cost > 0 {
		select {
		case <-time.After(j.cost):
		case <-ctx.Done():
			res.Cancelled = true
			return res, ctx.Err()
		}
	}
	for _, p := range size.Paths {
		root := filepath.Join(j.base, filepath.FromSlash(strings.TrimPrefix(string(p), "/")))
		err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if d.IsDir() {
				res.Dirs++
			} else {
				res.Files++
				if info, ierr := d.Info(); ierr == nil {
					res.Bytes += info.Size()
				}
			}
			if size.MaxEntries > 0 && res.Files+res.Dirs >= size.MaxEntries {
				res.Capped = true
				return errScaleCapped
			}
			return nil
		})
		switch {
		case errors.Is(err, errScaleCapped):
			return res, nil
		case ctx.Err() != nil:
			res.Cancelled = true
			return res, ctx.Err()
		case err != nil:
			res.Warnings++
		}
	}
	return res, nil
}

// scaleFixture is the fixture the job route tests use, jobsFixture, with
// scaleJobs measuring and resolveStub resolving. One serves all four routes:
// none of them changes the tree — the dispatched jobs go to the fake worker —
// so a selection made once is the same selection for each.
//
// The resolver is the one transferFixture uses, and the reason is the timing
// this file exists for. The fake backend's own Resolve runs
// filepath.EvalSymlinks twice per call, and on Windows that normalises every
// path component with a FindFirstFile: about 7 ms per root on the dev box, so
// a thousand roots spend most of the deadline in the fixture. No production
// resolve has that cost — the worker resolves with openat as the user, and a
// round trip through the real pool and worker loop costs tens of
// microseconds before that work — so the selection's spellings are registered
// with the stub (scaleFiles, scaleDirs) and what is timed is the route.
func scaleFixture(t *testing.T) (*Server, *fakeBackend, *scaleJobs) {
	t.Helper()
	s, b, fj := jobsFixture(t, jobs.Limits{})
	sj := &scaleJobs{fakeJobs: fj, base: b.dir}
	s.SetJobs(sj, s.jobMgr)
	s.mutator = &resolveStub{fakeBackend: b, aliases: map[string]string{}}
	scaleAlias(s, "/dest")
	mkAPIDir(t, b, "/dest")
	return s, b, sj
}

// scaleAlias registers p as resolving to itself — as its own parent for the
// leaf-literal resolution every route makes, and whole for the followed one a
// destination and a recursive root get.
func scaleAlias(s *Server, paths ...string) {
	rs := s.mutator.(*resolveStub)
	for _, p := range paths {
		rs.aliases[p] = p
	}
}

// scaleFiles makes n one-byte files in dir and returns their API paths.
func scaleFiles(t *testing.T, s *Server, b *fakeBackend, dir string, n int) []string {
	t.Helper()
	mkAPIDir(t, b, dir)
	scaleAlias(s, dir)
	paths := make([]string, n)
	for i := range paths {
		paths[i] = fmt.Sprintf("%s/f%04d", dir, i)
		if err := os.WriteFile(b.osPath(paths[i]), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scaleAlias(s, paths...)
	return paths
}

// scaleDirs makes n folders in dir holding per one-byte files each, and returns
// the folders' API paths.
func scaleDirs(t *testing.T, s *Server, b *fakeBackend, dir string, n, per int) []string {
	t.Helper()
	scaleAlias(s, dir)
	paths := make([]string, n)
	for i := range paths {
		paths[i] = fmt.Sprintf("%s/d%04d", dir, i)
		mkAPIDir(t, b, paths[i])
		for k := 0; k < per; k++ {
			if err := os.WriteFile(b.osPath(fmt.Sprintf("%s/f%d", paths[i], k)), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	scaleAlias(s, paths...)
	return paths
}

// scaleRefs is the paths array of a job body.
func scaleRefs(t *testing.T, paths []string) string {
	t.Helper()
	refs := make([]pathRef, len(paths))
	for i, p := range paths {
		refs[i] = pathRef{Path: p}
	}
	b, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// scalePost is post under a context of the caller's choosing — the request a
// client sends with only so much time left — and says how long the answer took.
func scalePost(ctx context.Context, s *Server, target string, cookie *http.Cookie, csrf, body string) (*http.Response, time.Duration) {
	r := httptest.NewRequest("POST", target, strings.NewReader(body)).WithContext(ctx)
	r.AddCookie(cookie)
	r.Header.Set("X-Taproot-CSRF", csrf)
	r.Header.Set("Origin", "http://example.com")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	start := time.Now()
	s.Handler().ServeHTTP(w, r)
	return w.Result(), time.Since(start)
}

// scaleChallenge reads a 409 confirmation challenge.
func scaleChallenge(t *testing.T, what string, resp *http.Response) confirmEnvelope {
	t.Helper()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("%s: want 409 confirm_required, got %d %s", what, resp.StatusCode, readBody(resp))
	}
	var env confirmEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatal(err)
	}
	if env.Error.Code != "confirm_required" || env.Confirm.Token == "" {
		t.Fatalf("%s: %+v", what, env)
	}
	return env
}

// scaleOp is one of the four destructive routes the contract's test covers.
type scaleOp struct {
	name  string
	route string
	body  func(refs string) string
}

var scaleOps = []scaleOp{
	{name: "copy", route: "/api/jobs/copy", body: func(refs string) string { return `{"paths":` + refs + `,"dest":{"path":"/dest"}}` }},
	{name: "move", route: "/api/jobs/move", body: func(refs string) string { return `{"paths":` + refs + `,"dest":{"path":"/dest"}}` }},
	{name: "delete", route: "/api/jobs/delete", body: func(refs string) string { return `{"paths":` + refs + `}` }},
	// Recursive, so the route measures what it will touch (permScan), and the
	// thousand roots promote it to the typed phrase.
	{name: "permissions", route: "/api/jobs/chmod", body: func(refs string) string {
		return `{"paths":` + refs + `,"files":{"mask":511,"value":420},"recursive":true}`
	}},
}

// confirmAtScale sends op's challenge and its confirmed re-post, each under ctx
// as the client would, fails either above preflightLimit (or past ctx's own
// deadline), logs both wall times, and returns the challenge.
func confirmAtScale(t *testing.T, s *Server, op scaleOp, what string, paths []string, life time.Duration) confirmEnvelope {
	t.Helper()
	c, csrf := sessionCookie(t, s)
	body := op.body(scaleRefs(t, paths))
	limit := preflightLimit
	if life > 0 && life < limit {
		limit = life
	}
	within := func() (context.Context, context.CancelFunc) {
		if life > 0 {
			return context.WithTimeout(context.Background(), life)
		}
		return context.WithCancel(context.Background())
	}

	ctx, cancel := within()
	resp, challengeTook := scalePost(ctx, s, op.route, c, csrf, body)
	cancel()
	env := scaleChallenge(t, op.name+" "+what, resp)

	ctx, cancel = within()
	resp, confirmTook := scalePost(ctx, s, op.route, c, csrf, withToken(body, env.Confirm.Token))
	cancel()
	job := acceptedJob(t, resp)

	t.Logf("%s of %d %s: challenge %v, confirmed re-post %v (limit %v)", op.name, len(paths), what, challengeTook, confirmTook, limit)
	if challengeTook > limit || confirmTook > limit {
		t.Fatalf("%s of %d %s: challenge %v, confirmed re-post %v; each must answer within %v", op.name, len(paths), what, challengeTook, confirmTook, limit)
	}
	awaitTerminal(t, s, job.ID)
	return env
}

func hasWarning(env confirmEnvelope, want string) bool {
	for _, w := range env.Confirm.Summary.Warnings {
		if w == want {
			return true
		}
	}
	return false
}

// TestPreflightsFitTheDeadlineAtTheSelectionLimit is the contract's test: for
// copy, move, delete and permissions, exactly maxJobRoots small files through
// the real handler and the route tests' own backend. Each answers its
// confirmation challenge and accepts the confirmed re-post well inside the
// deadline — and, nothing having run out, the measured routes report the whole
// selection exactly.
func TestPreflightsFitTheDeadlineAtTheSelectionLimit(t *testing.T) {
	s, b, _ := scaleFixture(t)
	paths := scaleFiles(t, s, b, "/sel", maxJobRoots)
	for _, op := range scaleOps {
		t.Run(op.name, func(t *testing.T) {
			env := confirmAtScale(t, s, op, "files", paths, 0)
			sum := env.Confirm.Summary
			switch op.name {
			case "copy", "move":
				if sum.Files != maxJobRoots || sum.Bytes != maxJobRoots || hasWarning(env, noticeSizeMinimum) {
					t.Fatalf("summary %+v, want all %d files measured", sum, maxJobRoots)
				}
			case "delete":
				if sum.Files != maxJobRoots || sum.Bytes != maxJobRoots {
					t.Fatalf("summary %+v, want %d roots of one byte", sum, maxJobRoots)
				}
			case "permissions":
				if sum.Files != maxJobRoots || sum.Capped || env.Confirm.Grade != gradeTyped {
					t.Fatalf("summary %+v grade %d, want %d items scanned and the typed phrase", sum, env.Confirm.Grade, maxJobRoots)
				}
			}
		})
	}
}

// TestPreflightsFitTheDeadlineWithFolders is the contract's second case: the
// same thousand roots as folders holding a few files each. It must still
// answer within the deadline, and the size must be a minimum wherever the
// budget ran out — on this fixture it should not, so the totals must then be
// the whole trees exactly.
//
// Then the budget is made to run out: the same folders on a disk slow enough
// that walking them all would take five seconds, asked for by requests with
// four seconds to live. The measuring stops permScanReserve before that
// deadline, the roots it did not reach are not sized, the summary says the
// totals are a minimum (an unknown count, for a permissions change), and every
// challenge and confirmed re-post still answers in time. Four rather than
// three, so that the route's own work on a thousand roots — several times
// slower under the race detector — cannot use up the measuring window before
// the first walk starts.
func TestPreflightsFitTheDeadlineWithFolders(t *testing.T) {
	const per = 3
	s, b, sj := scaleFixture(t)
	paths := scaleDirs(t, s, b, "/tree", maxJobRoots, per)
	for _, op := range scaleOps {
		t.Run(op.name, func(t *testing.T) {
			env := confirmAtScale(t, s, op, "folders", paths, 0)
			sum := env.Confirm.Summary
			const entries, bytes = maxJobRoots * (per + 1), maxJobRoots * per
			switch op.name {
			case "copy", "move":
				minimum := hasWarning(env, noticeSizeMinimum)
				if !minimum && (sum.Files != entries || sum.Bytes != bytes) {
					t.Fatalf("summary %+v claims whole trees, want %d entries and %d bytes", sum, entries, bytes)
				}
				if minimum && sum.Files >= entries {
					t.Fatalf("summary %+v is marked a minimum but counted everything", sum)
				}
			case "delete":
				if sum.Files != maxJobRoots {
					t.Fatalf("summary %+v, want %d roots", sum, maxJobRoots)
				}
			case "permissions":
				if env.Confirm.Grade != gradeTyped || (!sum.Capped && sum.Files != entries) {
					t.Fatalf("summary %+v grade %d, want %d items scanned (or unknown) and the typed phrase", sum, env.Confirm.Grade, entries)
				}
			}
		})
	}

	const life = 4 * time.Second
	sj.cost = 5 * time.Millisecond // per root: a thousand of them is five seconds
	for _, op := range scaleOps {
		t.Run(op.name+" on a slow disk", func(t *testing.T) {
			before := countSizeJobs(sj.fakeJobs)
			env := confirmAtScale(t, s, op, "folders on a slow disk", paths, life)
			sized := countSizeJobs(sj.fakeJobs) - before
			t.Logf("%s: %d of %d roots sized", op.name, sized, maxJobRoots)
			sum := env.Confirm.Summary
			switch op.name {
			case "copy", "move":
				// The challenge and the re-post both measure, and neither may reach
				// the end of the selection.
				if sized == 0 || sized >= 2*maxJobRoots {
					t.Fatalf("%d size requests over two passes, want the budget to end part-way through each", sized)
				}
				if !hasWarning(env, noticeSizeMinimum) || sum.Files >= maxJobRoots*(per+1) {
					t.Fatalf("summary %+v, want a partial count marked a minimum", sum)
				}
			case "permissions":
				// Measured once, for the challenge; the re-post reads the count back
				// from its token (peekScan).
				if sized == 0 || sized >= maxJobRoots {
					t.Fatalf("%d size requests, want the budget to end part-way", sized)
				}
				if !sum.Capped || sum.Files != 0 || env.Confirm.Grade != gradeTyped {
					t.Fatalf("summary %+v grade %d, want an unknown count and the typed phrase", sum, env.Confirm.Grade)
				}
			case "delete":
				if sized != 0 || sum.Files != maxJobRoots {
					t.Fatalf("summary %+v after %d walks, want the roots counted and nothing walked", sum, sized)
				}
			}
		})
	}
}

// TestTransferPreflightSpendsOneEntryBudget: the 500,000 entries are the
// selection's, each root walked against what the roots before it left, and a
// root reached with nothing left is not walked at all. A move still asks every
// root which volume it is on — outside the budget — and an unmeasured root
// that crosses volumes says it moves an unknown amount.
func TestTransferPreflightSpendsOneEntryBudget(t *testing.T) {
	const holds = 300_000 // every root, walked against what it is given
	s, fj := transferFixture(t)
	fj.resultFor = func(req wproto.JobReq) (wproto.JobResult, error) {
		if req.Kind != wproto.JobSize {
			return wproto.JobResult{Files: 3, Bytes: 30}, nil
		}
		var size wproto.SizeReq
		if err := json.Unmarshal(req.Body, &size); err != nil {
			return wproto.JobResult{}, err
		}
		if size.MaxEntries > 0 && size.MaxEntries <= holds {
			return wproto.JobResult{Files: size.MaxEntries, Bytes: size.MaxEntries, Capped: true}, nil
		}
		return wproto.JobResult{Files: holds, Bytes: holds}, nil
	}
	fj.fsid = map[string]wproto.FSIdentityResp{"/real/a": {Dev: 2}, "/real/c": {Dev: 3}}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/src/a"},{"path":"/src/b"},{"path":"/src/c"}],"dest":{"path":"/dest"}}`
	env := challenge(t, s, c, csrf, "/api/jobs/move", body)

	var budgets []int64
	for _, req := range fj.requests() {
		var size wproto.SizeReq
		if err := json.Unmarshal(req.Body, &size); err != nil {
			t.Fatal(err)
		}
		budgets = append(budgets, size.MaxEntries)
	}
	if want := []int64{transferScanMaxEntries, transferScanMaxEntries - holds}; !reflect.DeepEqual(budgets, want) {
		t.Fatalf("entry budgets sent %v, want %v: one budget across the selection, and nothing walked once it is spent", budgets, want)
	}
	if transferScanMaxEntries != 500_000 {
		t.Fatalf("transferScanMaxEntries = %d, want the contract's 500,000", transferScanMaxEntries)
	}
	sum := env.Confirm.Summary
	if sum.Files != transferScanMaxEntries || sum.Bytes != transferScanMaxEntries {
		t.Fatalf("summary %+v, want what the budget measured", sum)
	}
	if !hasWarning(env, noticeSizeMinimum) {
		t.Fatalf("warnings %q, want the totals marked a minimum", sum.Warnings)
	}
	var crossings []string
	for _, w := range sum.Warnings {
		if strings.Contains(w, crossDeviceMark) {
			crossings = append(crossings, w)
		}
	}
	if len(crossings) != 2 || !strings.HasPrefix(crossings[0], "a and ") || !strings.Contains(crossings[0], transferBytes(holds)) ||
		!strings.HasPrefix(crossings[1], "c and ") || !strings.Contains(crossings[1], transferBytes(-1)) {
		t.Fatalf("crossings %q, want a's measured size and c's unknown one", crossings)
	}
	asked := strings.Join(fj.fsidPaths, " ")
	for _, root := range []string{"/real/a", "/real/b", "/real/c"} {
		if !strings.Contains(asked, root) {
			t.Fatalf("FSIdentity asked about %q, want every root including %s", fj.fsidPaths, root)
		}
	}
	j := acceptedJob(t, post(s, "/api/jobs/move", c, csrf, withToken(body, env.Confirm.Token)))
	awaitTerminal(t, s, j.ID)
}

// TestPreflightsWithNoBudgetLeftStillAnswer: a request that arrives with less
// than permScanReserve to live measures nothing at all — no walk is started
// that could not finish, and no stat is made — and still gets its confirmation,
// whose re-post is accepted. With the route's whole budget the same selection
// is measured.
func TestPreflightsWithNoBudgetLeftStillAnswer(t *testing.T) {
	short := permScanReserve / 2

	t.Run("copy", func(t *testing.T) {
		s, b, sj := scaleFixture(t)
		paths := scaleFiles(t, s, b, "/sel", 150)
		env := confirmAtScale(t, s, scaleOps[0], "files with no budget", paths, short)
		if n := countSizeJobs(sj.fakeJobs); n != 0 {
			t.Fatalf("%d walks started with no budget to finish them in", n)
		}
		if sum := env.Confirm.Summary; sum.Files != 0 || !hasWarning(env, noticeSizeMinimum) {
			t.Fatalf("summary %+v, want nothing counted and the totals marked a minimum", sum)
		}
	})

	t.Run("delete", func(t *testing.T) {
		s, b, _ := scaleFixture(t)
		mkAPIFile(t, b, "/del/a", strings.Repeat("a", 10))
		mkAPIFile(t, b, "/del/b", strings.Repeat("b", 20))
		paths := []string{"/del/a", "/del/b"}
		env := confirmAtScale(t, s, scaleOps[2], "files with the whole budget", paths, 0)
		if sum := env.Confirm.Summary; sum.Files != 2 || sum.Bytes != 30 {
			t.Fatalf("summary %+v, want both roots stated", sum)
		}
		mkAPIFile(t, b, "/del/a", strings.Repeat("a", 10))
		mkAPIFile(t, b, "/del/b", strings.Repeat("b", 20))
		env = confirmAtScale(t, s, scaleOps[2], "files with no budget", paths, short)
		if sum := env.Confirm.Summary; sum.Files != 2 || sum.Bytes != 0 {
			t.Fatalf("summary %+v, want the roots counted and no stat made", sum)
		}
	})
}
