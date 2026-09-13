package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

func transferFixture(t *testing.T) (*Server, *fakeJobs) {
	t.Helper()
	s, b, fj := jobsFixture(t, jobs.Limits{})
	s.mutator = &resolveStub{fakeBackend: b, aliases: map[string]string{
		"/":    "/",
		"/src": "/real", "/dest": "/target", "/other": "/elsewhere",
		"/etc/config": "/normal", "/warn": "/etc/config", "/bad": "/proc",
		"/inside": "/real/folder/child", "/src/folder/child": "/outside",
		"/same": "/real", "/secret": "/app/logs",
	}}
	return s, fj
}

func transferBody(src, dst, conflict string, cross bool) string {
	return fmt.Sprintf(`{"paths":[{"path":%q}],"dest":{"path":%q},"conflict":%q,"crossMounts":%t}`, src, dst, conflict, cross)
}

func TestTransferContainedDenials(t *testing.T) {
	const install = "/share/CACHEDEV1_DATA/.qpkg/QNAPFileManager"
	for _, mode := range []string{"copy", "move"} {
		for _, tc := range []struct{ name, src, dst, alias, target string }{
			{"firmware source requested", "/etc", "/dest", "/", "/ordinary"},
			{"firmware source resolved", "/alias/etc", "/dest", "/alias", "/"},
			{"source requested", "/share/CACHEDEV1_DATA/.qpkg", "/dest", "/share/CACHEDEV1_DATA", "/ordinary"},
			{"source resolved", "/alias/.qpkg", "/dest", "/alias", "/share/CACHEDEV1_DATA"},
			{"installation source", install, "/dest", "/share/CACHEDEV1_DATA/.qpkg", "/share/CACHEDEV1_DATA/.qpkg"},
			{"destination requested", "/src/.qpkg", "/share/CACHEDEV1_DATA", "/share/CACHEDEV1_DATA", "/ordinary"},
			{"destination resolved", "/src/.qpkg", "/volume", "/volume", "/share/CACHEDEV1_DATA"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				s, fj := transferFixture(t)
				s.guard = guard.New(install, false)
				s.mutator.(*resolveStub).aliases[tc.alias] = tc.target
				c, csrf := sessionCookie(t, s)
				resp := post(s, "/api/jobs/"+mode, c, csrf, transferBody(tc.src, tc.dst, "skip", false))
				raw := readBody(resp)
				if resp.StatusCode != http.StatusForbidden || !strings.Contains(raw, `"code":"protected"`) {
					t.Fatalf("%d %s", resp.StatusCode, raw)
				}
				if strings.Contains(raw, install+"/config") || strings.Contains(raw, install+"/logs") {
					t.Fatalf("contained path disclosed: %s", raw)
				}
				if len(fj.requests()) != 0 {
					t.Fatal("contained denial measured or dispatched")
				}
			})
		}
	}
}

func TestTransferContainedWarning(t *testing.T) {
	for _, mode := range []string{"copy", "move"} {
		for _, spelling := range []string{"requested", "resolved"} {
			t.Run(mode+"/"+spelling, func(t *testing.T) {
				s, fj := transferFixture(t)
				s.guard = guard.New("", false)
				prefix := "/dest/folder/config"
				if spelling == "resolved" {
					prefix = "/target/folder/config"
				}
				// Seed a warning-only canonical prefix through the startup seam.
				// The first lookup duplicates the firmware warning; the subsequent
				// exact-delete lookup fails, leaving that denial at its lexical path.
				// This isolates warning containment from exact-directory refusal.
				mapped := false
				s.guard.CanonicalizeRoots(func(p string) (string, bool) {
					if p == "/etc/config" && !mapped {
						mapped = true
						return prefix, true
					}
					return "", false
				})
				c, csrf := sessionCookie(t, s)
				body := transferBody("/src/folder", "/dest", "overwrite", false)
				env := challenge(t, s, c, csrf, "/api/jobs/"+mode, body)
				want := []string{"QTS firmware configuration", noticeOverwrite}
				if !reflect.DeepEqual(env.Confirm.Summary.Warnings, want) {
					t.Fatalf("warnings = %q, want %q", env.Confirm.Summary.Warnings, want)
				}
				switch env.Confirm.Summary.Warnings[0] {
				case noticeSizeMinimum, noticeSizeOverflow, noticeCrossUnknown, noticeOverwrite:
					t.Fatal("contained guard warning grades as a route notice")
				}
				j := acceptedJob(t, post(s, "/api/jobs/"+mode, c, csrf, withToken(body, env.Confirm.Token)))
				awaitTerminal(t, s, j.ID)
				transferRequest(t, fj, j.ID)
			})
		}
	}
}

func TestTransferOrdinaryShareHasNoContainmentWarnings(t *testing.T) {
	for _, mode := range []string{"copy", "move"} {
		s, _ := transferFixture(t)
		s.mutator.(*resolveStub).aliases["/share/Public"] = "/share/Public"
		c, csrf := sessionCookie(t, s)
		body := transferBody("/src/folder", "/share/Public", "skip", false)
		j := acceptedJob(t, post(s, "/api/jobs/"+mode, c, csrf, body))
		awaitTerminal(t, s, j.ID)
		body = transferBody("/src/folder", "/share/Public", "overwrite", false)
		env := challenge(t, s, c, csrf, "/api/jobs/"+mode, body)
		if !reflect.DeepEqual(env.Confirm.Summary.Warnings, []string{noticeOverwrite}) {
			t.Fatalf("ordinary share gained guard warnings: %q", env.Confirm.Summary.Warnings)
		}
	}
}

func transferRequest(t *testing.T, fj *fakeJobs, id string) wproto.CopyReq {
	t.Helper()
	for _, req := range fj.requests() {
		if req.JobID == id {
			var cp wproto.CopyReq
			if err := json.Unmarshal(req.Body, &cp); err != nil {
				t.Fatal(err)
			}
			return cp
		}
	}
	t.Fatal("no transfer request")
	return wproto.CopyReq{}
}

func TestTransferDispatchAndOwnership(t *testing.T) {
	for _, mode := range []string{"copy", "move"} {
		for _, root := range []bool{false, true} {
			for _, dest := range []string{"/dest", "/etc/config", "/warn"} {
				t.Run(fmt.Sprintf("%s/root=%t/%s", mode, root, dest), func(t *testing.T) {
					s, fj := transferFixture(t)
					c, csrf := sessionCookie(t, s)
					s.sessions[c.Value].who.Root = root
					body := transferBody("/src/file", dest, "rename", true)
					if dest != "/dest" {
						env := challenge(t, s, c, csrf, "/api/jobs/"+mode, body)
						body = withToken(body, env.Confirm.Token)
					}
					j := acceptedJob(t, post(s, "/api/jobs/"+mode, c, csrf, body))
					awaitTerminal(t, s, j.ID)
					cp := transferRequest(t, fj, j.ID)
					wantDest := map[string]string{"/dest": "/target", "/etc/config": "/normal", "/warn": "/etc/config"}[dest]
					if len(cp.Src) != 1 || string(cp.Src[0]) != "/real/file" || string(cp.DstDir) != wantDest || cp.Opts.Conflict != "rename" || !cp.Opts.CrossMounts || !cp.Opts.PreserveTimes {
						t.Fatalf("request %+v", cp)
					}
					wantAs := mode == "copy" && root && dest == "/dest"
					if (cp.Opts.As != nil) != wantAs {
						t.Fatalf("As = %+v, want set %t", cp.Opts.As, wantAs)
					}
					if wantAs && (cp.Opts.As.UID != 1000 || cp.Opts.As.GID != -1 || cp.Opts.As.Mode != 0) {
						t.Fatalf("As %+v", cp.Opts.As)
					}
					if j.Kind != jobs.Kind(mode) || j.Title != transferTitle(mode, []string{"/src/file"}, dest) || j.Dst != dest || j.Actor != "dev" || j.UID != 1000 {
						t.Fatalf("job %+v", j)
					}
					resp := request(s, "GET", "/api/jobs", c, nil)
					if resp.Code != 200 || !strings.Contains(resp.Body.String(), `"kind":"`+mode+`"`) || !strings.Contains(resp.Body.String(), j.Title) {
						t.Fatal(resp.Body.String())
					}
				})
			}
		}
	}
}

func TestTransferRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, mode, src, dst, conflict, code string
		status                               int
	}{
		{"conflict", "copy", "/src/file", "/dest", "invalid", "bad_request", 422},
		{"resolved inside", "copy", "/src/folder", "/inside", "", "invalid_target", 409},
		{"requested inside", "move", "/src/folder", "/src/folder/child", "", "invalid_target", 409},
		{"equal", "copy", "/src", "/src", "", "invalid_target", 409},
		{"same skip", "move", "/src/file", "/src", "skip", "exists", 409},
		{"same overwrite", "move", "/src/file", "/same", "overwrite", "exists", 409},
		{"resolved protected", "copy", "/src/file", "/bad", "", "protected", 403},
		{"requested protected", "copy", "/src/file", "/proc", "", "protected", 403},
		{"source protected", "move", "/bad/file", "/dest", "", "protected", 403},
		{"source read denied", "copy", "/secret/file", "/dest", "", "protected", 403},
		{"child protected", "copy", "/src/.zfs", "/dest", "", "protected", 403},
		{"overwrite delete denied", "copy", "/src/file", "/dev", "overwrite", "protected", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fj := transferFixture(t)
			rs := s.mutator.(*resolveStub)
			rs.aliases["/proc"], rs.aliases["/dev"] = "/normal", "/normal"
			s.guard = guard.New("/app", false)
			c, csrf := sessionCookie(t, s)
			resp := post(s, "/api/jobs/"+tc.mode, c, csrf, transferBody(tc.src, tc.dst, tc.conflict, false))
			body := readBody(resp)
			if resp.StatusCode != tc.status || !strings.Contains(body, `"code":"`+tc.code+`"`) {
				t.Fatalf("%d %s", resp.StatusCode, body)
			}
			if len(fj.requests()) != 0 {
				t.Fatal("refused job measured or dispatched")
			}
		})
	}
}

func TestTransferSameDirectoryRenameAndDefaultSkip(t *testing.T) {
	for _, tc := range []struct{ mode, dest, conflict, want string }{
		{"move", "/same", "rename", "rename"}, {"copy", "/dest", "", "skip"},
	} {
		s, fj := transferFixture(t)
		c, csrf := sessionCookie(t, s)
		j := acceptedJob(t, post(s, "/api/jobs/"+tc.mode, c, csrf, transferBody("/src/file", tc.dest, tc.conflict, false)))
		awaitTerminal(t, s, j.ID)
		if cp := transferRequest(t, fj, j.ID); cp.Opts.Conflict != tc.want {
			t.Fatal(cp)
		}
	}
}

func TestTransferPreflightSummary(t *testing.T) {
	for _, tc := range []struct {
		name            string
		files, bytes    int64
		dirs            int64
		different, fail bool
		confirm         bool
	}{
		{"equal", 3, 30, 0, false, false, false},
		{"different", 3, 2 << 30, 0, true, false, true},
		{"identity error", 3, 30, 0, false, true, true},
		{"file boundary", 100, 30, 0, false, false, false},
		{"file threshold", 101, 30, 0, false, false, true},
		{"byte boundary", 1, 1 << 30, 0, false, false, false},
		{"byte threshold", 1, (1 << 30) + 1, 0, false, false, true},
		{"directories count as items", 0, 30, 102, false, false, true},
		{"directories under the boundary", 50, 30, 50, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, fj := transferFixture(t)
			fj.result = wproto.JobResult{Files: tc.files, Dirs: tc.dirs, Bytes: tc.bytes}
			if tc.different {
				fj.fsid = map[string]wproto.FSIdentityResp{"/real/file": {Dev: 2}}
			}
			if tc.fail {
				fj.fsidErr = fmt.Errorf("private resolved path: %w", os.ErrPermission)
			}
			c, csrf := sessionCookie(t, s)
			body := transferBody("/src/file", "/dest", "skip", false)
			if tc.confirm {
				env := challenge(t, s, c, csrf, "/api/jobs/move", body)
				if env.Confirm.Summary.Files != tc.files+tc.dirs || env.Confirm.Summary.Bytes != tc.bytes {
					t.Fatal(env)
				}
				warnings := strings.Join(env.Confirm.Summary.Warnings, " ")
				if strings.Contains(warnings, "different volumes") != tc.different || strings.Contains(warnings, "could not tell") != tc.fail || strings.Contains(warnings, "/real") || strings.Contains(warnings, "private") {
					t.Fatal(warnings)
				}
				if tc.different && (!strings.Contains(warnings, "file and dest") || !strings.Contains(warnings, "2.0 GiB") || !strings.Contains(warnings, "leaves both copies")) {
					t.Fatal(warnings)
				}
				body = withToken(body, env.Confirm.Token)
			}
			j := acceptedJob(t, post(s, "/api/jobs/move", c, csrf, body))
			awaitTerminal(t, s, j.ID)
		})
	}
}

func TestTransferTokens(t *testing.T) {
	s, _ := transferFixture(t)
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/src/z"},{"path":"/src/a"}],"dest":{"path":"/dest"},"conflict":"overwrite"}`
	env := challenge(t, s, c, csrf, "/api/jobs/copy", body)
	parts := []string{"job=copy", "conflict=overwrite", "cross=false", "dest=/target", "/real/a", "/real/z"}
	if got := transferJobTokenParts("copy", "overwrite", false, "/target", []string{"/real/z", "/real/a"}); !reflect.DeepEqual(got, parts) {
		t.Fatal(got)
	}
	if s.guard.Redeem(env.Confirm.Token, "copy", parts, false) == nil {
		t.Fatal("unordered redemption accepted")
	}
	if s.guard.Redeem(env.Confirm.Token, "copy", parts, true) != nil {
		t.Fatal("ordered redemption refused")
	}
	for _, change := range []string{"mode", "conflict", "cross", "dest", "source"} {
		env = challenge(t, s, c, csrf, "/api/jobs/copy", body)
		changed, route := body, "/api/jobs/copy"
		switch change {
		case "mode":
			route = "/api/jobs/move"
		case "conflict":
			changed = strings.Replace(body, "overwrite", "rename", 1)
		case "cross":
			changed = strings.TrimSuffix(body, "}") + `,"crossMounts":true}`
		case "dest":
			changed = strings.Replace(body, `"/dest"`, `"/other"`, 1)
		case "source":
			changed = strings.Replace(body, `"/src/z"`, `"/src/b"`, 1)
		}
		challenge(t, s, c, csrf, route, withToken(changed, env.Confirm.Token))
	}
	env = challenge(t, s, c, csrf, "/api/jobs/copy", body)
	reordered := strings.Replace(body, `{"path":"/src/z"},{"path":"/src/a"}`, `{"path":"/src/a"},{"path":"/src/z"}`, 1)
	j := acceptedJob(t, post(s, "/api/jobs/copy", c, csrf, withToken(reordered, env.Confirm.Token)))
	awaitTerminal(t, s, j.ID)
	challenge(t, s, c, csrf, "/api/jobs/copy", withToken(body, env.Confirm.Token))
	if j.Title != "Copying 2 items to dest" {
		t.Fatal(j.Title)
	}
}

func TestTransferAuditAndReadOnly(t *testing.T) {
	for _, mode := range []string{"copy", "move"} {
		t.Run(mode, func(t *testing.T) {
			s, fj := transferFixture(t)
			readAudit := withAudit(t, s)
			fj.result.Files = 100
			c, csrf := sessionCookie(t, s)
			body := transferBody("/src/file", "/dest", "skip", false)
			s.guard.SetReadOnly(true)
			resp := post(s, "/api/jobs/"+mode, c, csrf, body)
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(readBody(resp), "read_only") {
				t.Fatal("read-only not refused")
			}
			if len(fj.requests()) != 0 {
				t.Fatal("read-only measured or dispatched")
			}
			s.guard.SetReadOnly(false)
			j := acceptedJob(t, post(s, "/api/jobs/"+mode, c, csrf, body))
			awaitTerminal(t, s, j.ID)
			intent, result := 0, 0
			for _, ev := range readAudit() {
				if !strings.Contains(ev.Detail, "job "+j.ID) {
					continue
				}
				if ev.Op != mode || ev.Path != "/src/file" || !strings.Contains(ev.Detail, mode+" to /dest") || strings.Contains(ev.Detail, "/real") {
					t.Fatal(ev)
				}
				if ev.Phase == "intent" {
					intent++
					if ev.Dst != "/dest" || ev.Files != 100 {
						t.Fatal(ev)
					}
				}
				if ev.Phase == "result" {
					result++
					if ev.Job != j.ID || ev.Result != "ok" {
						t.Fatal(ev)
					}
				}
			}
			if intent != 1 || result != 1 {
				t.Fatalf("intent=%d result=%d", intent, result)
			}
		})
	}
}

func TestTransferResolveFailureAndMethods(t *testing.T) {
	for _, mode := range []string{"copy", "move"} {
		s, fj := transferFixture(t)
		s.mutator.(*resolveStub).blocked = "/blocked"
		c, csrf := sessionCookie(t, s)
		for _, body := range []string{
			transferBody("/blocked/file", "/dest", "", false),
			transferBody("/src/file", "/blocked", "", false),
			`{"paths":[{"path":"/src/file"},{"path":"/blocked/file"}],"dest":{"path":"/dest"}}`,
		} {
			resp := post(s, "/api/jobs/"+mode, c, csrf, body)
			if resp.StatusCode != 403 {
				t.Fatalf("%d %s", resp.StatusCode, readBody(resp))
			}
		}
		if len(fj.requests()) != 0 {
			t.Fatal("partial selection dispatched")
		}
		resp := request(s, "GET", "/api/jobs/"+mode, c, nil)
		if resp.Code != 405 || resp.Header().Get("Allow") != "POST" {
			t.Fatal(resp.Code)
		}
	}
}

func TestTransferQueuedGuardAndAudit(t *testing.T) {
	for _, cancelQueued := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelQueued), func(t *testing.T) {
			s, fj := transferFixture(t)
			read := withAudit(t, s)
			// Occupy both byte-mover slots without blocking the size pre-flight.
			started := make(chan struct{}, 2)
			release := make(chan struct{})
			for i := 0; i < 2; i++ {
				_, err := s.jobMgr.Submit(jobs.KindCopy, "blocker", jobs.Meta{}, func(ctx context.Context, _ *jobs.Progress) (any, error) {
					started <- struct{}{}
					select {
					case <-release:
						return nil, nil
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 2; i++ {
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("blocker did not start")
				}
			}
			c, csrf := sessionCookie(t, s)
			j := acceptedJob(t, post(s, "/api/jobs/move", c, csrf, transferBody("/src/file", "/dest", "skip", false)))
			awaitState(t, s, j.ID, jobs.StateQueued)
			if cancelQueued {
				s.jobMgr.Cancel(j.ID)
			} else {
				s.guard.SetReadOnly(true)
			}
			close(release)
			final := awaitTerminal(t, s, j.ID)
			if cancelQueued {
				if final.State != jobs.StateCancelled {
					t.Fatal(final)
				}
			} else if final.State != jobs.StateFailed || final.ErrCode != "read_only" {
				t.Fatal(final)
			}
			for _, req := range fj.requests() {
				if req.JobID == j.ID {
					t.Fatal("queued job dispatched")
				}
			}
			if events := eventsFor(read(), j.ID); len(events) != 1 {
				t.Fatalf("result events %+v", events)
			}
		})
	}
}

func TestTransferMapsProgressAndWarnings(t *testing.T) {
	s, fj := transferFixture(t)
	fj.prog = []wproto.Prog{{Current: []byte("/target/file"), Files: 1, Bytes: 30}}
	fj.warns = []wproto.Warn{{Path: []byte("/real/file"), Code: "permission", Message: "secret raw text"}, {Path: []byte("/target/file"), Code: "exists", Message: "secret raw text"}}
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/copy", c, csrf, transferBody("/src/file", "/dest", "skip", false)))
	final := awaitTerminal(t, s, j.ID)
	warnings := strings.Join(final.Warnings, " ")
	if final.Current != "/dest/file" || !strings.Contains(warnings, "/src/file") || !strings.Contains(warnings, "/dest/file") || strings.Contains(warnings, "/real") || strings.Contains(warnings, "/target") || strings.Contains(warnings, "secret") {
		t.Fatalf("job %+v", final)
	}
}

func TestTransferMultipleRootPredictionAndMeasurement(t *testing.T) {
	s, fj := transferFixture(t)
	fj.fsid = map[string]wproto.FSIdentityResp{"/real/a": {Dev: 2}, "/real/b": {Dev: 3}}
	c, csrf := sessionCookie(t, s)
	body := `{"paths":[{"path":"/src/a"},{"path":"/src/b"}],"dest":{"path":"/dest"},"crossMounts":true}`
	env := challenge(t, s, c, csrf, "/api/jobs/move", body)
	if env.Confirm.Summary.Files != 6 || env.Confirm.Summary.Bytes != 60 || len(env.Confirm.Summary.Warnings) != 2 {
		t.Fatal(env)
	}
	for i, req := range fj.requests() {
		var size wproto.SizeReq
		if err := json.Unmarshal(req.Body, &size); err != nil {
			t.Fatal(err)
		}
		if req.Kind != wproto.JobSize || len(size.Paths) != 1 || string(size.Paths[0]) != []string{"/real/a", "/real/b"}[i] || !size.CrossMounts {
			t.Fatal(req, size)
		}
	}
}

func TestTransferIncompleteMeasurementWarns(t *testing.T) {
	s, fj := transferFixture(t)
	fj.err = os.ErrPermission
	c, csrf := sessionCookie(t, s)
	body := transferBody("/src/file", "/dest", "skip", false)
	env := challenge(t, s, c, csrf, "/api/jobs/copy", body)
	if !strings.Contains(strings.Join(env.Confirm.Summary.Warnings, " "), "minimum") {
		t.Fatal(env)
	}
	// The measurement is advisory; the worker still gets a confirmed transfer.
	j := acceptedJob(t, post(s, "/api/jobs/copy", c, csrf, withToken(body, env.Confirm.Token)))
	awaitTerminal(t, s, j.ID)
	transferRequest(t, fj, j.ID)
}
