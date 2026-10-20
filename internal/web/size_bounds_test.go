package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

// Stabilization contract §2.1–§2.3 at the size route: a measurement carries its
// bounds, its result says when it stopped at one, and a cancelled measurement
// keeps its concurrency slot until its walk has stopped.

// TestJobSizeSendsItsBounds: every measurement POST /api/jobs/size starts goes
// to the worker with the contract's two bounds, ten million entries and six
// hundred seconds, whatever the client asked for.
func TestJobSizeSendsItsBounds(t *testing.T) {
	for _, body := range []string{
		`{"paths":[{"path":"/"}]}`,
		`{"paths":[{"path":"/"}],"crossMounts":true,"readCross":true}`,
	} {
		s, _, fj := jobsFixture(t, jobs.Limits{})
		c, csrf := sessionCookie(t, s)
		job := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, body))
		awaitTerminal(t, s, job.ID)
		reqs := fj.requests()
		if len(reqs) != 1 {
			t.Fatalf("%s: %d worker requests, want 1", body, len(reqs))
		}
		var req wproto.SizeReq
		if err := json.Unmarshal(reqs[0].Body, &req); err != nil {
			t.Fatal(err)
		}
		if req.MaxEntries != 10_000_000 || req.MaxDuration != 600 {
			t.Fatalf("%s: size request %+v, want MaxEntries 10,000,000 and MaxDuration 600 s", body, req)
		}
		if sizeJobMaxEntries != 10_000_000 || sizeJobMaxDuration != 10*time.Minute {
			t.Fatalf("the named bounds drifted from the contract: %d entries, %v", sizeJobMaxEntries, sizeJobMaxDuration)
		}
	}
}

// uiJobView is a job as the dialog reads it (props.js sizeReport): the state,
// and the result's own capped flag — a pointer, so "absent" and "false" differ.
type uiJobView struct {
	Job struct {
		State  string `json:"state"`
		Result struct {
			Capped *bool `json:"capped"`
		} `json:"result"`
	} `json:"job"`
}

// TestABoundedMeasurementEndsDoneAndCapped is the outcome the UI depends on
// (§2.1, §2.2, §3.8), read off the wire the way props.js reads it: a
// measurement that stopped at either bound is job.state "done" with
// job.result.capped === true — not "failed", which shows an error, and not
// "cancelled", which shows no figure — because "At least …" is rendered for
// exactly that pair. A user's cancel stays "cancelled" and claims no bound.
//
// The worker answers both bounds the same way, an OK terminal frame with
// Capped set and its "capped" warning folded in (TestJobSizeStopsAtItsTimeBound
// and TestJobSizeAnswersCappedAtItsBound in internal/worker drive each bound
// through a real worker session), so the two bound rows feed the route that
// answer with the counts each would plausibly carry.
func TestABoundedMeasurementEndsDoneAndCapped(t *testing.T) {
	cappedWarn := wproto.Warn{Code: "capped", Message: "the scan stopped at its limit, so these totals are a floor and not the whole tree"}
	for _, tc := range []struct {
		name   string
		res    wproto.JobResult
		cancel bool
		state  jobs.State
		capped bool
	}{
		{name: "the entry bound",
			res:   wproto.JobResult{Files: 9_990_000, Dirs: 10_000, Bytes: 1 << 40, Capped: true, Warnings: 1, Warns: []wproto.Warn{cappedWarn}},
			state: jobs.StateDone, capped: true},
		{name: "the time bound",
			res:   wproto.JobResult{Files: 81_234, Dirs: 5_678, Bytes: 9 << 30, Capped: true, Warnings: 1, Warns: []wproto.Warn{cappedWarn}},
			state: jobs.StateDone, capped: true},
		{name: "a user's cancel", cancel: true, state: jobs.StateCancelled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, fj := jobsFixture(t, jobs.Limits{})
			fj.result = tc.res
			if tc.res.Capped {
				fj.warns = []wproto.Warn{cappedWarn} // the frame, beside the folded copy
			}
			if tc.cancel {
				fj.block, fj.started = make(chan struct{}), make(chan struct{})
				fj.partial = wproto.JobResult{Files: 40, Cancelled: true}
			}
			c, csrf := sessionCookie(t, s)
			job := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}]}`))
			if tc.cancel {
				select {
				case <-fj.started:
				case <-time.After(5 * time.Second):
					t.Fatal("the measurement never started")
				}
				if resp := post(s, "/api/jobs/"+job.ID+"/cancel", c, csrf, `{}`); resp.StatusCode != http.StatusOK {
					t.Fatalf("cancel: %d %s", resp.StatusCode, readBody(resp))
				}
			}
			awaitTerminal(t, s, job.ID)

			for _, route := range []string{"/api/jobs/" + job.ID, "/api/jobs"} {
				w := request(s, "GET", route, c, nil)
				if w.Code != http.StatusOK {
					t.Fatalf("GET %s: %d %s", route, w.Code, w.Body)
				}
				var got uiJobView
				if route == "/api/jobs" {
					var list struct {
						Jobs []json.RawMessage `json:"jobs"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Jobs) != 1 {
						t.Fatalf("GET %s: %v %s", route, err, w.Body)
					}
					if err := json.Unmarshal([]byte(`{"job":`+string(list.Jobs[0])+`}`), &got); err != nil {
						t.Fatal(err)
					}
				} else if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				if got.Job.State != string(tc.state) {
					t.Fatalf("GET %s: state %q, want %q: %s", route, got.Job.State, tc.state, w.Body)
				}
				isCapped := got.Job.Result.Capped != nil && *got.Job.Result.Capped
				if isCapped != tc.capped {
					t.Fatalf("GET %s: result.capped = %v, want %v: %s", route, isCapped, tc.capped, w.Body)
				}
				if !tc.capped && got.Job.Result.Capped != nil {
					t.Fatalf("GET %s: result.capped is present on a job that reached no bound: %s", route, w.Body)
				}
			}
		})
	}
}

// TestACappedMeasurementSaysSoInItsResult is §2.2: a walk that stopped at its
// bound is a finished job — done, not failed — whose result carries
// "capped":true, on the single-job read and in the list the Operations panel
// polls alike. A measurement that reached the end of its tree says nothing.
func TestACappedMeasurementSaysSoInItsResult(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{})
	c, csrf := sessionCookie(t, s)

	fj.result = wproto.JobResult{Files: 9_999_000, Dirs: 1000, Bytes: 1 << 40, Capped: true, Warnings: 1}
	capped := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}]}`))
	final := awaitTerminal(t, s, capped.ID)
	if final.State != jobs.StateDone {
		t.Fatalf("a capped measurement is %s, want done: reaching a bound is not a failure", final.State)
	}
	var view jobResultView
	if err := json.Unmarshal(final.Result, &view); err != nil {
		t.Fatal(err)
	}
	if !view.Capped || view.Files != 9_999_000 || view.Dirs != 1000 {
		t.Fatalf("result %+v, want the floor marked capped", view)
	}
	one := request(s, "GET", "/api/jobs/"+capped.ID, c, nil)
	if one.Code != http.StatusOK || !strings.Contains(one.Body.String(), `"capped":true`) {
		t.Fatalf("GET /api/jobs/<id>: %d %s", one.Code, one.Body)
	}
	list := request(s, "GET", "/api/jobs", c, nil)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"capped":true`) {
		t.Fatalf("GET /api/jobs: %d %s", list.Code, list.Body)
	}

	fj.mu.Lock()
	fj.result = wproto.JobResult{Files: 3, Bytes: 30}
	fj.mu.Unlock()
	whole := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}]}`))
	final = awaitTerminal(t, s, whole.ID)
	if strings.Contains(string(final.Result), "capped") {
		t.Fatalf("an uncapped measurement mentions capped: %s", final.Result)
	}

	// The list's hit-free spelling keeps the flag too: it is a fact about the
	// counts, not about the hits it exists to leave out.
	trimmed := jobResultView{Hits: []fsx.Entry{{Name: "x"}}, Files: 1, Capped: true}.ForList()
	if !trimmed.Capped || len(trimmed.Hits) != 0 {
		t.Fatalf("ForList = %+v, want the hits gone and capped kept", trimmed)
	}
}

// stubbornSizeJobs is a worker whose walk of "/slow" does not stop the instant
// it is told to: it sees the cancellation and carries on until the test lets
// it finish — a walk in the middle of a long directory read, which is what the
// pool's cancelAndDrain waits for. Every other request is fakeJobs'.
type stubbornSizeJobs struct {
	*fakeJobs
	walking chan struct{} // closed when the walk of /slow starts
	told    chan struct{} // closed when it has seen its cancellation
	finish  chan struct{} // closed by the test to let it end
	once    sync.Once
}

func (j *stubbornSizeJobs) Job(ctx context.Context, who backend.Principal, req wproto.JobReq, onProg func(wproto.Prog), onWarn func(wproto.Warn)) (wproto.JobResult, error) {
	var size wproto.SizeReq
	_ = json.Unmarshal(req.Body, &size)
	if req.Kind != wproto.JobSize || len(size.Paths) != 1 || string(size.Paths[0]) != "/slow" {
		return j.fakeJobs.Job(ctx, who, req, onProg, onWarn)
	}
	j.once.Do(func() { close(j.walking) })
	<-ctx.Done()
	close(j.told)
	<-j.finish
	// What the pool hands back for a cancelled job: the worker's own partial
	// result beside the cancellation.
	return wproto.JobResult{Files: 7, Cancelled: true}, context.Canceled
}

// TestACancelledMeasurementKeepsItsSlotUntilItsWalkStops is §2.3 through the
// routes the UI uses. A size job is cancelled with POST /api/jobs/<id>/cancel,
// the cancellation reaches the walk, and the walk is still on its way out:
// until it has stopped, the metadata slot it holds is not given to anybody — not
// the next measurement, which stays queued, and not an admission.
func TestACancelledMeasurementKeepsItsSlotUntilItsWalkStops(t *testing.T) {
	s, _, fj := jobsFixture(t, jobs.Limits{Metadata: 1})
	sj := &stubbornSizeJobs{fakeJobs: fj, walking: make(chan struct{}), told: make(chan struct{}), finish: make(chan struct{})}
	s.SetJobs(sj, s.jobMgr)
	t.Cleanup(func() {
		select {
		case <-sj.finish:
		default:
			close(sj.finish) // a failed test still lets the manager drain
		}
	})
	c, csrf := sessionCookie(t, s)

	first := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/slow"}]}`))
	select {
	case <-sj.walking:
	case <-time.After(5 * time.Second):
		t.Fatal("the measurement never started walking")
	}
	resp := post(s, "/api/jobs/"+first.ID+"/cancel", c, csrf, `{}`)
	if body := readBody(resp); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("cancel: %d %s", resp.StatusCode, body)
	}
	select {
	case <-sj.told:
	case <-time.After(5 * time.Second):
		t.Fatal("the cancellation never reached the walk")
	}

	next := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, `{"paths":[{"path":"/"}]}`))
	admit, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if release, err := s.jobMgr.Admit(admit, jobs.ClassMetadata); err == nil {
		release()
		t.Fatal("the metadata slot was free while the cancelled walk was still running")
	}
	if j, _ := s.jobMgr.Get(next.ID); j.State != jobs.StateQueued {
		t.Fatalf("the next measurement is %s while the cancelled one still walks, want queued", j.State)
	}
	if j, _ := s.jobMgr.Get(first.ID); j.State != jobs.StateRunning {
		t.Fatalf("the cancelled measurement is %s before its walk stopped, want running", j.State)
	}

	close(sj.finish)
	final := awaitTerminal(t, s, first.ID)
	if final.State != jobs.StateCancelled {
		t.Fatalf("job %+v, want cancelled", final)
	}
	var view jobResultView
	if err := json.Unmarshal(final.Result, &view); err != nil {
		t.Fatal(err)
	}
	if view.Files != 7 || view.Capped {
		t.Fatalf("result %+v, want the partial count, and a cancellation that is not a cap", view)
	}
	if done := awaitTerminal(t, s, next.ID); done.State != jobs.StateDone {
		t.Fatalf("the next measurement ended %s, want done once the slot came back", done.State)
	}
}
