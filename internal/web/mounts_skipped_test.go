package web

// JobResult.MountsSkipped (and MountsNetwork, HiddenSkipped) end to end on the web side (PLAN.md decision 9,
// amended 2026-09-23): the count of mount points a search or a size did not
// enter has to reach the UI, including after a search's hits have been moved
// out of the manager into the retention ledger and spliced back on read.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

func TestSearchMountsSkippedSurvivesTheHitsHandoff(t *testing.T) {
	hit := fsx.Entry{Type: "dir"}
	hit.SetPath([]byte("/real/.qpkg/QKVM"))
	hit.SetName([]byte("QKVM"))
	tests := []struct {
		name string
		hits []fsx.Entry
	}{
		// Hits in the ledger: the single-job read splices them back in front of
		// the summary, and the count must be in the summary it is spliced onto.
		{"with hits", []fsx.Entry{hit}},
		// The case the count exists for: nothing found, and the reason.
		{"without hits", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, fj := transferFixture(t)
			fj.result = wproto.JobResult{Files: 4, MountsSkipped: 3, MountsNetwork: 1, HiddenSkipped: 5, Hits: tc.hits}
			c, csrf := sessionCookie(t, s)
			j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"qkvm","hidden":true,"crossMounts":true}`))
			_, view := awaitSearchView(t, s, j.ID)
			if view.MountsSkipped != 3 || view.MountsNetwork != 1 || view.HiddenSkipped != 5 {
				t.Fatalf("manager's summary: %+v", view)
			}
			one := request(s, "GET", "/api/jobs/"+j.ID, c, nil)
			if one.Code != 200 || !strings.Contains(one.Body.String(), `"mountsSkipped":3`) || !strings.Contains(one.Body.String(), `"mountsNetwork":1`) || !strings.Contains(one.Body.String(), `"hiddenSkipped":5`) {
				t.Fatalf("single job: %d %s", one.Code, one.Body)
			}
			if len(tc.hits) > 0 && !strings.Contains(one.Body.String(), `"hits"`) {
				t.Fatalf("single job lost its hits: %s", one.Body)
			}
			list := request(s, "GET", "/api/jobs", c, nil)
			if list.Code != 200 || !strings.Contains(list.Body.String(), `"mountsSkipped":3`) || !strings.Contains(list.Body.String(), `"mountsNetwork":1`) || !strings.Contains(list.Body.String(), `"hiddenSkipped":5`) {
				t.Fatalf("job list: %d %s", list.Code, list.Body)
			}
		})
	}
}

// TestSizeRouteTakesTheReadRuleOnlyWhenAsked: the measurement's purpose is the
// client's to state (Astra r1 on the QKVM fix). Properties asks for the read
// rule; the Permissions impact estimate predicts a chmod, which keeps the strict
// rule, and must not get it by default. transferSize — what the permissions and
// transfer pre-scans confirm a change with — never sets it.
func TestSizeRouteTakesTheReadRuleOnlyWhenAsked(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"Properties asks", `{"paths":[{"path":"/"}],"crossMounts":true,"readCross":true}`, true},
		{"Permissions impact does not", `{"paths":[{"path":"/"}],"crossMounts":true}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _, fj := jobsFixture(t, jobs.Limits{})
			fj.result = wproto.JobResult{Files: 1, Dirs: 1, MountsSkipped: 2, MountsNetwork: 1}
			c, csrf := sessionCookie(t, s)
			job := acceptedJob(t, post(s, "/api/jobs/size", c, csrf, tc.body))
			final := awaitTerminal(t, s, job.ID)
			var view jobResultView
			if err := json.Unmarshal(final.Result, &view); err != nil {
				t.Fatal(err)
			}
			if view.MountsSkipped != 2 || view.MountsNetwork != 1 {
				t.Fatalf("size result %+v", view)
			}
			var req wproto.SizeReq
			if err := json.Unmarshal(fj.requests()[0].Body, &req); err != nil {
				t.Fatal(err)
			}
			if req.ReadCross != tc.want || !req.CrossMounts {
				t.Fatalf("size route request %+v, want ReadCross=%v", req, tc.want)
			}
		})
	}

	s, _, fj := jobsFixture(t, jobs.Limits{})
	if _, err := s.transferSize(context.Background(), backend.Principal{}, "/", true, 0); err != nil {
		t.Fatalf("transferSize: %v", err)
	}
	var pre wproto.SizeReq
	if err := json.Unmarshal(fj.requests()[0].Body, &pre); err != nil {
		t.Fatal(err)
	}
	if pre.ReadCross {
		t.Fatalf("pre-scan request %+v asked for the read rule", pre)
	}
}
