package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

func TestSearchJobListOmitsHits(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{
		Files: 25, Dirs: 3, Bytes: 4096, Skipped: 2, Warnings: 1,
		Detail: "search limit reached",
		Hits:   []fsx.Entry{{Path: "/real/found.txt", Name: "found.txt", Type: "file"}},
	}
	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"found"}`))
	// Wait for the finish hook, not just the terminal state: it is what moves
	// the hits out of the manager, so j.Result below is the settled value.
	j, _ = awaitSearchView(t, s, j.ID)

	w := request(s, http.MethodGet, "/api/jobs", c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var list struct {
		Jobs []struct {
			ID     string                     `json:"id"`
			Result map[string]json.RawMessage `json:"result"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Jobs) != 1 || list.Jobs[0].ID != j.ID {
		t.Fatalf("list jobs: %+v", list.Jobs)
	}
	listed := list.Jobs[0].Result
	if _, ok := listed["hits"]; ok {
		t.Fatal("list result includes hits")
	}

	// Fetch after LIST to prove that serialising the list left the hits the
	// ledger is holding intact, and that the single-job GET still splices them in.
	w = request(s, http.MethodGet, "/api/jobs/"+j.ID, c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	var single struct {
		Job struct {
			Result map[string]json.RawMessage `json:"result"`
		} `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &single); err != nil {
		t.Fatal(err)
	}
	var hits []fsx.Entry
	if err := json.Unmarshal(single.Job.Result["hits"], &hits); err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Path != "/src/found.txt" {
		t.Fatalf("single-job hits: %+v", hits)
	}
	for key, want := range map[string]string{
		"files": "25", "dirs": "3", "bytes": "4096", "skipped": "2",
		"warnings": "1", "detail": `"search limit reached"`,
	} {
		if string(listed[key]) != want {
			t.Errorf("list result %s = %s, want %s", key, listed[key], want)
		}
	}
	delete(single.Job.Result, "hits")
	if !reflect.DeepEqual(listed, single.Job.Result) {
		t.Errorf("summary differs: list=%s get=%s", listed, single.Job.Result)
	}
	stored, ok := s.jobMgr.Get(j.ID)
	if !ok || !bytes.Equal(stored.Result, j.Result) {
		t.Fatal("list polling changed the stored result")
	}
}

// --- retained search results (round-7 adversarial P1) ------------------------

// searchHits builds hits with long paths, so a handful of results is enough to
// overrun a small retention budget without building megabytes of JSON.
func searchHits(n int) []fsx.Entry {
	hits := make([]fsx.Entry, n)
	for i := range hits {
		// Each component stays inside NAME_MAX, which bodyPath now enforces on
		// the way back through the hit filter; the weight comes from depth.
		name := fmt.Sprintf("%04d-%s.txt", i, strings.Repeat("h", 230))
		hits[i] = fsx.Entry{Name: name, Path: "/real/" + name + "/" + name, Type: "file", Size: 1, Mode: "0644", ModeStr: "-rw-r--r--"}
	}
	return hits
}

// runSearch submits one search and waits until it has finished AND its result
// has been accounted for. OnFinish runs after the state is already terminal, so
// awaitTerminal alone can return before the budget has seen the job.
func runSearch(t *testing.T, s *Server, c *http.Cookie, csrf string) string {
	t.Helper()
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"h"}`))
	awaitSearchView(t, s, j.ID)
	return j.ID
}

// awaitSearchView waits for a search to finish AND for the finish hook to have
// moved its hits into the ledger, then returns the job the manager holds and the
// view a client asking about that one job would be served.
//
// Waiting for the ledger and not just for the terminal state is the point: hits
// live in jobs.Job.Result only from the instant the work function returns until
// OnFinish moves them, and awaitTerminal can return inside that window. A test
// that reads j.Result directly there is reading a value that is about to change.
func awaitSearchView(t *testing.T, s *Server, id string) (jobs.Job, jobResultView) {
	t.Helper()
	awaitTerminal(t, s, id)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.searchRetained.mu.Lock()
		_, ok := s.searchRetained.held[id]
		s.searchRetained.mu.Unlock()
		if ok {
			j, live := s.jobMgr.Get(id)
			if !live {
				t.Fatalf("job %s is gone", id)
			}
			// The ledger takes the hits BEFORE the manager gives them up (round
			// 11), so for an instant both hold them. A test that wants the
			// manager's hit-free summary must wait for the second half too.
			if bytes.Contains(j.Result, hitsKey) {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			return j, servedView(t, s, id)
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("search %s never reached the retention ledger", id)
	return jobs.Job{}, jobResultView{}
}

// storedView decodes what the MANAGER is holding for a job — the summary, with
// no hits at all once the finish hook has run. This is what Manager.List copies
// for every job on every poll, which is why its size is what matters.
func storedView(t *testing.T, s *Server, id string) (jobs.Job, jobResultView) {
	t.Helper()
	j, ok := s.jobMgr.Get(id)
	if !ok {
		t.Fatalf("job %s is gone", id)
	}
	var view jobResultView
	if len(j.Result) > 0 {
		if err := json.Unmarshal(j.Result, &view); err != nil {
			t.Fatal(err)
		}
	}
	return j, view
}

// servedView is what GET /api/jobs/<id> answers: the manager's summary with the
// ledger's hits spliced back in. It also proves the splice produces valid JSON.
func servedView(t *testing.T, s *Server, id string) jobResultView {
	t.Helper()
	j, ok := s.jobMgr.Get(id)
	if !ok {
		t.Fatalf("job %s is gone", id)
	}
	var view jobResultView
	raw, live := s.searchResultOf(j)
	if !live {
		t.Fatalf("job %s is no longer available", id)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatalf("spliced result is not valid JSON: %v: %s", err, raw)
		}
	}
	return view
}

// awaitDropped waits for a job's hits to be released from the ledger. The
// eviction is committed under the ledger's lock and the job's note written
// afterwards, so a test that has seen the newest job accounted for may still be
// a moment early.
func awaitDropped(t *testing.T, s *Server, id string) jobResultView {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if view := servedView(t, s, id); len(view.Hits) == 0 && view.Detail == searchDroppedNote {
			return view
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("job %s kept its hits", id)
	return jobResultView{}
}

// ledgerBytes is what the ledger is holding for one job, and for all of them.
func ledgerBytes(s *Server, id string) (one, total, jobs int) {
	s.searchRetained.mu.Lock()
	defer s.searchRetained.mu.Unlock()
	return len(s.searchRetained.held[id].hits), s.searchRetained.total, len(s.searchRetained.held)
}

// TestSearchListPollNeverCopiesHits is the round-7 second pass: budgeting the
// retained bytes was not enough while the hits lived inside jobs.Job.Result.
// Manager.List copies each job's Result to snapshot it and the list view decoded
// every one of them just to drop the hits, so nine retained searches sitting
// comfortably inside the budget cost tens of megabytes of garbage per poll — and
// a GET has no admission limit, so a browser polling on a timer was enough.
func TestSearchListPollNeverCopiesHits(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: 60, Dirs: 2, Bytes: 4096, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)
	var ids []string
	for range 5 {
		ids = append(ids, runSearch(t, s, c, csrf))
	}

	for _, id := range ids {
		// What the manager holds — and therefore what every poll copies — is a
		// summary, not a payload.
		j, view := storedView(t, s, id)
		if len(j.Result) > 4<<10 {
			t.Fatalf("the manager still holds %d bytes for %s", len(j.Result), id)
		}
		if len(view.Hits) != 0 {
			t.Fatalf("the manager still holds %d hits for %s", len(view.Hits), id)
		}
		if view.Files != 60 || view.Dirs != 2 || view.Bytes != 4096 {
			t.Fatalf("the summary did not survive: %+v", view)
		}
		// The hits are not lost, they moved.
		if one, _, _ := ledgerBytes(s, id); one < 4<<10 {
			t.Fatalf("the ledger holds only %d bytes for %s", one, id)
		}
		if hits := servedView(t, s, id).Hits; len(hits) != 60 {
			t.Fatalf("single-job GET lost the hits: %d", len(hits))
		}
	}

	// The list response is hit-free and carries every job's counts.
	w := request(s, http.MethodGet, "/api/jobs", c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), `"hits"`) {
		t.Fatalf("the list carried hits: %.200s", w.Body)
	}
	var list struct {
		Jobs []struct {
			ID     string                     `json:"id"`
			Result map[string]json.RawMessage `json:"result"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Jobs) != len(ids) {
		t.Fatalf("list has %d jobs, want %d", len(list.Jobs), len(ids))
	}
	for _, j := range list.Jobs {
		if string(j.Result["files"]) != "60" || string(j.Result["bytes"]) != "4096" {
			t.Fatalf("list lost the counts: %s", w.Body)
		}
	}

	// The single-job GET still serves them over HTTP, spliced back in.
	w = request(s, http.MethodGet, "/api/jobs/"+ids[0], c, nil)
	var single struct {
		Job struct {
			Result jobResultView `json:"result"`
		} `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &single); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || len(single.Job.Result.Hits) != 60 || single.Job.Result.Files != 60 {
		t.Fatalf("single GET: %d hits=%d", w.Code, len(single.Job.Result.Hits))
	}
	if single.Job.Result.Hits[0].Path != servedView(t, s, ids[0]).Hits[0].Path {
		t.Fatal("the spliced hits are not the ledger's")
	}

	// Retention still reclaims the hits. Moving them out of jobs.Job took them
	// out of Reap's reach — while they lived inside the job, retention freed
	// them with it — so the ledger has to notice a reaped job for itself.
	// Swapping the manager makes every job so far unreachable, which is what a
	// Reap looks like from here.
	if _, _, held := ledgerBytes(s, ""); held != len(ids) {
		t.Fatalf("ledger holds %d entries before the prune, want %d", held, len(ids))
	}
	s.SetJobs(fj, jobs.New(jobs.Limits{}))
	t.Cleanup(func() { _ = s.jobMgr.Close(context.Background()) })
	runSearch(t, s, c, csrf)
	_, total, held := ledgerBytes(s, "")
	if held != 1 {
		t.Fatalf("the ledger kept %d reaped searches", held)
	}
	if one, _, _ := ledgerBytes(s, ids[0]); one != 0 || total <= 0 {
		t.Fatalf("a reaped job's hits survived: %d bytes, total %d", one, total)
	}
}

// --- bulk result reads (round-11 P1) -----------------------------------------

// bulkFixtureHits makes a result of roughly three megabytes — the size the
// round-11 reproduction used — which is past anything the loopback socket
// buffers will swallow, so a client that does not read really does block the
// handler inside its write. A smaller result is quietly absorbed by the kernel
// and proves nothing.
const bulkFixtureHits = 4000

// bulkFixture is a server holding one search result far bigger than
// bulkResultBytes, plus a real HTTP server to drive it over a socket: a write
// deadline lives on the connection, and a ResponseRecorder has not got one.
func bulkFixture(t *testing.T, cfg func(*Server)) (*Server, *httptest.Server, *http.Cookie, string, string) {
	t.Helper()
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: bulkFixtureHits, Hits: searchHits(bulkFixtureHits)}
	c, csrf := sessionCookie(t, s)
	id := runSearch(t, s, c, csrf)
	one, _, _ := ledgerBytes(s, id)
	if one < bulkResultBytes {
		t.Fatalf("the fixture result is %d bytes, below the %d that needs a slot", one, bulkResultBytes)
	}
	// Every knob and seam the serving goroutines read is set HERE, before the
	// listener exists: the goroutine that will read them is created by Start,
	// so the write is ordered before the read by construction. Setting them
	// after a request is in flight is a data race, and the Linux -race job says
	// so (CI 34758168317).
	if cfg != nil {
		cfg(s)
	}
	server := httptest.NewServer(s.Handler())
	t.Cleanup(server.Close)
	return s, server, c, csrf, id
}

// bulkGet sends GET /api/jobs/<id> on a raw connection and hands the connection
// back for the caller to read (or not).
func bulkGet(t *testing.T, server *httptest.Server, c *http.Cookie, id string) net.Conn {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET /api/jobs/%s HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\n\r\n", id, u.Host, c.String()); err != nil {
		t.Fatal(err)
	}
	return conn
}

// bulkStream sends the request and drains the reply in the background.
//
// Draining is what keeps this test honest on every machine. What holds the
// handler is the admitted seam, deterministically; the socket is deliberately
// NOT part of the mechanism, because how much a kernel will buffer for a client
// that is not reading varies wildly — this box swallowed megabytes whole, and
// the CI runner under -race swallowed nothing, so the same test passed for the
// wrong reason here and hung there.
func bulkStream(t *testing.T, server *httptest.Server, c *http.Cookie, id string) {
	t.Helper()
	conn := bulkGet(t, server, c, id)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(io.Discard, conn)
	}()
	t.Cleanup(func() {
		_ = conn.Close()
		<-drained
	})
}

// awaitBulkSlots waits for the number of admitted bulk reads to settle.
func awaitBulkSlots(t *testing.T, s *Server, want int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.bulkReads.mu.Lock()
		got := s.bulkReads.total
		s.bulkReads.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	s.bulkReads.mu.Lock()
	got := s.bulkReads.total
	s.bulkReads.mu.Unlock()
	t.Fatalf("bulk slots settled at %d, want %d", got, want)
}

// TestBulkResultReadsAreAdmitted is round-11 P1: the retention ledger bounds
// what the daemon HOLDS, and said nothing about what it is in the middle of
// WRITING. One authenticated user could ask for the same large search result
// over and over and never read the replies — each blocked write keeping its own
// complete copy alive, with no WriteTimeout to interrupt it (32 blocked readers
// of one 3.37 MiB result held about 108 MiB).
//
// The slots are held through the admitted seam rather than by relying on a
// client that stops reading. That is not squeamishness: with megabytes in
// flight, tiny buffers set on BOTH ends of the socket and nobody reading, this
// machine's loopback still swallowed the whole response and the handler
// finished — a test written that way passed just as happily with the fix taken
// out again, which is the definition of proving nothing.
func TestBulkResultReadsAreAdmitted(t *testing.T) {
	hold := make(chan struct{})
	s, server, first, _, id := bulkFixture(t, func(s *Server) {
		s.bulkReads.perSessionLimit, s.bulkReads.totalLimit = 1, 2
		s.bulkReads.admitted = func() { <-hold }
	})
	second, _ := sessionCookie(t, s)

	refused := func(c *http.Cookie, want string) {
		t.Helper()
		conn := bulkGet(t, server, c, id)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("no refusal arrived: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusTooManyRequests || !bytes.Contains(body, []byte(`"code":"queue_full"`)) {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("refusal names the wrong ceiling: %s", body)
		}
		// Retry-After and a closed connection, the same shape as the upload
		// admission refusal: a client that retries at once on a kept-alive
		// connection is the behaviour this exists to stop.
		if resp.Header.Get("Retry-After") == "" || !resp.Close {
			t.Fatalf("headers: %v close=%v", resp.Header, resp.Close)
		}
	}

	// One reader holds this session's only slot. It drains its reply, so the
	// only thing keeping the handler there is the seam.
	bulkStream(t, server, first, id)
	awaitBulkSlots(t, s, 1)
	refused(first, "This session is already receiving")

	// Another session takes the last free slot, and is then refused by the
	// process-wide ceiling rather than by its own.
	bulkStream(t, server, second, id)
	awaitBulkSlots(t, s, 2)
	refused(second, "as many large results as it can")

	// A job with no retained hits is an ordinary response and needs no slot, so
	// the rest of the job API keeps working while the big ones are queued.
	w := request(s, http.MethodGet, "/api/jobs", first, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list while saturated: %d %s", w.Code, w.Body)
	}

	// Every slot comes back when the responses finish. The seam stays installed:
	// a closed channel lets every later call straight through, and clearing it
	// here would race the handlers still reading it.
	close(hold)
	awaitBulkSlots(t, s, 0)
}

// TestBulkAdmissionFollowsThePayloadNotTheLedger is round-12 P1. Admission used
// to ask the ledger how many hit bytes it held, which is not the same question
// as how big the response is: a GET landing after a search goes terminal but
// before the finish hook's ledger insert found nothing recorded, skipped the
// slot and the deadline — and then served the hits out of the manager's own copy
// in full. Admission now measures the payload it has actually built.
//
// The window is recreated exactly, without needing to catch it: hits back in the
// manager's copy, ledger holding none for that job.
func TestBulkAdmissionFollowsThePayloadNotTheLedger(t *testing.T) {
	hold := make(chan struct{})
	s, server, c, _, id := bulkFixture(t, func(s *Server) {
		s.bulkReads.perSessionLimit, s.bulkReads.totalLimit = 1, 1
		s.bulkReads.admitted = func() { <-hold }
	})

	// Put the result back the way it looks before the finish hook moves it.
	full := servedView(t, s, id)
	if len(full.Hits) != bulkFixtureHits {
		t.Fatalf("fixture: %d hits", len(full.Hits))
	}
	if _, ok := s.jobMgr.ReplaceResult(id, full); !ok {
		t.Fatal("the fixture job is gone")
	}
	s.searchRetained.mu.Lock()
	s.searchRetained.total -= len(s.searchRetained.held[id].hits)
	s.searchRetained.held[id] = retainedHits{}
	s.searchRetained.mu.Unlock()
	if one, _, _ := ledgerBytes(s, id); one != 0 {
		t.Fatalf("the ledger still holds %d bytes", one)
	}

	// The payload is still megabytes, so it must still be admitted.
	bulkStream(t, server, c, id)
	awaitBulkSlots(t, s, 1)

	conn := bulkGet(t, server, c, id)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no refusal arrived: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || !bytes.Contains(body, []byte(`"code":"queue_full"`)) {
		t.Fatalf("an unbounded response slipped through: %d %.200s", resp.StatusCode, body)
	}
	close(hold)
	awaitBulkSlots(t, s, 0)
}

// TestJobCancelNeverCarriesHits is the round-16 P1. Cancel serialises the whole
// job, and a search's hits are inside jobs.Job.Result from the instant the work
// function returns until the finish hook moves them into the retention ledger.
// A cancel landing in that window shipped every hit — 879 KiB in the
// reproduction — with none of what makes the single-job GET affordable: no bulk
// admission, no write deadline, and no reason for the client to have wanted
// them, since the cancel reply is only ever read for its state.
//
// The window is entered deliberately through the handoff seam, which fires with
// the ledger already holding the hits and the manager not yet let go of them.
func TestJobCancelNeverCarriesHits(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: bulkFixtureHits, Hits: searchHits(bulkFixtureHits)}
	// Both seams are installed before the search that will read them is
	// submitted, so the job goroutine's reads are ordered after these writes by
	// construction. Setting a knob while a request is in flight is a data race
	// and the Linux -race job says so.
	var admitted atomic.Int64
	s.bulkReads.admitted = func() { admitted.Add(1) }
	entered, release := make(chan string, 1), make(chan struct{})
	s.searchRetained.handoff = func(id string) {
		entered <- id
		<-release
	}
	// Registered after the fixture's own cleanups, so it runs BEFORE them
	// (LIFO): the job goroutine is let go before Close waits for it.
	t.Cleanup(func() { close(release) })

	c, csrf := sessionCookie(t, s)
	j := acceptedJob(t, post(s, "/api/jobs/search", c, csrf, `{"roots":[{"path":"/src"}],"query":"h"}`))
	select {
	case id := <-entered:
		if id != j.ID {
			t.Fatalf("the handoff hook saw %s, want %s", id, j.ID)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the handoff hook never ran")
	}
	held, live := s.jobMgr.Get(j.ID)
	if !live || !bytes.Contains(held.Result, hitsKey) {
		t.Fatalf("the manager is not holding hits (live=%t); the window was missed", live)
	}

	resp := post(s, "/api/jobs/"+j.ID+"/cancel", c, csrf, `{}`)
	body := readBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cancel: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(body, `"hits":`) {
		t.Fatalf("the cancel reply carried hits: %d bytes", len(body))
	}
	if len(body) >= bulkResultBytes {
		t.Fatalf("the cancel reply is %d bytes, past the %d that would need a slot", len(body), bulkResultBytes)
	}
	// And it does not pay for one either: GET /api/jobs/<id> is the only route
	// that takes a bulk slot, because it is the only one that serves hits.
	if n := admitted.Load(); n != 0 {
		t.Fatalf("cancel took %d bulk slots", n)
	}
	s.bulkReads.mu.Lock()
	slots := s.bulkReads.total
	s.bulkReads.mu.Unlock()
	if slots != 0 {
		t.Fatalf("%d bulk slots are held after a cancel", slots)
	}

	// The summary still travels, so the panel can say what the search had found.
	var env struct {
		OK  bool `json:"ok"`
		Job struct {
			ID     string        `json:"id"`
			Result jobResultView `json:"result"`
		} `json:"job"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("invalid JSON: %v: %.200s", err, body)
	}
	if env.Job.ID != j.ID || len(env.Job.Result.Hits) != 0 || env.Job.Result.Files != bulkFixtureHits {
		t.Fatalf("cancel body: id=%s %d hits, files=%d", env.Job.ID, len(env.Job.Result.Hits), env.Job.Result.Files)
	}

	// The single-job GET still serves them, in full: it is the route that pays.
	if got := servedView(t, s, j.ID); len(got.Hits) != bulkFixtureHits {
		t.Fatalf("the GET view lost its hits: %d", len(got.Hits))
	}
}

// TestSearchResultCarriesTheEvictionNotice is round-12 P2. jobGet snapshots the
// job, then looks the ledger up. If the eviction lands between the two, the
// snapshot is the pre-eviction summary — hit-free and with no notice — while the
// ledger says the hits are gone and the stored job already carries the notice.
// Returning the snapshot verbatim then describes a search that found nothing.
func TestSearchResultCarriesTheEvictionNotice(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: 60, Dirs: 2, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)
	id := runSearch(t, s, c, csrf)

	// The snapshot a reader would be holding, taken before any eviction.
	stale, ok := s.jobMgr.Get(id)
	if !ok {
		t.Fatal("the job is gone")
	}
	if bytes.Contains(stale.Result, []byte(searchDroppedNote)) {
		t.Fatalf("the snapshot already carries the notice: %s", stale.Result)
	}

	// Now the eviction lands: the ledger releases the hits and the stored job is
	// told to say so. The stale snapshot knows about neither.
	s.searchRetained.mu.Lock()
	s.searchRetained.total -= len(s.searchRetained.held[id].hits)
	s.searchRetained.held[id] = retainedHits{dropped: true}
	s.searchRetained.mu.Unlock()
	s.noteSearchResultDropped(id)

	var view jobResultView
	raw, live := s.searchResultOf(stale)
	if !live {
		t.Fatal("the job went away")
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, raw)
	}
	if len(view.Hits) != 0 || view.Detail != searchDroppedNote {
		t.Fatalf("a stale snapshot lost the notice: %d hits, detail=%q", len(view.Hits), view.Detail)
	}
	// The counts still come from the snapshot; only the loss is added.
	if view.Files != 60 || view.Dirs != 2 {
		t.Fatalf("the counts did not survive: %+v", view)
	}
}

// deadlineWriter records the write deadlines http.ResponseController sets, which
// is the only way to see them: a ResponseRecorder has none, and over a real
// socket this machine's loopback finishes the write before any deadline bites.
type deadlineWriter struct {
	http.ResponseWriter
	set []time.Time
}

func (d *deadlineWriter) SetWriteDeadline(t time.Time) error {
	d.set = append(d.set, t)
	return nil
}

// TestBulkResultWriteDeadlineIsArmedAndCleared is the other half of P1: an
// admitted response that is never read must not pin its slot and its buffers
// for the life of the process. The server sets no WriteTimeout, so without a
// deadline of its own a blocked write is never interrupted.
func TestBulkResultWriteDeadlineIsArmedAndCleared(t *testing.T) {
	s, _, c, _, id := bulkFixture(t, nil)
	sess := s.sessions[c.Value]
	one, _, _ := ledgerBytes(s, id)

	rec := &deadlineWriter{ResponseWriter: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodGet, "/api/jobs/"+id, nil)
	before := time.Now()
	done, ok := s.admitBulkResult(rec, r, sess, one)
	if !ok {
		t.Fatal("a first large read was refused")
	}
	if len(rec.set) != 1 {
		t.Fatalf("write deadlines armed: %v", rec.set)
	}
	// Proportional to the payload, and never less than the base grace.
	armed := rec.set[0].Sub(before)
	want := s.bulkReads.deadlineFor(one)
	if armed < want || armed > want+time.Second {
		t.Fatalf("armed %v for a %d-byte result, want about %v", armed, one, want)
	}
	s.bulkReads.mu.Lock()
	held := s.bulkReads.total
	s.bulkReads.mu.Unlock()
	if held != 1 {
		t.Fatalf("the response was not admitted: %d slots", held)
	}

	done()
	// Cleared on the way out, or the connection carries a stale deadline into
	// whatever request reuses it.
	if len(rec.set) != 2 || !rec.set[1].IsZero() {
		t.Fatalf("deadline not cleared: %v", rec.set)
	}
	awaitBulkSlots(t, s, 0)

	// The sizing rule itself: base grace plus a second per MiB, bounded.
	s.bulkReads.writeGrace = 30 * time.Second
	if got := s.bulkReads.deadlineFor(0); got != 30*time.Second {
		t.Fatalf("deadlineFor(0) = %v", got)
	}
	if got := s.bulkReads.deadlineFor(4 << 20); got != 34*time.Second {
		t.Fatalf("deadlineFor(4MiB) = %v", got)
	}
	if got := s.bulkReads.deadlineFor(1 << 30); got != bulkWriteMax {
		t.Fatalf("deadlineFor(1GiB) = %v, want the %v ceiling", got, bulkWriteMax)
	}
}

// TestSearchEvictionDuringHandoffKeepsTheLossNotice is round-11 P2. A search's
// retainSearchResult gives its hits to the ledger, drops the lock, and only then
// rewrites the manager's copy. In that gap a NEWER search can evict this one and
// write its loss notice — and the rewrite then landed on top, restoring the
// summary computed before the eviction existed. The hits were gone and the job
// read as a search that had simply found nothing: the worst kind of wrong,
// because it looks like an answer.
//
// The handoff seam makes it deterministic: the eviction is performed from
// inside the very window it has to survive.
func TestSearchEvictionDuringHandoffKeepsTheLossNotice(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: 60, Dirs: 2, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)

	// From inside a search's OWN handoff, release its hits under the ledger lock
	// exactly as a newer search's eviction would. Its goroutine then resumes and
	// rewrites the manager's copy — the interleaving the fix has to survive.
	//
	// The seam MARKS but does not write the notice, which is both a real
	// interleaving (the evictor marks under the lock before it writes) and the
	// only way to test this at all: if the seam wrote the notice too, a poll
	// would see that write and pass before the rewrite that overwrites it.
	// Here the only thing that can produce the notice is the second look.
	//
	// Every value crosses to the test goroutine through this channel. A shared
	// counter here was a data race — the seam runs on the job's goroutine, and
	// the ledger's mutex is released before the seam is called, so there is no
	// edge from it back to the test (CI 34758328471).
	handoffs := make(chan string, 4)
	s.searchRetained.handoff = func(id string) {
		s.searchRetained.mu.Lock()
		entry := s.searchRetained.held[id]
		s.searchRetained.total -= len(entry.hits)
		s.searchRetained.held[id] = retainedHits{dropped: true}
		s.searchRetained.mu.Unlock()
		handoffs <- id
	}
	evicted := runSearch(t, s, c, csrf)
	select {
	case got := <-handoffs:
		if got != evicted {
			t.Fatalf("the handoff hook saw %s, want %s", got, evicted)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handoff hook never ran")
	}
	// Receiving above is what orders the seam's read of this field before the
	// write below; the next search is submitted afterwards, so its goroutine is
	// created after the write and sees nil.
	s.searchRetained.handoff = nil

	// The evicted search says its results are gone. Without the second look the
	// rewrite put the pre-eviction summary back and it said nothing at all: no
	// hits, no notice, counts intact — a clean zero-hit search. Polled, because
	// retainSearchResult keeps going after the seam returns; every read goes
	// through the manager and ledger mutexes, which is also what orders it.
	got := awaitDropped(t, s, evicted)
	if len(got.Hits) != 0 || got.Detail != searchDroppedNote {
		t.Fatalf("the loss notice was overwritten: %d hits, detail=%q", len(got.Hits), got.Detail)
	}
	if got.Files != 60 || got.Dirs != 2 {
		t.Fatalf("the counts did not survive: %+v", got)
	}
	// Over HTTP too, which is where a user would have seen the wrong answer.
	w := request(s, http.MethodGet, "/api/jobs/"+evicted, c, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), searchDroppedNote) || strings.Contains(w.Body.String(), `"hits"`) {
		t.Fatalf("GET of the evicted job: %d %.300s", w.Code, w.Body)
	}

	// A search that is NOT evicted mid-handoff keeps its hits: the second look
	// must not turn every handoff into a loss.
	kept := runSearch(t, s, c, csrf)
	if live := servedView(t, s, kept); len(live.Hits) != 60 || live.Detail == searchDroppedNote {
		t.Fatalf("an unevicted search lost its hits: %d hits, detail=%q", len(live.Hits), live.Detail)
	}
}

// TestSearchHitsHandoffIsAtomicForReaders pins the window between the manager
// and the ledger. The handoff used to strip the manager's hits BEFORE the ledger
// had them, so a GET landing in between answered with a finished search, no hits
// and no note — which in the UI is a successful search reporting "0 results" on
// its final fetch. Recording first and releasing second means the two sides
// overlap rather than gap, and a reader always sees one of them.
//
// The race detector needs cgo, which this build does not have, so the coverage
// comes from repetition instead: run with -count=20.
func TestSearchHitsHandoffIsAtomicForReaders(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: 60, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)

	// readAt is the check itself: whatever a reader is served for a finished
	// search, it either has the hits or says where they went.
	readAt := func(id string) string {
		j, live := s.jobMgr.Get(id)
		if !live {
			return ""
		}
		raw, served := s.searchResultOf(j)
		if !served {
			// Reaped between the snapshot and the lookup; a 404 is the honest
			// answer and there is nothing here to check.
			return ""
		}
		var view jobResultView
		if err := json.Unmarshal(raw, &view); err != nil {
			return fmt.Sprintf("job %s served invalid JSON: %v: %.200s", id, err, raw)
		}
		if len(view.Hits) == 0 && view.Detail == "" {
			return fmt.Sprintf("job %s served no hits and no note: %.200s", id, raw)
		}
		// And never both copies at once: splicing the ledger's hits into a
		// result that still carries its own would write the key twice, and the
		// last one would win silently.
		if n := bytes.Count(raw, hitsKey); n > 1 {
			return fmt.Sprintf("job %s served %d hits keys", id, n)
		}
		return ""
	}

	// Deterministic half. A concurrent reader will not reliably land in a window
	// a few instructions wide — hammering this for twenty runs did not catch the
	// old order even once — so the read is made FROM inside the window instead.
	//
	// The seam's verdict crosses to this goroutine through a channel and nothing
	// else. Sharing a variable with it was a data race: the seam runs on the
	// job's own goroutine, and the ledger's mutex is released before the seam is
	// called, so nothing orders its writes against this goroutine's reads — the
	// Linux -race job caught exactly that (CI 34758328471).
	verdicts := make(chan string, 4)
	s.searchRetained.handoff = func(id string) { verdicts <- readAt(id) }
	id := runSearch(t, s, c, csrf)
	select {
	case duringHandoff := <-verdicts:
		if duringHandoff != "" {
			t.Fatal(duringHandoff)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handoff hook never ran")
	}
	if extra := len(verdicts); extra != 0 {
		t.Fatalf("the handoff hook ran %d extra times", extra)
	}
	// And the same read once the handoff has finished.
	if after := readAt(id); after != "" {
		t.Fatal(after)
	}
	// The receive above orders the seam's read of this field before the write;
	// every later search is submitted afterwards, so its goroutine sees nil.
	s.searchRetained.handoff = nil

	// Concurrent half, as a belt: nothing a reader sees while searches retire
	// around it is ever invalid or silent.
	stop := make(chan struct{})
	problems := make(chan string, 1)
	report := func(what string) {
		select {
		case problems <- what:
		default:
		}
	}
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// Exactly what jobGet does: snapshot the job, then merge.
				for _, j := range s.jobMgr.List() {
					if j.Kind != jobs.KindSearch || !j.State.Terminal() {
						continue
					}
					if what := readAt(j.ID); what != "" {
						report(what)
						return
					}
				}
				runtime.Gosched()
			}
		}()
	}

	for range 20 {
		runSearch(t, s, c, csrf)
	}
	close(stop)
	readers.Wait()
	select {
	case what := <-problems:
		t.Fatal(what)
	default:
	}
}

// TestPruneSearchResultsDropsReapedHits is the janitor backstop: the hits of a
// job the manager has forgotten are unreachable, and on a daemon where nobody
// searches again nothing else would come along to notice.
func TestPruneSearchResultsDropsReapedHits(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: 60, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)
	id := runSearch(t, s, c, csrf)
	if one, _, held := ledgerBytes(s, id); one <= 0 || held != 1 {
		t.Fatalf("nothing was retained: %d bytes, %d entries", one, held)
	}

	// A live job's hits are not the prune's business.
	s.PruneSearchResults()
	if one, _, held := ledgerBytes(s, id); one <= 0 || held != 1 {
		t.Fatalf("the prune released a live job's hits: %d bytes, %d entries", one, held)
	}

	// Swapping the manager makes that job unreachable, which is what a Reap
	// looks like from the ledger. No new search follows: the exported prune is
	// the only thing that runs.
	s.SetJobs(fj, jobs.New(jobs.Limits{}))
	t.Cleanup(func() { _ = s.jobMgr.Close(context.Background()) })
	s.PruneSearchResults()
	one, total, held := ledgerBytes(s, id)
	if one != 0 || total != 0 || held != 0 {
		t.Fatalf("a reaped job's hits survived: %d bytes, total %d, %d entries", one, total, held)
	}

	// And it is safe on a server with no job spine at all.
	bare := &Server{}
	bare.PruneSearchResults()
}

// TestSearchRetentionEvictsOldestResults is the round-7 adversarial P1: a user
// repeating searches of their own directory retained every hit of every one of
// them for the manager's whole retention window — hundreds of megabytes inside
// a daemon running as root. The bytes are budgeted now, and the OLDEST results
// are the ones released.
func TestSearchRetentionEvictsOldestResults(t *testing.T) {
	s, fj := transferFixture(t)
	s.searchRetained.limit = 64 << 10
	fj.result = wproto.JobResult{Files: 60, Dirs: 2, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)

	// Calibrate against one result's real weight rather than guessing at the
	// JSON size, then submit enough searches to overrun the budget.
	ids := []string{runSearch(t, s, c, csrf)}
	one, _, _ := ledgerBytes(s, ids[0])
	budget := s.searchRetained.budget()
	if one <= 0 || one > budget {
		t.Fatalf("one result weighs %d against a %d budget; recalibrate the fixture", one, budget)
	}
	for range budget/one + 2 {
		ids = append(ids, runSearch(t, s, c, csrf))
	}

	// The newest search is intact: a user who just searched sees their results.
	newest, _ := storedView(t, s, ids[len(ids)-1])
	view := servedView(t, s, ids[len(ids)-1])
	if len(view.Hits) != 60 || view.Detail == searchDroppedNote {
		t.Fatalf("the newest result was released: %d hits detail=%q", len(view.Hits), view.Detail)
	}
	if newest.State != jobs.StateDone {
		t.Fatalf("newest state %v", newest.State)
	}

	// The oldest is not, and it says so rather than pretending it found nothing.
	dropped := awaitDropped(t, s, ids[0])
	if dropped.Detail != searchDroppedNote {
		t.Fatalf("evicted detail = %q, want %q", dropped.Detail, searchDroppedNote)
	}
	// The job, and everything about it that is not the payload, survives: only
	// Result is rewritten, so the state, the title and the history stay put.
	if evicted, _ := storedView(t, s, ids[0]); evicted.State != jobs.StateDone || evicted.Title == "" || evicted.FinishedAt.IsZero() {
		t.Fatalf("eviction damaged the job: %+v", evicted)
	}
	if dropped.Files != 60 || dropped.Dirs != 2 {
		t.Fatalf("eviction dropped the counts: %+v", dropped)
	}

	s.searchRetained.mu.Lock()
	total, tracked, order := s.searchRetained.total, len(s.searchRetained.held), len(s.searchRetained.order)
	holding, marked := 0, 0
	for _, entry := range s.searchRetained.held {
		if len(entry.hits) > 0 {
			holding++
		}
		if entry.dropped {
			marked++
		}
	}
	s.searchRetained.mu.Unlock()
	if total > budget {
		t.Fatalf("retained %d bytes against a %d budget", total, budget)
	}
	if tracked != order {
		t.Fatalf("ledger tracked=%d but order=%d", tracked, order)
	}
	// An evicted entry stays behind as its own marker — that mark is what stops
	// its own goroutine from restoring the pre-eviction summary on top of the
	// loss notice (round-11 P2) — so what shrinks is the number still HOLDING.
	if holding >= len(ids) || marked == 0 || holding+marked != tracked {
		t.Fatalf("ledger holding=%d marked=%d of %d entries after %d searches", holding, marked, tracked, len(ids))
	}
}

// TestSearchRetentionEvictedJobAnswersHonestly is the HTTP half: a GET of an
// evicted job must say the results are gone, and the list must still show the
// job with its counts.
func TestSearchRetentionEvictedJobAnswersHonestly(t *testing.T) {
	s, fj := transferFixture(t)
	s.searchRetained.limit = 64 << 10
	fj.result = wproto.JobResult{Files: 60, Dirs: 2, Bytes: 4096, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)
	oldest := runSearch(t, s, c, csrf)
	one, _, _ := ledgerBytes(s, oldest)
	for range s.searchRetained.budget()/one + 2 {
		runSearch(t, s, c, csrf)
	}
	awaitDropped(t, s, oldest)

	w := request(s, http.MethodGet, "/api/jobs/"+oldest, c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	var single struct {
		Job struct {
			Result map[string]json.RawMessage `json:"result"`
		} `json:"job"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &single); err != nil {
		t.Fatal(err)
	}
	if _, ok := single.Job.Result["hits"]; ok {
		t.Fatalf("an evicted job still served hits: %s", w.Body)
	}
	if string(single.Job.Result["detail"]) != `"`+searchDroppedNote+`"` {
		t.Fatalf("detail = %s", single.Job.Result["detail"])
	}
	if string(single.Job.Result["files"]) != "60" || string(single.Job.Result["bytes"]) != "4096" {
		t.Fatalf("counts did not survive the GET: %s", w.Body)
	}

	w = request(s, http.MethodGet, "/api/jobs", c, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	var list struct {
		Jobs []struct {
			ID     string                     `json:"id"`
			Result map[string]json.RawMessage `json:"result"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, j := range list.Jobs {
		if j.ID != oldest {
			continue
		}
		found = true
		if string(j.Result["files"]) != "60" || string(j.Result["dirs"]) != "2" || string(j.Result["bytes"]) != "4096" {
			t.Fatalf("list lost the counts: %s", w.Body)
		}
		if string(j.Result["detail"]) != `"`+searchDroppedNote+`"` {
			t.Fatalf("list detail = %s", j.Result["detail"])
		}
	}
	if !found {
		t.Fatalf("the evicted job left the list: %s", w.Body)
	}
}

// TestSearchRetentionTruncatesAnOversizedResult covers the case eviction cannot
// help with: a single result bigger than the whole budget. Releasing older
// results would not bring it inside, so it is kept truncated — the first hits,
// which are the ones on screen — carrying the same note.
func TestSearchRetentionTruncatesAnOversizedResult(t *testing.T) {
	s, fj := transferFixture(t)
	s.searchRetained.limit = 16 << 10
	fj.result = wproto.JobResult{Files: 60, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)
	id := runSearch(t, s, c, csrf)

	view := servedView(t, s, id)
	if len(view.Hits) == 0 || len(view.Hits) >= 60 {
		t.Fatalf("kept %d of 60 hits", len(view.Hits))
	}
	one, _, _ := ledgerBytes(s, id)
	if one > s.searchRetained.budget() {
		t.Fatalf("a truncated result still holds %d bytes", one)
	}
	if !strings.HasPrefix(view.Detail, "kept the first ") || !strings.Contains(view.Detail, searchDroppedNote) {
		t.Fatalf("detail = %q", view.Detail)
	}
	// The hits kept are the first ones, in order, mapped back to the requested
	// spelling like every other search hit.
	if !strings.HasPrefix(view.Hits[0].Path, "/src/0000-") {
		t.Fatalf("truncation kept the wrong end: %q", view.Hits[0].Path)
	}
	if view.Files != 60 {
		t.Fatalf("truncation dropped the counts: %+v", view)
	}
	_, total, _ := ledgerBytes(s, id)
	if total != one {
		t.Fatalf("ledger total %d does not match the %d bytes it holds", total, one)
	}
	// The manager holds only the summary, truncation note and all.
	j, stored := storedView(t, s, id)
	if len(stored.Hits) != 0 || len(j.Result) > 4<<10 || !strings.HasPrefix(stored.Detail, "kept the first ") {
		t.Fatalf("the manager holds %d bytes: %+v", len(j.Result), stored)
	}
}

// TestSearchResultOfAReapedJobIs404 is round-13 P2. jobGet snapshots the job's
// hit-free summary and then resolves the hits; the janitor can reap the job and
// prune its ledger entry in between. The branch for "nothing recorded" then
// returned that stale summary — 200, state done, zero hits, no notice — for a
// search that had found matches. A result that looks like an answer and is not
// one is worse than no result, so the job is reported gone.
func TestSearchResultOfAReapedJobIs404(t *testing.T) {
	s, fj := transferFixture(t)
	fj.result = wproto.JobResult{Files: 60, Dirs: 2, Hits: searchHits(60)}
	c, csrf := sessionCookie(t, s)
	id := runSearch(t, s, c, csrf)

	// The snapshot a reader is holding: the summary, hits already in the ledger.
	stale, ok := s.jobMgr.Get(id)
	if !ok {
		t.Fatal("the job is gone")
	}
	if bytes.Contains(stale.Result, hitsKey) {
		t.Fatalf("the fixture snapshot still carries hits: %.200s", stale.Result)
	}

	// Now the janitor gets there first: the job is reaped and the prune drops
	// its ledger entry, so neither side knows anything about it any more.
	s.SetJobs(fj, jobs.New(jobs.Limits{}))
	t.Cleanup(func() { _ = s.jobMgr.Close(context.Background()) })
	s.PruneSearchResults()
	if _, _, held := ledgerBytes(s, id); held != 0 {
		t.Fatalf("the prune left %d entries", held)
	}

	if raw, live := s.searchResultOf(stale); live {
		t.Fatalf("a reaped job was served a stale summary: %.200s", raw)
	}
	// And over HTTP, where the difference is what a user sees.
	w := request(s, http.MethodGet, "/api/jobs/"+id, c, nil)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), `"code":"not_found"`) {
		t.Fatalf("GET of a reaped job: %d %s", w.Code, w.Body)
	}

	// A job the manager still holds, with its hits still in its own copy, is
	// served as before — the 404 is for "gone", not for "not in the ledger".
	fresh := runSearch(t, s, c, csrf)
	full := servedView(t, s, fresh)
	if _, ok := s.jobMgr.ReplaceResult(fresh, full); !ok {
		t.Fatal("the fresh job is gone")
	}
	s.searchRetained.mu.Lock()
	s.searchRetained.total -= len(s.searchRetained.held[fresh].hits)
	delete(s.searchRetained.held, fresh)
	s.searchRetained.mu.Unlock()
	j, _ := s.jobMgr.Get(fresh)
	raw, live := s.searchResultOf(j)
	if !live {
		t.Fatal("a job the manager still holds was reported gone")
	}
	var view jobResultView
	if err := json.Unmarshal(raw, &view); err != nil || len(view.Hits) != 60 {
		t.Fatalf("hits from the manager's own copy: %d %v", len(view.Hits), err)
	}
}

// TestSearchCountEvictionKeepsTheLossNoticeInTheGap is round-15 P2. The byte
// budget leaves an evicted entry behind as its own marker; the COUNT cap used to
// delete it outright, and between that delete and the notice reaching the
// manager a GET found neither hits nor a mark. It then answered with the stale
// hit-free summary: 200, done, no results, no explanation — for a search that
// had found matches.
//
// The gap is entered deliberately through the handoff seam, which fires after
// the ledger has committed the eviction and before any notice is published.
func TestSearchCountEvictionKeepsTheLossNoticeInTheGap(t *testing.T) {
	s, fj := transferFixture(t)
	// Small results: the byte budget must never be what evicts here, or the test
	// would be exercising the path that was already correct.
	fj.result = wproto.JobResult{Files: 2, Hits: searchHits(2)}
	c, csrf := sessionCookie(t, s)

	oldest := runSearch(t, s, c, csrf)
	for range maxRetainedSearchJobs - 1 {
		runSearch(t, s, c, csrf)
	}
	if one, total, _ := ledgerBytes(s, oldest); one == 0 || total > s.searchRetained.budget() {
		t.Fatalf("fixture: oldest holds %d bytes, ledger holds %d against a %d budget", one, total, s.searchRetained.budget())
	}

	// The next search takes the count past the cap and evicts the oldest. Read
	// it from inside the window, which is where the wrong answer used to live.
	// The verdict crosses on a channel; a shared variable here would be a race.
	verdicts := make(chan string, 4)
	s.searchRetained.handoff = func(string) {
		j, live := s.jobMgr.Get(oldest)
		if !live {
			verdicts <- "the evicted job disappeared"
			return
		}
		raw, served := s.searchResultOf(j)
		if !served {
			verdicts <- "the evicted job was reported gone"
			return
		}
		var view jobResultView
		if err := json.Unmarshal(raw, &view); err != nil {
			verdicts <- fmt.Sprintf("invalid JSON: %v", err)
			return
		}
		if len(view.Hits) != 0 || view.Detail != searchDroppedNote {
			verdicts <- fmt.Sprintf("served %d hits and detail=%q inside the eviction gap", len(view.Hits), view.Detail)
			return
		}
		verdicts <- ""
	}
	runSearch(t, s, c, csrf)
	select {
	case got := <-verdicts:
		if got != "" {
			t.Fatal(got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handoff hook never ran")
	}
	// The receive orders the seam's read of this field before the write.
	s.searchRetained.handoff = nil

	// Settled, the answer is the same: the hits are gone and it says so.
	if view := awaitDropped(t, s, oldest); view.Detail != searchDroppedNote {
		t.Fatalf("after the gap: detail=%q", view.Detail)
	}
	// And the cap did its job: the number still HOLDING hits is bounded, while
	// the marker stayed behind to answer for the one that was released.
	s.searchRetained.mu.Lock()
	holding, entries := 0, len(s.searchRetained.held)
	for _, entry := range s.searchRetained.held {
		if len(entry.hits) > 0 {
			holding++
		}
	}
	s.searchRetained.mu.Unlock()
	if holding > maxRetainedSearchJobs {
		t.Fatalf("%d entries still hold hits, cap is %d", holding, maxRetainedSearchJobs)
	}
	if entries <= holding {
		t.Fatalf("no marker was kept: %d entries, %d holding", entries, holding)
	}
}
