package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"qnapfilemanager/internal/audit"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/wproto"
)

func (s *Server) jobSearch(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.jobsReady(w, r) || !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Roots       []pathRef `json:"roots"`
		Query       string    `json:"query"`
		Glob        bool      `json:"glob"`
		Hidden      bool      `json:"hidden"`
		CrossMounts bool      `json:"crossMounts"`
		Kind        string    `json:"kind"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	// Refused before anything is resolved or measured: the query is pure request
	// data that never reaches the kernel, so nothing downstream would ever have
	// rejected it on length (round-7 adversarial P1). Every other job route's
	// title is built from a path component the worker resolves first, and the
	// kernel refuses a component past NAME_MAX; a query has no such backstop.
	if len(body.Query) > maxSearchQueryBytes {
		writeError(w, http.StatusUnprocessableEntity, "bad_request",
			fmt.Sprintf("The search query must be at most %d bytes.", maxSearchQueryBytes), "", "search", "")
		return
	}
	paths, ok := s.jobPaths(w, r, body.Roots)
	if !ok {
		return
	}
	var patternErr error
	if body.Glob {
		_, patternErr = path.Match(body.Query, "")
	}
	if body.Query == "" || patternErr != nil || body.Kind != "" && body.Kind != "any" && body.Kind != "file" && body.Kind != "dir" {
		writeError(w, http.StatusUnprocessableEntity, "bad_request", "Supply a non-empty query, valid pattern and kind (any, file or dir).", "", "search", "")
		return
	}
	resolved := make([]string, len(paths))
	wire := make([][]byte, len(paths))
	m := mutation{op: "search", path: paths[0]}
	for i, p := range paths {
		osPath, err := s.Root.OS(p)
		if err != nil {
			s.failResolve(w, r, p, err)
			return
		}
		// Even resolving a root on a dead network mount can block indefinitely.
		if s.platform != nil {
			if caps, _ := s.platform.ForLiteral(osPath); caps.Network {
				s.fail(w, r, "protected", "This location is a network mount and cannot be searched from here.", p, "")
				return
			}
		}
		resolved[i], err = s.resolveForGuard(r.Context(), sess.who, p, true)
		if err != nil {
			s.failResolve(w, r, p, err)
			return
		}
		for _, spelling := range []string{p, resolved[i]} {
			if s.guard.Check(guard.OpTraverse, spelling) != nil {
				s.authorize(w, r, sess, guard.ErrProtected, false, m, p, nil, false, "", guard.Summary{})
				return
			}
		}
		wire[i] = []byte(resolved[i])
	}
	reqBody, err := json.Marshal(wproto.SearchReq{Roots: wire, Query: body.Query, Glob: body.Glob, Hidden: body.Hidden,
		CrossMounts: body.CrossMounts, Kind: body.Kind, MaxHits: 1000, MaxVisited: 10_000_000, MaxDuration: 300})
	if err != nil {
		s.fail(w, r, "internal", "The search could not be prepared.", m.path, "")
		return
	}
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The search could not be prepared.", m.path, "")
		return
	}
	// The audit line quotes the query FIRST and clips the quoted form, so the
	// cap holds in the bytes actually written: %q can double the length of a
	// query made of quotes and sextuple one made of control characters, and an
	// audit record is durable.
	detail := jobIntentDetail(id, "search query="+clipUTF8(strconv.Quote(body.Query), maxSearchQueryBytes), paths)
	if err := s.writeAudit(sess, r, m, "intent", "", "", detail, false); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The search could not be audited.", m.path, m.op, "")
		return
	}
	roots, who, actor := mappedRoots(paths, resolved), sess.who, jobActorOf(sess, r)
	meta := jobs.Meta{ID: id, Src: paths, Actor: who.User, UID: who.UID, OnFinish: func(j jobs.Job) {
		var view jobResultView
		_ = json.Unmarshal(j.Result, &view)
		result, code := jobFinishOutcome(j, max(view.Warnings, j.WarningCount), view.Skipped)
		// Detail carries the worker's cap reason, rather than a separate wire
		// flag: hit, visit and time caps all mean an incomplete search.
		truncated := strings.HasPrefix(view.Detail, "first ") || strings.HasPrefix(view.Detail, "stopped after ") || strings.Contains(view.Detail, "truncated=true")
		s.jobAudit(context.Background(), actor, audit.Event{Op: "search", Job: id, Path: m.path,
			Phase: "result", Result: result, Code: code, Files: view.Files,
			Detail: fmt.Sprintf("%s: %d hits, %d visited, truncated=%t; %s", detail, len(view.Hits), view.Files, truncated, view.Detail)}, false)
		// After the audit, which must record what the search actually found even
		// if the hits are released in the very next breath.
		s.retainSearchResult(j)
	}}
	// The title is a label the UI shows in a job row, and it is copied into every
	// snapshot of every poll for as long as the job is retained — so it carries a
	// display-sized fragment of the query, never the query.
	job, err := s.jobMgr.Submit(jobs.KindSearch, "Searching: "+clipUTF8(body.Query, maxJobTitleBytes), meta, func(ctx context.Context, p *jobs.Progress) (any, error) {
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: wproto.JobSearch, Body: reqBody},
			s.searchFilteredProgressSink(roots, p), s.searchFilteredWarnSink(roots, "search", id, p))
		view := viewOf(res)
		for _, hit := range res.Hits {
			raw, err := bodyPath(hit.Path, hit.PathB64)
			if err != nil {
				continue
			}
			inside := false
			for _, root := range roots.resolved {
				inside = inside || underRoot(raw, root)
			}
			if !inside {
				continue
			}
			mapped := roots.mapPath(raw)
			if s.guard.Check(guard.OpRead, raw) != nil || s.guard.Check(guard.OpTraverse, raw) != nil ||
				s.guard.Check(guard.OpRead, mapped) != nil || s.guard.Check(guard.OpTraverse, mapped) != nil {
				continue
			}
			hit.SetPath([]byte(mapped))
			hit.Class = s.class(mapped)
			view.Hits = append(view.Hits, hit)
		}
		return view, s.jobErr("search", id, err)
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, m, id, err)
		return
	}
	s.writeJob(w, *job)
}

// --- the query itself (round-7 adversarial P1) -------------------------------
//
// The retained-hit budget below counts hits. It does not count the QUERY, and
// the query outlived it: a 900 KiB query — comfortably under the 1 MiB body
// limit — survived verbatim in jobs.Job.Title and in the string the completion
// hook had captured for the audit line, so forty searches held 36 MB of titles
// while the ledger reported 880 bytes, and every poll of the job list
// serialised them again. A query is the one piece of a job that is pure request
// data: every other route's title is a path component, and the worker resolves
// those through the kernel before a job exists, so ENAMETOOLONG refuses
// anything past NAME_MAX. A query has no such backstop, so it gets an explicit
// one here.
const (
	// maxSearchQueryBytes is the largest query accepted at all, and the largest
	// number of bytes any audit line may spend on one. A thousand bytes is far
	// past any glob or substring a person types.
	maxSearchQueryBytes = 1024
	// maxJobTitleBytes is what a job title may carry of whatever names it. A
	// title is a row label copied into every snapshot of every poll, so it is
	// sized for a screen. Every other route's title is built from a path
	// component, which bodyPath now bounds at NAME_MAX (routes_mutate.go), but
	// 255 bytes is still a long row label — jobSize clips for the same reason.
	maxJobTitleBytes = 80
)

// clipUTF8 returns s cut to at most n BYTES, ending on a rune boundary, with an
// ellipsis in place of whatever was removed. The ellipsis is counted inside n,
// so the result never exceeds the budget the caller named — which is the whole
// point: these budgets exist to bound retained and durable bytes, and a limit
// that the marker itself could push past would not be one.
//
// Input is expected to be valid UTF-8 (a query arrives through encoding/json,
// which replaces invalid bytes with U+FFFD); for anything else the cut is still
// made on a leading byte, so the result never ends in a half-written rune.
func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const ellipsis = "…"
	cut := n - len(ellipsis)
	if cut <= 0 {
		return ""
	}
	// s[cut] is the first byte dropped; backing up until it starts a rune is
	// what makes s[:cut] whole.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + ellipsis
}

// --- retained search results (round-7 adversarial P1) ------------------------
//
// A search job's hits are the only unbounded thing a FINISHED job holds, and
// jobs.Manager's retention is a time window and a count — neither counts bytes.
// An ordinary user repeating searches of their own directory (a thousand hits
// under a dozen long components is some 17 MB of escaped JSON per result) could
// leave more than a gigabyte sitting in the root daemon for the whole hour,
// multiplied by every user doing it. Omitting hits from the polled list only
// changed what was sent; the payloads stayed, and every snapshot copied them.
//
// So the web layer budgets the bytes instead: each finished search declares what
// its stored result weighs, and when the total goes over budget the OLDEST
// retained results are released first — the job, its counts and its place in the
// history all survive; only the hits go, and Detail says so, so a later
// GET /api/jobs/<id> answers honestly rather than returning an empty list that
// looks like a search which found nothing.
//
// Budgeting the bytes was not enough on its own (round-7, second pass). While
// the hits lived inside jobs.Job.Result, every /api/jobs poll paid for them
// twice over: Manager.List copies each job's Result to snapshot it, and the list
// view then decoded each one only to throw the hits away. Nine retained searches
// that sat happily INSIDE the 32 MiB budget cost 72 MB of garbage and ~200 ms of
// CPU per poll — and a GET has no admission limit, so a user whose browser polls
// on a timer could exhaust the daemon without ever exceeding a single limit.
//
// The fix is to keep the hits out of the manager entirely. At finish the stored
// result is replaced with a hit-free view — counts, detail, truncation state —
// and the hits move here, keyed by job id, under the same accounting and the
// same eviction. The list then copies only small results and decodes nothing,
// and GET /api/jobs/<id> splices the hits back in for the one job it is asked
// about.
const (
	// maxRetainedSearchBytes is the process-wide budget for stored search hits.
	maxRetainedSearchBytes = 32 << 20
	// maxRetainedSearchJobs bounds how many finished searches may be HOLDING
	// hits at once, so a stream of tiny results cannot grow the ledger without
	// ever tripping the byte budget. It is well past jobs.Limits' own retention
	// count, so in practice the byte budget is what bites. An entry whose hits
	// have been released does not count: it is a marker, and forgetting markers
	// early is what produced round-15 P2.
	maxRetainedSearchJobs = 256
	// maxRetainedSearchMarkers bounds the entries themselves, markers included.
	// pruneReapedSearchResults normally collects a marker as soon as the manager
	// forgets its job, so this only bites on a daemon where nothing is ever
	// reaped; a marker is an id and two words, so it is sized generously.
	maxRetainedSearchMarkers = 4096
	// searchDroppedNote is what Detail says once a result's hits are gone. It
	// is phrased for the user, because the UI shows Detail verbatim.
	searchDroppedNote = "results no longer available (memory limit); run the search again"
	// searchSummaryHeadroom is what a truncated result reserves for everything
	// around the hits (counts, the note, the JSON scaffolding).
	searchSummaryHeadroom = 4 << 10
)

// searchRetention is the ledger: the hits of every finished search job, keyed
// by job id, in the order they were recorded, with what each weighs. Its mutex
// covers all four fields, and nothing takes it while holding a jobs.Manager
// lock — the order is always web ledger, then manager, and the manager is only
// called after the ledger is released.
type searchRetention struct {
	// limit replaces maxRetainedSearchBytes when it is positive. It exists so a
	// test can drive eviction and truncation with kilobytes instead of building
	// tens of megabytes of JSON; set it before serving, like Server.Now, and
	// never from a request.
	limit int
	// handoff, when set, is called once in the MIDDLE of moving a job's hits
	// from the manager to the ledger — after the ledger has them and before the
	// manager lets go. A test sets it to read at exactly that instant, which is
	// the only way to exercise a window a few instructions wide deterministically
	// rather than hoping a concurrent reader lands in it. Set before serving,
	// like limit; production never sets it and pays one nil check per search.
	handoff func(id string)

	mu    sync.Mutex
	held  map[string]retainedHits // job id -> what it is holding
	order []string                // job ids, oldest recorded first
	total int
}

// retainedHits is one finished search's entry in the ledger.
//
// dropped outlives the hits on purpose, and that is the whole reason this is a
// struct rather than a bare []byte. Eviction happens on a NEWER search's
// goroutine while the evicted search's own retainSearchResult is in the middle
// of its handoff — it has already given the ledger the hits and has not yet
// rewritten the manager's copy. The evictor writes the loss notice, then the
// evicted job's own goroutine resumes and its rewrite lands on top, restoring
// the summary it computed before the eviction existed: hits gone, and a job
// that reads as a clean search that simply found nothing (round-11 P2). The
// mark is what lets that goroutine notice and put the notice back.
type retainedHits struct {
	hits    json.RawMessage
	dropped bool
}

func (r *searchRetention) budget() int {
	if r.limit > 0 {
		return r.limit
	}
	return maxRetainedSearchBytes
}

// entryFor returns what the ledger holds for a job and whether it has an entry
// for that job at all. The two differ and the difference decides an answer: no
// entry means the finish hook has not run yet, while an entry with no hits means
// it has — the search found none, or they have been evicted, which the entry's
// mark says ("no hits" and "hits released" are different answers to a client).
// A stored slice is never mutated afterwards, so handing it out is safe.
func (r *searchRetention) entryFor(id string) (retainedHits, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, recorded := r.held[id]
	return entry, recorded
}

// wasDropped reports whether this job's hits have been released to stay inside
// the budget. It is asked once more at the end of the handoff, because the
// answer can change while the ledger's lock is down.
func (r *searchRetention) wasDropped(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.held[id].dropped
}

// retainSearchResult moves a finished search's hits out of the manager and into
// the ledger, then releases older results until the process is back inside the
// budget. It runs on the job's own goroutine, from the OnFinish hook, exactly
// once per job — which is what makes the accounting below safe to do here.
func (s *Server) retainSearchResult(j jobs.Job) {
	if s.jobMgr == nil {
		return
	}
	var view jobResultView
	if len(j.Result) > 0 {
		if err := json.Unmarshal(j.Result, &view); err != nil {
			return
		}
	}
	budget := s.searchRetained.budget()
	hits, size := view.Hits, 0
	// A single result larger than the entire budget: there is nothing older to
	// release that would help, so it is cut down to what fits. Truncating beats
	// dropping it whole — the first hits are the ones the user is looking at —
	// and the note says the rest are gone.
	truncated := false
	if kept := hitsWithin(hits, budget-searchSummaryHeadroom); kept < len(hits) {
		view.Detail = fmt.Sprintf("kept the first %d of %d; further %s", kept, len(hits), searchDroppedNote)
		hits, truncated = hits[:kept], true
	}
	raw, err := json.Marshal(hits)
	if err != nil || len(hits) == 0 {
		raw, size = nil, 0
	} else {
		size = len(raw)
	}
	// Only the manager's copy is rewritten, and only when there is something to
	// rewrite. A search cancelled in the queue never ran and has no result at
	// all, and replacing that with a zeroed summary would invent counts for work
	// that never happened.
	changed := len(view.Hits) > 0 || truncated
	view.Hits = nil

	// The ledger takes the hits BEFORE the manager gives them up. The other
	// order left a window — narrow, but reproducible under concurrent reads —
	// in which a finished search's hits were in neither place, and a GET landing
	// in it answered with an empty result and no note: a successful search
	// showing "0 results" in the UI's final fetch. Inverting it means both sides
	// hold them for an instant instead of neither, which searchResultOf resolves
	// by preferring the manager's copy while it is still there.
	r := &s.searchRetained
	r.mu.Lock()
	if r.held == nil {
		r.held = make(map[string]retainedHits)
	}
	if prev, seen := r.held[j.ID]; seen {
		r.total -= len(prev.hits)
	} else {
		r.order = append(r.order, j.ID)
	}
	// Recorded even when there are no hits, so the ledger is an exact record of
	// which finished searches have been through here — which is also what bounds
	// it by count, not only by bytes.
	r.held[j.ID] = retainedHits{hits: raw}
	r.total += size
	var release []string
	// The byte budget releases the oldest hits, oldest first, and leaves each
	// entry behind as its own marker. The result just recorded is the newest;
	// releasing it here would make a search that fits the budget arrive already
	// empty, and truncation above has already brought it inside.
	for i := 0; r.total > budget && i < len(r.order); i++ {
		id := r.order[i]
		entry := r.held[id]
		if id == j.ID || len(entry.hits) == 0 {
			continue
		}
		r.total -= len(entry.hits)
		r.held[id] = retainedHits{dropped: true}
		release = append(release, id)
	}
	// The count cap releases hits the same way, and for the same reason: it used
	// to delete the entry outright, and between that delete and the notice being
	// published a GET found neither hits nor a mark and answered with a clean
	// empty result — the exact wrong answer the marker exists to prevent
	// (round-15 P2). So the cap counts what still HOLDS something; a marker is a
	// few words and is not what the cap is for.
	holding := 0
	for _, id := range r.order {
		if len(r.held[id].hits) > 0 {
			holding++
		}
	}
	for i := 0; holding > maxRetainedSearchJobs && i < len(r.order); i++ {
		id := r.order[i]
		entry := r.held[id]
		if id == j.ID || len(entry.hits) == 0 {
			continue
		}
		r.total -= len(entry.hits)
		r.held[id] = retainedHits{dropped: true}
		release = append(release, id)
		holding--
	}
	// Markers are cheap but not free. Normally pruneReapedSearchResults collects
	// them as the manager forgets the jobs they belong to; this is the backstop
	// for a daemon whose jobs are never reaped, and by the time an entry is this
	// old its notice was published long ago and the goroutine that could have
	// overwritten it is finished.
	for len(r.order) > maxRetainedSearchMarkers && r.order[0] != j.ID {
		id := r.order[0]
		r.order = r.order[1:]
		if entry := r.held[id]; len(entry.hits) > 0 {
			r.total -= len(entry.hits)
			release = append(release, id)
		}
		delete(r.held, id)
	}
	r.mu.Unlock()

	// The middle of the handoff: the ledger has the hits and the manager has not
	// yet let go, so a reader here must still be answered in full.
	if h := r.handoff; h != nil {
		h(j.ID)
	}

	// Outside the ledger's lock: everything below calls into jobs.Manager.
	if changed {
		if _, ok := s.jobMgr.ReplaceResult(j.ID, view); !ok {
			// Reaped between finishing and here. The hits just recorded are for
			// a job nobody can ask about; the prune below collects them.
			s.pruneReapedSearchResults()
			return
		}
	}
	// The second look (round-11 P2). While the ledger's lock was down, a NEWER
	// search may have evicted this very job and written its loss notice — and
	// the rewrite just above would have put the pre-eviction summary back on
	// top of it, leaving a job whose hits are gone but which reads as a search
	// that found nothing. The notice always wins, so it goes back on.
	//
	// This converges rather than merely narrowing the window: an eviction
	// BEFORE this point is caught here, and one after it is written by the
	// evicting goroutine with nothing left to overwrite it.
	// noteSearchResultDropped is idempotent, so both writing it is harmless.
	if r.wasDropped(j.ID) {
		s.noteSearchResultDropped(j.ID)
	}
	for _, id := range release {
		s.noteSearchResultDropped(id)
	}
	s.pruneReapedSearchResults()
}

// PruneSearchResults releases the hits of search jobs the manager has already
// forgotten, with no new search having to arrive. Every finish prunes too, which
// covers a daemon anybody is using; this is the backstop for a quiet one, for a
// caller's janitor ticker to call beside ReapArchiveSelections. The byte budget
// bounds the ledger either way, so this only shortens how long an unreachable
// job's hits are held. Safe to call at any time.
func (s *Server) PruneSearchResults() {
	s.pruneReapedSearchResults()
}

// pruneReapedSearchResults releases the hits of jobs the manager has already
// forgotten. It exists because moving the hits out of jobs.Job took them out of
// Reap's reach: while they lived inside the job, retention freed them with it,
// and without this they would outlive the job they belong to and sit there until
// the byte budget happened to push them out. Nothing can ask about a reaped job,
// so its hits are unreachable and there is no reason to keep them.
//
// The manager is queried between the two lock holds rather than under the
// ledger's, which keeps the rule that this package never calls jobs.Manager
// while holding the ledger. Entries added in the gap are simply not considered
// this time round.
func (s *Server) pruneReapedSearchResults() {
	if s.jobMgr == nil {
		// Nothing can have been recorded without a manager, and the exported
		// entry point above may be called by a caller that wired none.
		return
	}
	r := &s.searchRetained
	r.mu.Lock()
	ids := append([]string(nil), r.order...)
	r.mu.Unlock()

	var gone []string
	for _, id := range ids {
		if _, ok := s.jobMgr.Get(id); !ok {
			gone = append(gone, id)
		}
	}
	if len(gone) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range gone {
		if entry, ok := r.held[id]; ok {
			r.total -= len(entry.hits)
			delete(r.held, id)
		}
	}
	kept := r.order[:0]
	for _, id := range r.order {
		if _, ok := r.held[id]; ok {
			kept = append(kept, id)
		}
	}
	r.order = kept
}

// hitsWithin reports how many leading hits fit in room bytes. They are measured
// one at a time rather than by re-marshalling the whole array per candidate,
// which would be quadratic in the thousand hits this exists for.
func hitsWithin(hits []fsx.Entry, room int) int {
	if room <= 0 {
		return 0
	}
	used := 0
	for i, hit := range hits {
		raw, err := json.Marshal(hit)
		if err != nil {
			return i
		}
		if used+len(raw)+1 > room {
			return i
		}
		used += len(raw) + 1
	}
	return len(hits)
}

// noteSearchResultDropped tells a job whose hits have just been evicted to say
// so, keeping everything else about it. A job the manager has already reaped is
// left alone.
func (s *Server) noteSearchResultDropped(id string) {
	j, ok := s.jobMgr.Get(id)
	if !ok || len(j.Result) == 0 {
		return
	}
	var view jobResultView
	if err := json.Unmarshal(j.Result, &view); err != nil || view.Detail == searchDroppedNote {
		return
	}
	view.Hits = nil
	view.Detail = searchDroppedNote
	s.jobMgr.ReplaceResult(id, view)
}

// --- bulk result reads (round-11 P1) -----------------------------------------
//
// The retention ledger bounds what the daemon HOLDS. It says nothing about what
// the daemon is in the middle of WRITING, and a single-job GET of a search with
// retained hits builds a complete copy of that result per request — once for
// the splice, once more inside the JSON encoder. An authenticated user can ask
// for the same large result again and again and simply never read the replies:
// each blocked write keeps its buffers alive, and with no WriteTimeout on the
// server a blocked write is never interrupted. Thirty-two blocked readers of
// one 3.37 MiB result held about 108 MiB, none of it visible to the budget.
//
// So the big responses are admitted rather than merely produced: a few at a
// time per session and a few in total, and each one gets a write deadline so a
// client that stops reading is dropped instead of pinning its buffers forever.
// Ordinary responses — a job summary is a few hundred bytes — are untouched.
const (
	// bulkResultBytes is the size at which a single-job GET stops being an
	// ordinary response and starts needing a slot.
	bulkResultBytes = 64 << 10
	// maxBulkReadsPerSession is what one browser may have in flight. The UI
	// fetches a search's hits exactly once when the search finishes, so two is
	// already slack; it is not a throughput knob.
	maxBulkReadsPerSession = 2
	// maxBulkReadsTotal is the process-wide ceiling. A search is capped at 1000
	// hits, so the largest plausible result is a few MiB and this bounds the
	// bytes in flight to a few tens of MiB — against unbounded before.
	maxBulkReadsTotal = 6
	// bulkWriteGrace and bulkWritePerMiB size the write deadline: enough for a
	// slow but real client, short enough that a silent one lets go. Bounded by
	// bulkWriteMax however large the result is.
	bulkWriteGrace  = 30 * time.Second
	bulkWritePerMiB = time.Second
	bulkWriteMax    = 5 * time.Minute
)

// bulkReadLimiter admits the single-job GETs that carry a large payload. It is
// the same shape as uploadLimiter (routes_upload.go), and deliberately separate
// from it: an upload slot and a bulk-read slot bound different resources, and
// sharing one pool would let a download starve an upload.
type bulkReadLimiter struct {
	// what names these responses in a refusal. Empty reads as "large results".
	what string
	// perSessionLimit, totalLimit and writeGrace replace the constants when
	// positive, for tests; set before serving, like Server.Now.
	perSessionLimit, totalLimit int
	writeGrace                  time.Duration
	// admitted, when set, is called once a slot is taken and the write deadline
	// armed, before the response is written. A test blocks in it to hold a slot
	// deterministically: a real client that stops reading cannot be relied on to
	// do that, because a loopback kernel will absorb megabytes on its own and
	// the handler finishes before anything can observe it. Set before serving;
	// production never sets it and pays one nil check per large response.
	admitted func()

	mu         sync.Mutex
	perSession map[string]int
	total      int
}

func (b *bulkReadLimiter) limits() (int, int) {
	perSession, total := b.perSessionLimit, b.totalLimit
	if perSession <= 0 {
		perSession = maxBulkReadsPerSession
	}
	if total <= 0 {
		total = maxBulkReadsTotal
	}
	return perSession, total
}

// acquire takes a slot for one response, or reports which ceiling refused it.
func (b *bulkReadLimiter) acquire(sessionID string) (release func(), refusal string) {
	perSession, total := b.limits()
	what := b.what
	if what == "" {
		what = "large results"
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total >= total {
		return nil, "The server is sending as many " + what + " as it can. Try again in a moment."
	}
	if b.perSession[sessionID] >= perSession {
		return nil, "This session is already receiving as many " + what + " as it may. Let one finish first."
	}
	if b.perSession == nil {
		b.perSession = make(map[string]int)
	}
	b.perSession[sessionID]++
	b.total++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.perSession[sessionID] <= 1 {
				delete(b.perSession, sessionID)
			} else {
				b.perSession[sessionID]--
			}
			if b.total > 0 {
				b.total--
			}
		})
	}, ""
}

// stallWindow is the rolling idle window for a response whose size is not known
// in advance — an archive stream. writeGrace overrides it for tests.
func (b *bulkReadLimiter) stallWindow() time.Duration {
	if b.writeGrace > 0 {
		return b.writeGrace
	}
	return archiveStallWindow
}

// deadlineFor is how long a response of this size may take to write.
func (b *bulkReadLimiter) deadlineFor(size int) time.Duration {
	grace := b.writeGrace
	if grace <= 0 {
		grace = bulkWriteGrace
	}
	return min(grace+time.Duration(size>>20)*bulkWritePerMiB, bulkWriteMax)
}

// admitBulkResult gates a single-job GET by the size of the response it is
// about to write. It reports whether the request may proceed, writing its own
// refusal if not, and returns the cleanup the caller defers.
//
// The caller measures the payload it has ALREADY built and passes that size.
// Asking the ledger instead used to leave a hole: a GET arriving after a search
// went terminal but before the finish hook's ledger insert found nothing
// recorded, skipped admission and the deadline entirely — and then served the
// hits out of the manager's copy in full, unbounded (round-12 P1). One code
// path, one measurement, taken from the bytes that are actually going out.
//
// An ordinary few-hundred-byte response is waved through: taking a slot for
// those would make the UI's normal polling contend for a resource it does not
// need.
func (s *Server) admitBulkResult(w http.ResponseWriter, r *http.Request, sess *session, size int) (func(), bool) {
	if size < bulkResultBytes {
		return func() {}, true
	}
	release, refusal := s.bulkReads.acquire(sess.id)
	if refusal != "" {
		// Retry-After and a closed connection, the same shape as the upload
		// admission refusal: a client that keeps the connection and retries at
		// once is the behaviour this exists to stop.
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Connection", "close")
		s.fail(w, r, "queue_full", refusal, "", "")
		return nil, false
	}
	// A client that stops reading must not pin these buffers for the life of the
	// process. Cleared on the way out so the connection is reusable.
	rc := http.NewResponseController(w)
	supported := rc.SetWriteDeadline(time.Now().Add(s.bulkReads.deadlineFor(size))) == nil
	if h := s.bulkReads.admitted; h != nil {
		h()
	}
	return func() {
		if supported {
			_ = rc.SetWriteDeadline(time.Time{})
		}
		release()
	}, true
}

// searchResultOf is a finished job's result as a client asking about that ONE
// job should see it: what the manager holds, with the hits the ledger keeps for
// it spliced back in.
//
// The hits of a finished search are in exactly one of two places, and for one
// instant in both: retainSearchResult records them in the ledger and only then
// takes them out of the manager. So the order of these cases matters. The
// manager's copy wins while it is still there — splicing the ledger's hits into
// a result that already carries its own would write the key twice — and the
// ledger answers once the manager has let go.
//
// The last case is the one this was written for. An entry in the ledger with no
// hits is a settled answer: the search found nothing, or the hits were evicted
// and Detail says so. NO entry, with nothing in the manager either, means the
// finish hook has not got there yet — and since the manager was read before the
// ledger was locked (this package never calls jobs.Manager while holding it),
// the handoff may simply have completed in between. That is worth one more look
// at the manager before answering, and exactly one: after that, a job with no
// entry and no hits genuinely has none yet.
func (s *Server) searchResultOf(j jobs.Job) (json.RawMessage, bool) {
	result := j.Result
	for attempt := 0; ; attempt++ {
		entry, recorded := s.searchRetained.entryFor(j.ID)
		switch {
		case bytes.Contains(result, hitsKey):
			return result, true
		case len(entry.hits) > 0:
			return spliceSearchHits(result, entry.hits), true
		case entry.dropped:
			// The ledger says the hits are gone, so the answer says so — rather
			// than trusting the snapshot in hand to say it already. That
			// snapshot may have been taken before the eviction landed, and
			// returning it verbatim describes a search that found nothing
			// (round-12 P2): the loss is exactly the thing a user must be told.
			return applyDroppedNote(result), true
		case recorded || attempt > 0:
			return result, true
		}
		fresh, live := s.jobMgr.Get(j.ID)
		if !live {
			// Nothing in the ledger and the job itself is gone: the janitor
			// reaped it and pruned its entry between the caller's snapshot and
			// this lookup. The snapshot in hand is a hit-free summary with no
			// notice, and serving it would report a successful search that
			// found nothing — for a search that found matches (round-13 P2).
			// There is no truthful answer left, so say the job is gone.
			return nil, false
		}
		result = fresh.Result
	}
}

// applyDroppedNote rewrites a summary to say its hits are gone. It decodes and
// re-encodes, which is affordable precisely because it only ever runs on a
// result that has no hits left in it.
func applyDroppedNote(result json.RawMessage) json.RawMessage {
	var view jobResultView
	if err := json.Unmarshal(result, &view); err != nil {
		return result
	}
	if len(view.Hits) == 0 && view.Detail == searchDroppedNote {
		return result
	}
	view.Hits, view.Detail = nil, searchDroppedNote
	out, err := json.Marshal(view)
	if err != nil {
		return result
	}
	return out
}

// spliceSearchHits puts a hits array back at the front of a stored summary.
//
// It works on the bytes rather than decoding the view and re-encoding it, and
// that is deliberate: a decode-and-re-encode allocates the hits two or three
// times over, which is the cost this whole arrangement exists to remove.
// jobResultView declares Hits first, so the canonical encoding starts
// `{"hits":[…],` and putting them back at the front reproduces it byte for byte.
func spliceSearchHits(result, hits json.RawMessage) json.RawMessage {
	if len(hits) == 0 || len(result) < 2 || result[0] != '{' {
		return result
	}
	out := make([]byte, 0, len(result)+len(hits)+8)
	out = append(out, '{')
	out = append(out, `"hits":`...)
	out = append(out, hits...)
	if result[1] != '}' {
		out = append(out, ',')
	}
	return append(out, result[1:]...)
}

// searchGuardedPath checks if a path should be hidden from the search view.
// It applies the same guard logic as hits: both OpRead and OpTraverse checks
// on both the raw and mapped spellings must pass.
func (s *Server) searchGuardedPath(raw, mapped string) bool {
	return s.guard.Check(guard.OpRead, raw) != nil || s.guard.Check(guard.OpTraverse, raw) != nil ||
		s.guard.Check(guard.OpRead, mapped) != nil || s.guard.Check(guard.OpTraverse, mapped) != nil
}

// searchNearestAllowedAncestor returns the nearest ancestor of path that passes
// guard checks on both spellings, or "" if no ancestor is allowed.
func (s *Server) searchNearestAllowedAncestor(raw, mapped string) string {
	for {
		parent := fsx.Parent(raw)
		if parent == raw { // reached root
			return ""
		}
		raw = parent
		mapped = fsx.Parent(mapped)
		if !s.searchGuardedPath(raw, mapped) {
			return mapped
		}
	}
}

// searchFilteredProgressSink wraps the standard progress sink to redact paths
// that would be hidden from the final hits (protected paths under Deny rules).
func (s *Server) searchFilteredProgressSink(roots jobRoots, p *jobs.Progress) func(wproto.Prog) {
	baseSink := s.progressSink(roots, p)
	return func(pr wproto.Prog) {
		// First pass: handle current path with guard filtering
		if len(pr.Current) > 0 {
			raw, _ := bodyPath(string(pr.Current), "")
			mapped := roots.mapPath(raw)
			if s.searchGuardedPath(raw, mapped) {
				// Path is protected; use nearest allowed ancestor or omit
				if ancestor := s.searchNearestAllowedAncestor(raw, mapped); ancestor != "" {
					pr.Current = []byte(ancestor)
				} else {
					pr.Current = nil
				}
			}
		}
		baseSink(pr)
	}
}

// searchFilteredWarnSink wraps the standard warning sink to redact paths
// that would be hidden from the final hits (protected paths under Deny rules).
func (s *Server) searchFilteredWarnSink(roots jobRoots, op, id string, p *jobs.Progress) func(wproto.Warn) {
	baseSink := s.warnSink(roots, op, id, p)
	return func(wn wproto.Warn) {
		// Check if the warning path should be hidden
		raw, _ := bodyPath(string(wn.Path), "")
		mapped := roots.mapPath(raw)
		if s.searchGuardedPath(raw, mapped) {
			// Path is protected; replace with nearest allowed ancestor or omit
			if ancestor := s.searchNearestAllowedAncestor(raw, mapped); ancestor != "" {
				wn.Path = []byte(ancestor)
			} else {
				// Drop the path from the warning but still count it in progress
				wn.Path = nil
			}
		}
		baseSink(wn)
	}
}
