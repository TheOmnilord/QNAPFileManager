package fsops

// The M2-C search (contract §3): one walk per selected root, matching names and
// nothing else.
//
// Three properties fix its shape, and all three are the walk's rather than this
// file's.
//
//   - It reads NOTHING. A search opens no file, follows no symlink and
//     descends into nothing the walk would not descend into for a size probe:
//     held descriptors all the way down, ProtectSnapshots so a ".zfs" tree is
//     not enumerated, and the crossing rule of PLAN.md decision 9. A match is
//     decided from the lstat the walk already has, so a hit costs no syscall of
//     its own.
//   - It is BOUNDED three ways, and says which bound it hit. A file manager's
//     search runs against a share with four million files on a NAS with one
//     gigabyte of memory; a result set that grew until the worker was killed
//     would be a worse answer than a truncated one that says it is truncated.
//     The caps arrive on the wire and are clamped here to the maxima below,
//     because the worker does not trust a request to carry its own limits
//     (§3.2, the rule List already follows for ListMax).
//   - A per-item failure is a warning and a count, never the end. An
//     unreadable subdirectory of a million-entry tree is reported and skipped,
//     exactly as it is for a delete or a size.
//
// Nothing here decides policy. Which roots may be searched, and which hits a
// Deny prefix hides, is the front-end guard's (INV-1); this file matches names
// and reports what the kernel let it see.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// The maxima of contract §3.2. The route sends these; the worker clamps to
// them, so a request asking for a million hits gets a thousand.
const (
	searchMaxHits    = 1000
	searchMaxVisited = 500_000
	searchMaxSeconds = 60

	// maxSearchResultBytes bounds what the HITS may weigh, which the count of
	// them does not (M2-C review round 6 adversarial).
	//
	// A thousand is a bound on rows, not on bytes, and a row carries a path: up
	// to 4096 bytes of it, doubled by pathB64 when the name is not UTF-8, and
	// again by JSON escaping when it is full of ampersands and quotes. A
	// thousand such rows serialise to tens of megabytes, past wproto.MaxFrame —
	// and a terminal frame that cannot be encoded used to take the WHOLE WORKER
	// down with it, because a half-written frame is unrecoverable and the loop
	// cannot tell that kind of failure from this one. So the hits are weighed as
	// they are collected and the search stops before the frame it has to fit in
	// does.
	//
	// Eight megabytes against a sixty-four megabyte frame is deliberately not a
	// tight fit: the same frame carries up to a hundred warnings, each with its
	// own path and message, plus the envelope. An ordinary search of ordinary
	// names never comes near it — a thousand hits of hundred-byte paths is under
	// two hundred kilobytes — so this bound is only ever met by the shape that
	// was the attack.
	maxSearchResultBytes = 8 << 20

	// searchHitOverhead is the fixed part of one encoded hit: the field names,
	// the punctuation, the mode string, the timestamp. Measured generously up,
	// and used only by the fallback estimate below.
	searchHitOverhead = 512
)

// searchTimeCheck is how many entries the walk visits between two readings of
// the clock, for the same reason scanTimeCheck exists: the deadline only has to
// be honoured to within a fraction of a second, and a time.Now() per entry of a
// four-million-file share is a cost with no buyer.
//
// It is a variable so a test can make every entry a clock check. Production
// never assigns to it.
var searchTimeCheck = 128

// searchClock is the clock the duration cap is measured against, as a variable
// so a test can reach the cap without sleeping for a minute. Production never
// assigns to it.
var searchClock = time.Now

// searchResultBytesCap is maxSearchResultBytes as a variable, so a test can
// reach the budget without a tree of four-kilobyte paths. Production never
// assigns to it.
var searchResultBytesCap int64 = maxSearchResultBytes

// hitCost is what one hit will weigh in the terminal frame.
//
// It is the REAL encoded length, because that is the number the frame cap is
// about and because a thousand marshals of a small struct is nothing beside the
// walk that found them. The estimate below is the fallback for a struct that
// cannot be marshalled at all — which today cannot happen, and which must not
// quietly make the budget infinite if some later field changes that.
func hitCost(e fsx.Entry) int64 {
	if b, err := json.Marshal(e); err == nil {
		return int64(len(b)) + 1 // the comma that joins it to the array
	}
	return int64(len(e.Path)+len(e.PathB64)+len(e.Name)+len(e.NameB64)+
		len(e.LinkTarget)+len(e.LinkTargetB64)+len(e.LinkResolved)+len(e.LinkResolvedB64)+
		len(e.User)+len(e.Group)) + searchHitOverhead
}

// errSearchCapped stops a search from inside the visitor. It never leaves this
// file: Search turns it into the Detail that says which bound was hit.
var errSearchCapped = errors.New("fsops: the search hit its bound")

// Search walks the selected roots and returns the entries whose NAME matches
// (contract §3).
//
// The query is a case-insensitive substring by default and a path.Match pattern
// when Glob is set. Both are matched against the entry's own name — never
// against its path — because that is what a file manager's "find" box means and
// because matching a path would make the answer depend on where the search
// started rather than on what is in the tree.
//
// The result is a JobResult: Files is how many entries were visited, Hits are
// the matches in walk order, Skipped counts the directories that could not be
// read, and Detail says why the walk stopped early when it did. Cancellation
// returns what was found so far together with the context's error, so the
// worker's terminal frame carries the partial hits (job.go, F7) rather than an
// err frame with nothing in it.
func Search(ctx context.Context, r fsx.Root, plat *platform.Platform, req wproto.SearchReq, emit Emit) (wproto.JobResult, error) {
	s, err := newSearch(r, plat, req, emit)
	if err != nil {
		return wproto.JobResult{}, err
	}
	// The duration cap is a CONTEXT as well as a counter (adversarial finding
	// 5). The counter is only read when an entry is visited, and a directory
	// whose children all fail their lstat never visits one: every failure goes
	// through Warn, so a tree of unreadable entries ran past sixty seconds
	// without anything noticing. A context bounds every syscall path the walk
	// takes, including the ones that only ever produce warnings.
	walkCtx, cancel := searchTimeout(ctx, s.limit)
	defer cancel()

	for _, raw := range req.Roots {
		if err := ctx.Err(); err != nil {
			return s.result(), err
		}
		if err := s.root(walkCtx, string(raw)); err != nil {
			if errors.Is(err, errSearchCapped) {
				return s.result(), nil
			}
			if ctx.Err() != nil {
				return s.result(), ctx.Err()
			}
			if walkCtx.Err() != nil {
				// The walk's own deadline, not the caller's. It is a
				// TRUNCATION and not a cancellation: what was found is
				// reported, with the reason, exactly as the visited counter's
				// version of the same bound is.
				s.stop = fmt.Sprintf("stopped after %d s", s.limit)
				return s.result(), nil
			}
			return wproto.JobResult{}, err
		}
	}
	return s.result(), nil
}

// searchTimeout bounds the walk by wall-clock time. It is a variable so a test
// can hand back an already-expired context: the branch it guards is a walk that
// produces nothing but warnings for a minute, which cannot be staged any other
// way. Production never assigns to it.
var searchTimeout = func(ctx context.Context, seconds int64) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
}

// searcher is one running search.
type searcher struct {
	r    fsx.Root
	plat *platform.Platform
	emit Emit

	query    string
	glob     bool
	hidden   bool
	kind     string
	opts     WalkOptions
	deadline time.Time // zero when no duration cap applies

	maxHits    int
	maxVisited int64
	// limit is the duration cap in seconds, after clamping. It is kept so the
	// truncation reason names the bound that was actually applied rather than
	// the maximum.
	limit int64

	visited int64
	skipped int64
	hits    []fsx.Entry
	// hitBytes is what the hits collected so far will weigh on the wire,
	// against searchResultBytesCap.
	hitBytes int64

	// since counts entries since the last clock reading (searchTimeCheck).
	since int
	// stop names the bound that ended the walk, empty while it is running.
	stop string
	// current is the directory being scanned, for the progress frames.
	current string
}

func newSearch(r fsx.Root, plat *platform.Platform, req wproto.SearchReq, emit Emit) (*searcher, error) {
	if req.Query == "" {
		return nil, fmt.Errorf("a search needs something to look for: %w", fsx.ErrBadName)
	}
	if req.Glob {
		// A malformed pattern is refused BEFORE the walk. path.Match reports
		// ErrBadPattern only when it reaches the bad syntax, so a pattern like
		// "[" would otherwise match nothing at all for four million entries and
		// report a clean, empty result.
		if _, err := path.Match(req.Query, ""); err != nil {
			return nil, fmt.Errorf("%q is not a usable pattern: %v: %w", req.Query, err, fsx.ErrBadName)
		}
	}
	switch req.Kind {
	case "", "any", "file", "dir":
	default:
		return nil, fmt.Errorf("%q is not a kind a search can filter by: %w", req.Kind, fsx.ErrBadName)
	}
	s := &searcher{
		r:      r,
		plat:   plat,
		emit:   emit,
		query:  req.Query,
		glob:   req.Glob,
		hidden: req.Hidden,
		kind:   req.Kind,
		opts:   WalkOptions{CrossMounts: req.CrossMounts, Protect: ProtectSnapshots},
	}
	s.maxHits = clampInt(req.MaxHits, searchMaxHits)
	s.maxVisited = clampInt64(req.MaxVisited, searchMaxVisited)
	s.limit = clampInt64(req.MaxDuration, searchMaxSeconds)
	if s.limit > 0 {
		s.deadline = searchClock().Add(time.Duration(s.limit) * time.Second)
	}
	return s, nil
}

// clampInt applies "the route sends the cap and the worker clamps to the
// maximum": a value outside (0, max] becomes max, so a request that forgot the
// cap or asked for more than the maximum gets the maximum.
func clampInt(v, max int) int {
	if v <= 0 || v > max {
		return max
	}
	return v
}

func clampInt64(v int64, max int64) int64 {
	if v <= 0 || v > max {
		return max
	}
	return v
}

// root searches one selected path.
//
// The path is resolved as the caller — an O_PATH walk, so a component the user
// cannot search is the kernel's own EACCES (INV-2) — and it must be a
// directory: "search this file" has no meaning, and answering it by matching
// the file's own name would be a different feature wearing this one's name.
func (s *searcher) root(ctx context.Context, apiPath string) error {
	clean, err := fsx.Clean(apiPath)
	if err != nil {
		return err
	}
	// BEFORE resolve, because resolving is the dangerous act: a root inside a
	// hard NFS mount whose server has gone parks this goroutine inside an lstat
	// that no deadline can interrupt (round 2 adversarial, finding 2). The
	// mount table answers by name and makes no syscall at all.
	if err := refuseRootPath(s.r, s.plat, clean, s.opts.Protect); err != nil {
		return err
	}
	// NOT resolve(): the route sends the spelling its own guarded resolution
	// produced, and resolving it again here would follow whatever the tree says
	// now (round 14 adversarial). The walk below follows nothing and refuses a
	// symlink anywhere on the path, leaf included — a search root is a directory
	// the guard cleared, not a link of that name.
	tg, err := canonicalTarget(s.r, clean)
	if err != nil {
		return err
	}
	// The root is OPENED once and everything is decided on that descriptor —
	// is it a directory, may it be searched — and the walk then starts from it
	// (round 14). The shape this replaces was an lstat by name followed by a
	// Walk that resolved the same name all over again: two lookups with a gap
	// between them, so a directory renamed away and replaced in the gap was
	// checked in one place and searched in another. walkFrom takes the
	// descriptor that was checked and never names it again.
	// openCanonicalDir proves every component; what comes back is a dirfd-only
	// O_PATH handle, and enumerating needs a readable one — which is asked for
	// on that descriptor rather than by naming the directory again.
	proved, err := openCanonicalDir(tg.jail, tg.rel, clean)
	if err != nil {
		return err
	}
	fi, err := proved.stat()
	if err != nil {
		proved.close()
		return err
	}
	if !fi.IsDir() {
		proved.close()
		return fmt.Errorf("%q is not a directory, so there is nothing under it to search: %w", clean, fsx.ErrBadName)
	}
	readable, err := enumerable(proved)
	proved.close()
	if err != nil {
		return err
	}
	held := dirRefFrom(tg.jail, readable, tg.rel)
	// The refusals the walker makes for every child, made for the root as well
	// (adversarial finding 4): a ".zfs" component on either spelling, and a
	// mount nothing here traverses.
	if err := refuseRoot(s.r, s.plat, clean, tg.api, s.opts.Protect); err != nil {
		held.close()
		return err
	}
	s.current = tg.api

	v := Visitor{
		Pre:  func(it WalkItem) error { return s.visit(it) },
		Warn: func(apiPath string, err error) { s.warn(apiPath, err) },
	}
	// walkFrom CONSUMES the descriptor on every path, including the ones that
	// end early.
	return walkFrom(ctx, s.r, s.plat, held, tg.api, fi, s.opts, v)
}

// visit is one entry: counted, filtered, matched, and checked against the three
// bounds — in that order, so that the count a truncated search reports is the
// number of entries it really looked at.
//
// The root of a walk (depth 0) is the folder being searched rather than
// something found in it, so it is neither counted nor matched. Searching
// /share/Public for "public" is a request for what is INSIDE it.
func (s *searcher) visit(it WalkItem) error {
	if it.Depth == 0 {
		return nil
	}
	// Hidden entries are not MATCHED, and a hidden directory is not descended
	// into — "include hidden" is one switch, and a listing that hides .cache has
	// no business searching a hundred thousand files inside it.
	//
	// They are still COUNTED, and the bounds are still checked for them. The
	// order used to be the other way round, and it was a hole rather than an
	// inefficiency: an excluded dot-entry returned before `visited` was
	// incremented and before the clock was read, so a directory of a million
	// hidden files was enumerated and lstat'ed in full — at the walk's expense,
	// on the worker's time — for a search that was bounded at five hundred
	// thousand entries and sixty seconds (M2-C review round 1, finding 4). Every
	// entry the walk touches costs the same syscalls whether or not it can
	// become a hit, so every entry counts against the bounds.
	skipHidden := !s.hidden && strings.HasPrefix(it.Name, ".")

	s.visited++
	if it.isDir() {
		s.current = it.Path
	}
	s.emit.prog(wproto.Prog{
		Files: s.visited,
		// -1 rather than 0: a search has no denominator and never will, and a
		// UI that saw a zero total would draw a full bar (§3.2).
		FilesTotal: -1,
		Current:    []byte(s.current),
		Phase:      wproto.PhaseScanning,
	})
	if !skipHidden && s.matches(it) {
		e := s.entry(it)
		// Weighed BEFORE it is kept, so the budget bounds what the terminal
		// frame will actually hold rather than what it held a hit ago.
		if cost := hitCost(e); s.hitBytes+cost > searchResultBytesCap {
			s.stop = fmt.Sprintf("first %d of many — results too large", len(s.hits))
			return errSearchCapped
		} else {
			s.hitBytes += cost
		}
		s.hits = append(s.hits, e)
		if len(s.hits) >= s.maxHits {
			s.stop = fmt.Sprintf("first %d of many", len(s.hits))
			return errSearchCapped
		}
	}
	if s.visited >= s.maxVisited {
		s.stop = fmt.Sprintf("stopped after %d entries", s.visited)
		return errSearchCapped
	}
	s.since++
	if !s.deadline.IsZero() && s.since >= searchTimeCheck {
		s.since = 0
		if searchClock().After(s.deadline) {
			s.stop = fmt.Sprintf("stopped after %d s", s.limit)
			return errSearchCapped
		}
	}
	// Last, so that a bound reached on this very entry ends the whole walk
	// rather than only this branch of it.
	if skipHidden && it.isDir() {
		return fs.SkipDir
	}
	return nil
}

// matches applies the kind filter and then the name test.
//
// "file" means "not a directory" rather than "a regular file": a symlink, a
// fifo and a device all appear in a listing beside the files, and a user who
// filtered a search to files meant "not folders". The distinction is visible in
// the hit's own Type, which is the lstat's.
func (s *searcher) matches(it WalkItem) bool {
	switch s.kind {
	case "dir":
		if !it.isDir() {
			return false
		}
	case "file":
		if it.isDir() {
			return false
		}
	}
	if s.glob {
		ok, err := path.Match(s.query, it.Name)
		return err == nil && ok
	}
	return foldContains(it.Name, s.query)
}

// entry builds one hit from the lstat the walk already made — the same fields
// List fills, through the same constructor, so a search result and a listing
// row describe an entry identically.
func (s *searcher) entry(it WalkItem) fsx.Entry {
	e := newEntry(it.Path, []byte(it.Name), it.Info, IDMap())
	if it.Mount {
		e.MountPoint = true
	}
	if e.IsSymlink && it.parent != nil {
		// The link's own target text, read with readlinkat through the
		// directory the walk is standing in — so the text belongs to the entry
		// that was enumerated and not to whatever answers to its name now.
		//
		// LinkResolved and TargetType are deliberately left EMPTY (M2-C review
		// round 10). Filling them means FOLLOWING the link, and a search follows
		// nothing: it would turn a read-only name match into a walk out of the
		// selected tree — possibly out of the jail — once per hit, and a
		// thousand hits would be a thousand resolutions nobody asked for. What
		// the UI can say from this is "→ target", which is the truth; what it
		// must not do is claim the link is broken because the fields it would
		// have used to say otherwise were never filled. A listing spends those
		// syscalls because a user opened that one folder; a search does not,
		// and the Properties dialog resolves a link when somebody asks for it.
		if target, err := readlinkIn(it.parent, it.Name); err == nil {
			e.SetLinkTarget([]byte(target))
		}
	}
	return e
}

// warn records a directory the walk could not read: counted in Skipped and
// reported once, exactly as a size job reports it.
func (s *searcher) warn(apiPath string, err error) {
	s.skipped++
	s.emit.warnErr(apiPath, err)
}

func (s *searcher) result() wproto.JobResult {
	res := wproto.JobResult{
		Files:   s.visited,
		Skipped: s.skipped,
		Hits:    s.hits,
		Detail:  s.stop,
	}
	return res
}

// foldContains reports whether substr occurs in s under Unicode SIMPLE case
// folding — the same rule strings.EqualFold applies, applied at every rune
// boundary of s.
//
// Simple folding is stated rather than assumed, because the difference shows
// up in real filenames. It relates single runes to single runes: "K" matches
// "k" and the Kelvin sign, "Σ" matches "σ" and the final "ς", and "ß" matches
// the capital "ẞ". It does NOT expand one rune into several, so "straße" does
// not match a query of "STRASSE" — that is FULL folding, which Go's standard
// library does not implement and which would also make the match length
// different from the query length. A user looking for "strasse" in a folder of
// German filenames finds "Strasse" and not "Straße"; the alternative is
// carrying a folding table of our own, which is not a thing a file manager
// should be maintaining.
//
// The scan is over rune boundaries of s rather than bytes, so an invalid UTF-8
// filename — which Linux allows and this app carries verbatim — advances one
// byte at a time through RuneError rather than looping.
func foldContains(s, substr string) bool {
	if substr == "" {
		return true
	}
	for i := 0; i < len(s); {
		if foldHasPrefix(s[i:], substr) {
			return true
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		if size <= 0 {
			break
		}
		i += size
	}
	return false
}

// foldHasPrefix is strings.EqualFold's comparison, stopping when the pattern
// runs out instead of when both do.
func foldHasPrefix(s, prefix string) bool {
	for len(prefix) > 0 {
		if len(s) == 0 {
			return false
		}
		sr, ssize := utf8.DecodeRuneInString(s)
		pr, psize := utf8.DecodeRuneInString(prefix)
		if ssize <= 0 || psize <= 0 {
			return false
		}
		s, prefix = s[ssize:], prefix[psize:]
		if sr == pr {
			continue
		}
		if !foldEqual(sr, pr) {
			return false
		}
	}
	return true
}

// foldEqual reports whether two runes are the same under simple folding. It is
// the orbit walk strings.EqualFold makes: SimpleFold visits every rune that
// folds to the same value, in increasing order and wrapping round.
func foldEqual(a, b rune) bool {
	if a == b {
		return true
	}
	if b < a {
		a, b = b, a
	}
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
		if r > b {
			return false
		}
	}
	return false
}
