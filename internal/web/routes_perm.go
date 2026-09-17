package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/guard"
	"qnapfilemanager/internal/jobs"
	"qnapfilemanager/internal/perm"
	"qnapfilemanager/internal/platform"
	"qnapfilemanager/internal/wproto"
)

// This file wires M3 — permissions and properties — into the web layer:
// POST /api/fs/chmod, POST /api/fs/chown (one non-recursive item, synchronous),
// POST /api/jobs/chmod, POST /api/jobs/chown (everything else, as a job), and
// GET /api/fs/properties.
//
// The gates are the ones M1 established and M2 kept (routes_mutate.go): the
// guard on BOTH the requested and the resolved spelling with the stricter
// verdict, a durable audit intent before the work and a result line after it,
// then the backend — whose worker runs as the user, where the kernel makes the
// real decision (INV-2). Three things are new:
//
//   - The aclmode confirm ladder (contract §7). A confirmation cannot be
//     demanded after the change, so the decision is made HERE, before dispatch,
//     from the daemon's own mount table (platform.Platform) plus the entry's own
//     ACL state. The worker reports the same facts in Props for display, and
//     both read the same data-driven table, so they agree by construction.
//   - Two hard refusals rather than confirmations: a recursive apply rooted at /
//     or at a depth-1 path (§4.5), and a recursive chmod that SETS a special bit
//     (§1.3). Neither has a legitimate form, so neither gets a dialog.
//   - The diff. A call the kernel completed differently than asked is a 200 with
//     warnings, never an error (§3.3); a call the kernel REFUSED is the kernel's
//     error, surfaced unchanged.
//
// M3 adds no error codes: every refusal it can make already has one, and the
// code-coverage table test (perm_test.go) keeps that true.

// The confirmation grades of ui-ux §4.2, as the confirm envelope carries them.
// The guard's token machinery is grade-blind — a token is a token — so the grade
// travels beside the token in the 409 and tells the client which dialog to
// build: L1 a plain confirmation, L2 the typed-phrase one with the danger class.
const (
	gradeNone    = 0
	gradeConfirm = 1 // L1: an explicit acknowledgement
	gradeTyped   = 2 // L2: a typed phrase, danger styling
)

// The ladder's sentences (contract §7). They are pinned constants for the same
// reason permanentWarning and the transfer notices are: the wire carries no flag
// telling a guard reason from a route notice, the client renders them verbatim,
// and a reworded sentence here would silently change what a user is told about
// an ACL that is about to be destroyed.
const (
	// L1, POSIX backend, the entry has a POSIX ACL: the mode's group bits
	// become the ACL mask, so named entries may lose effective access.
	aclPosixMaskNotice = "This item has a POSIX ACL. Changing the mode rewrites the ACL mask, so named users and groups may lose effective access. The ACL itself survives."
	// L1, aclmode=groupmask.
	aclGroupmaskNotice = "This dataset uses aclmode=groupmask, so the NFSv4 ACL will be silently reduced to the group bits of the mode you set."
	// L1, aclmode=passthrough.
	aclPassthroughNotice = "This dataset uses aclmode=passthrough: the mode is set and the owner, group and everyone entries are regenerated. Other entries are kept."
	// L1, aclmode=restricted.
	aclRestrictedNotice = "This dataset uses aclmode=restricted, so the kernel may refuse this change outright. The result will say what happened."
	// L2, aclmode=discard (or unknown, which is read as discard). The dataset
	// is named because that is what an operator needs in order to check.
	aclDiscardFmt = "This item's real permissions are an NFSv4 ACL on %s. Changing the mode will DESTROY that ACL, and it cannot be restored from this app."
	// L2, the same for a job — which may reach SEVERAL datasets, so the sentence
	// names them (bounded) rather than the one root the user clicked.
	aclDiscardJobFmt = "This change reaches %s and will DESTROY the NFSv4 ACLs there. They cannot be restored from this app."
	// Appended to the L2 sentence when the aclmode could not be read at all.
	// identity-and-hero-plan §4.4 is explicit: never guess, and the pessimistic
	// reading is the only honest one.
	aclUnknownModeSuffix = " The dataset's aclmode could not be read, so it is treated as discard."
	// L1 minimum on ANY chown (contract §7, backend plan §6.5).
	chownClearsNotice = "Changing the owner clears the setuid bit, and the setgid bit when the file is group-executable. The kernel does this and it cannot be kept."
	// L2: setting setuid outside an ordinary storage location.
	setuidOutsideNormalNotice = "This sets the setuid bit on an item outside ordinary storage. A setuid program runs with its owner's privileges."
	// L2: a recursive apply over more than recursiveScaleItems entries.
	recursiveScaleFmt = "This applies to %s and cannot be undone."
	// There is no undo for a permissions job, and it is said before it starts.
	recursiveNoUndoNotice = "A permissions job cannot be undone, and cancelling one leaves the change half applied."
)

// The two token vocabularies. A sync token and a job token for the same single
// non-recursive item would otherwise be the identical descriptor, and the two
// routes do not grade such a request the same way (round-3 finding 4).
const (
	tokenKindSync = "sync"
	tokenKindJob  = "job"
)

const (
	// recursiveScaleItems is the pre-scanned count above which a recursive
	// chmod or chown is promoted to L2 (contract §7).
	recursiveScaleItems = 500
	// permScanReserve is what the pre-scan leaves of the handler's own budget for
	// everything that follows it: the audit intent's fsync, the job submission,
	// the 202. The scan is bounded by the REQUEST context (server.go gives every
	// ordinary JSON route 15 s), not by a timeout of its own — a 30 s budget under
	// a 15 s deadline is a number that can never be reached, and one that reads as
	// a promise the route cannot keep.
	permScanReserve = 2 * time.Second
	// modeScanMaxEntries is the entry budget the pre-scan hands the size walk
	// (contract §13: 500 000, as delete and size use). Without it the walk is
	// bounded by the request deadline alone, which on a tree of tens of millions
	// of entries means the whole 15 s is spent producing a number nobody gets —
	// with the bound the walk ends, says Capped, and the ladder says "unknown",
	// which is the same answer at a fraction of the cost.
	modeScanMaxEntries = 500_000
	// idsMax bounds /api/ids (contract §13).
	idsMax = 2000
	// idsQueryMax bounds the q= prefix, which is only ever a name fragment.
	idsQueryMax = 128
)

// --- the aclmode ladder (contract §7) ----------------------------------------

// aclFacts is everything the ladder reads about one path: the mount's ACL
// backend and — on ZFS — its aclmode and dataset, from the daemon's own mount
// table; plus the entry's own ACL STATE, which is per-object and therefore comes
// from the worker (contract §6.1: presence is the wrong question on ZFS).
type aclFacts struct {
	backend string // platform.ACLPosix | platform.ACLNFS4 | platform.ACLNone | ""
	aclmode string // "discard"|"groupmask"|"passthrough"|"restricted"|"" (unknown)
	dataset string // Mount.Source, for the L2 sentence
	// altDataset is the OTHER dataset a mount disagreement leaves in play (Astra
	// r4 #1). When the daemon's table and the worker's name different mounts for
	// one object, neither name is known to be the right one, and an L2 sentence
	// that spells only the daemon's would tell the user the change lands on a
	// dataset it may well not land on. Empty whenever the two sides agree, which
	// is every path a permissions JOB grades: only entryACLFacts has two sides.
	altDataset string
	// mount is the mount point the facts came from. It is not displayed; it is
	// what tells two datasets apart when the table names neither, so a crossing
	// fold counts them as two rather than collapsing them into one (round-5).
	mount string
	state string // fsx.ACL* — "" and ACLUnknown are read the same, pessimistically
	// storage says the mount holds user data (FSCaps.Storage). It is what makes
	// an EMPTY backend a fact worth warning about rather than a shrug: a storage
	// mount whose backend this daemon has not probed may be a ZFS dataset under
	// aclmode=discard, and "we have not looked" is not "there is nothing there"
	// (Astra M3 round-1 finding 1).
	storage bool
	// unknown says the daemon HAS a mount table and it could not place this
	// path in it. That is different from having no table at all — the dev box,
	// where the whole mount half of the ladder is inert by design (contract
	// §14) — and it grades pessimistically, because a path the table cannot
	// place is one whose aclmode nobody can state.
	unknown bool
}

// key identifies one dataset for de-duplication. The name is the identity when
// there is one; otherwise the mount point is, because several distinct datasets
// can be equally unnamed and the sentence's count must still be right.
func (f aclFacts) key() string {
	if f.dataset != "" {
		return "dataset:" + f.dataset
	}
	return "mount:" + f.mount
}

// datasetNames spells every dataset an L2 sentence about this path has to name.
// Normally that is the one the mount table places it on; after a mount
// disagreement it is both candidates, because the honest sentence is the one
// that covers whichever of the two tables turns out to be the current one
// (Astra r4 #1). datasetList does the counting and the bounding.
func (f aclFacts) datasetNames() []string {
	if f.altDataset == "" {
		return []string{f.dataset}
	}
	return []string{f.dataset, f.altDataset}
}

// mountFacts fills the mount-table half of aclFacts. Nothing branches on QTS vs
// hero: the question asked is always the mount table (PLAN decision 8).
//
// The lookup is the LITERAL one (Platform.ForLiteral, M2-C round 3), never For
// or MountFor. Those normalise first — a backslash becomes a separator and the
// result is Cleaned — and on Linux a backslash is an ordinary character in a
// filename, so a file literally named `danger/..\safe/file` would be graded on
// the `safe` dataset while the chmod changed the inode on `danger` (Astra M3
// round-1 finding 2). A spelling the literal table cannot place is not graded
// leniently: it is marked unknown, and unknown warns.
func (s *Server) mountFacts(apiPath string) aclFacts {
	var f aclFacts
	if s.platform == nil {
		return f
	}
	osPath := s.osPathFor(apiPath)
	caps, ok := s.platform.ForLiteral(osPath)
	if !ok {
		// A table with rows in it describes a whole filesystem — every Linux
		// mountinfo has a "/" line — so a spelling it cannot place is a spelling
		// nobody can state an aclmode for, and that warns. An EMPTY table is the
		// other thing entirely: the dev box and any build without /proc, where the
		// mount half of the ladder is inert by design (contract §14). Reading that
		// as "unknown, therefore destroy" would put a typed phrase in front of
		// every chmod on a machine that has no datasets at all.
		f.unknown = len(s.platform.Mounts()) > 0
		return f
	}
	f.backend, f.aclmode, f.storage = caps.ACLBackend, caps.ZFSAclmode, caps.Storage
	if m, ok := s.platform.MountForLiteral(osPath); ok {
		f.dataset, f.mount = m.Source, m.MountPoint
	}
	return f
}

// osPathFor spells an API path the way the daemon's mount table spells its mount
// points, which on the NAS is the identity and on a jailed dev box is the jail's
// own mapping. A path the jail cannot map is graded by its API spelling, which is
// what the table has to be asked about anyway.
func (s *Server) osPathFor(apiPath string) string {
	if mapped, err := s.Root.OS(apiPath); err == nil {
		return mapped
	}
	return apiPath
}

// ladderFacts is every dataset one root of a permissions JOB can reach, each
// with its state read pessimistically (a job cannot probe a tree it has not
// walked, §6.1).
//
// Without crossing that is the root's own mount and nothing else. WITH crossing
// it is every mount the table places below the root as well, and that is the
// whole point (round-4 finding): a hero pool is one dataset per share and often
// per sub-folder, so a walk from a passthrough parent descends into children
// whose aclmode may be discard. Grading the roots alone promised "other entries
// are kept" and then destroyed them one directory down.
//
// The table is read at issue time, so a dataset mounted afterwards is not seen —
// the same window as residual 3, and recorded beside it.
func (s *Server) ladderFacts(apiRoot string, cross bool) []aclFacts {
	root := s.mountFacts(apiRoot)
	root.state = fsx.ACLUnknown
	out := []aclFacts{root}
	if !cross || s.platform == nil {
		return out
	}
	rootOS := apiRoot
	if mapped, err := s.Root.OS(apiRoot); err == nil {
		rootOS = mapped
	}
	rootOS = slashPath(rootOS)
	for _, m := range s.platform.Mounts() {
		mp := slashPath(m.MountPoint)
		if mp == rootOS || !underRoot(mp, rootOS) {
			continue
		}
		// The literal lookup again (finding 2): a mount point is bytes the kernel
		// wrote, and For would normalise a backslash in one into a separator and
		// then answer for a mount that is not this one.
		caps, ok := s.platform.ForLiteral(m.MountPoint)
		child := aclFacts{dataset: m.Source, mount: m.MountPoint, state: fsx.ACLUnknown}
		if ok {
			child.backend, child.aclmode, child.storage = caps.ACLBackend, caps.ZFSAclmode, caps.Storage
		} else {
			child.unknown = true
		}
		out = append(out, child)
	}
	return out
}

// slashPath spells an OS path the way the mount table does, so a jailed dev box
// (whose Root.OS answers in the host's separator) compares against it correctly.
func slashPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// chmodJobLadder folds the ACL rung over every dataset a job can reach and adds
// it to the ladder. The discarding datasets are collapsed into ONE L2 sentence
// that names them (bounded), rather than one sentence per dataset, so a pool
// with forty of them still produces a dialog somebody reads.
func (s *Server) chmodJobLadder(ladder *permLadder, targets []string, cross bool) {
	var discarding []string
	seen := map[string]bool{}
	unreadableMode := false
	for _, p := range targets {
		for _, f := range s.ladderFacts(p, cross) {
			grade, notice, discards := chmodACLNotice(f)
			if !discards {
				ladder.add(grade, notice)
				continue
			}
			ladder.discards = true
			if f.aclmode == "" {
				unreadableMode = true
			}
			if key := f.key(); !seen[key] {
				seen[key] = true
				discarding = append(discarding, f.dataset)
			}
		}
	}
	if len(discarding) == 0 {
		return
	}
	sort.Strings(discarding)
	sentence := fmt.Sprintf(aclDiscardJobFmt, datasetList(discarding))
	if unreadableMode {
		sentence += aclUnknownModeSuffix
	}
	ladder.add(gradeTyped, sentence)
}

// entryACLFacts is mountFacts plus the entry's own ACL state, asked of the
// worker through Props — the one read that probes a single object's attribute
// (contract §8.1). Where the worker answered with facts of its own they win:
// it holds the descriptor, and its mount identity is the authoritative one.
//
// With one exception, which is Astra M3 round-1 finding 5: the worker's backend
// may never DOWNGRADE the daemon's. A worker runs as the user, and a user who
// cannot read the dataset root's attribute gets "none" out of its own Detect —
// letting that overwrite a known nfs4 would delete the discard warning for
// exactly the sessions least able to check. So the more pessimistic of the two
// is kept (aclBackendRank), and when the worker's answer is the one discarded,
// the STATE it read on that reading is discarded with it: a state derived from
// an ACL model this object does not use says nothing about this object, and
// unknown is where §6.1 says to land.
//
// A failure to LEARN the state is fsx.ACLUnknown, never ACLNone (§6.1): the
// pessimistic side is the half that matters, and it is the side that warns.
//
// And the worker's facts are believed only about the MOUNT the two sides agree
// this object is on (Astra r3 #8). Over the window the asynchronous refresh
// opens, a worker's table and the daemon's disagree about a dataset that has just
// appeared, and a reading taken on the enclosing share is a reading of another
// filesystem: it is carried as an observation and kept out of the grade.
//
// A disagreement discredits BOTH tables, not just the worker's (Astra r4 #1).
// Either process can be the one holding the stale row — the daemon's refresh is
// asynchronous, and a worker's platform can equally well have refreshed first —
// so "the worker is elsewhere, keep the daemon's row" quietly grades a fresh
// discard dataset with its stale passthrough parent's reassurance. Where the two
// name different mounts the grade is the worst of the two readings instead.
//
// The second return is the PRECONDITION the caller sends with the change
// (contract §8.1 as amended): the state the worker OBSERVED and the identity of
// the object it read it from, so the worker refuses `changed` if either moved
// between the grade and the chmod. It is nil when nothing was learned — the
// route then promises nothing, because a precondition built from a failed probe
// would refuse every change rather than the changed ones.
//
// Observed and GRADED are two different states and conflating them broke every
// legitimate chmod on a mount the daemon could not place (Astra r2 #1). Grading
// is pessimistic by design: an unprobed backend, or a worker reading this route
// discarded as a downgrade, both land on ACLUnknown — but the worker holds the
// object, and when it re-probes it will see exactly what it saw the first time.
// Expecting the ladder's fallback therefore asks the worker to prove a state
// nothing ever reported, and it answers `changed` for an object that never
// moved. So the expectation carries the raw reading, whether or not the grade
// was allowed to use it; an EMPTY state means "nothing was observed, prove the
// identity only" and is not a claim that the object has no ACL.
func (s *Server) entryACLFacts(ctx context.Context, who backend.Principal, apiPath string) (aclFacts, *wproto.ACLExpect) {
	f := s.mountFacts(apiPath)
	f.state = fsx.ACLUnknown
	if s.backend == nil {
		return f, nil
	}
	resp, err := s.backend.Props(ctx, who, wproto.PropsReq{Path: []byte(apiPath)})
	if err != nil {
		return f, nil
	}
	// The raw reading, kept whatever the grading decides to do with it. ACLInfo
	// is the descriptor-read answer (§8.3) and is what the worker re-probes; the
	// entry's copy is the same value under a worker that fills only the entry.
	observed := resp.ACL.State
	if observed == "" {
		observed = resp.Entry.ACL
	}
	// The identity travels exactly as Props reported it, zero included (Astra r2
	// #6). Off Linux there is no inode to report and the zero value is the honest
	// answer; the worker, seeing no inode on either side, proves the state alone.
	// Suppressing the expectation on that account would drop the ACL half with it,
	// and inventing an identity would be a proof of nothing. It is built here, once,
	// because it is the raw reading and none of the grading below may touch it.
	expect := &wproto.ACLExpect{State: observed, Identity: resp.Identity}
	// Which MOUNT the two halves are talking about, before anything they say
	// about it (Astra r3 #8). A worker is a long-lived process with a mount table
	// of its own, and the daemon's refresh is asynchronous by design (r2 #7), so
	// the two can disagree: a dataset mounted a moment ago is a row the daemon has
	// and the worker has not, and the worker then answers for the enclosing share.
	// Its probe of the new inode asks that share's question — the POSIX attribute
	// — gets ENOTSUP, and reports `posix` with state `none`, which outranks "not
	// probed" and takes the L2 warning away from the one mount nobody has looked
	// at. The identical wrong answer satisfies the precondition afterwards, so the
	// chmod goes through and the ACL is what pays for it.
	agrees, haveRow := s.workerMountAgrees(apiPath, resp)
	elsewhere := haveRow && resp.FS.Mount != "" && !agrees

	// The aclmode half is folded pessimistically FIRST, and it is folded whether or
	// not the two sides agree about the mount (Astra r4 #1 and #4). Two different
	// facts are in play and only one of them is ever checked: `resp.Identity.Mount`
	// comes from the inode the worker has just opened, while `resp.ACL.Aclmode`
	// comes from its own cached platform row. Substitute one dataset for another at
	// the same mount point — unmount `pool/a` (passthrough), mount `pool/b`
	// (discard) there, let the daemon refresh and the worker not — and the agreement
	// check passes on the fresh identity while the aclmode arriving with it is a's.
	// The reverse staleness is the same story from the other end: a discard dataset
	// mounted beneath a passthrough parent, the worker's platform refreshed first,
	// and round 3's rule threw the worker's real `discard` away as "elsewhere" and
	// kept the daemon's stale `passthrough` — L1, a promise that the other entries
	// survive, and an unchanged re-reading that satisfies the precondition after.
	//
	// So the rule is not "whose row wins" at all. The worker's aclmode may never
	// make the grade LESS severe than the daemon's, and the daemon's row is no more
	// trustworthy than the worker's once the two contradict each other: the ladder
	// states the worst of the two, in both directions. What the agreement check
	// still decides — all it decides — is whether the worker's per-object STATE may
	// be believed.
	f.aclmode = worstAclmode(f.aclmode, resp.ACL.Aclmode)
	if resp.ACL.Dataset != "" {
		switch {
		case f.dataset == "":
			// The daemon's table named none; the worker's name is the only one.
			f.dataset = resp.ACL.Dataset
		case resp.ACL.Dataset != f.dataset:
			// Two candidates and no way to tell which one the chmod lands on, so the
			// sentence names both rather than reassuring about the wrong one.
			f.altDataset = resp.ACL.Dataset
		}
	}

	// A DEMONSTRATED mismatch — the worker's descriptor is on a mount the daemon's
	// row for this path is not — leaves the path exactly where one the table cannot
	// place at all is, whatever backend the daemon's stale row happens to carry
	// (Astra r4 #5). An NFSv4 dataset under aclmode=discard mounted beneath a cached
	// POSIX parent otherwise grades on that parent: posix plus an unknown state is
	// the L1 mask notice, and the stale worker's own POSIX probe answers `none`
	// twice — once for the grade, once for the precondition — so the ACL is
	// destroyed without anybody being told that it existed. Unknown warns.
	if elsewhere {
		f.unknown = true
	}

	// The unknown-storage floor comes next. A storage mount whose backend this
	// daemon has not probed, and a path its table cannot place, both grade L2
	// (§7, round-1 finding 1) precisely because nobody has looked; and a row nobody
	// has looked at is a row a worker's claim cannot be checked against. So while
	// the floor is up the worker's reading of this object is carried on the wire as
	// an observation and kept out of the grade entirely — the pessimistic reading
	// is the only honest one, and it lasts until the daemon's own probe lands.
	if f.unknown || (f.storage && f.backend == "") {
		return f, expect
	}

	// Past the floor the two sides agree about the mount, so the worker's own
	// reading may be taken into the grade. The backend decides whether it may: a
	// reading made under an ACL model this object does not use says nothing about
	// it, and the rank rule is what tells the two apart.
	trusted := true
	if resp.ACL.Backend != "" {
		if aclBackendRank(resp.ACL.Backend) >= aclBackendRank(f.backend) {
			f.backend = resp.ACL.Backend
		} else {
			trusted = false
		}
	}
	if trusted && observed != "" {
		f.state = observed
	}
	// The STATE needs no fold of its own anywhere above: the daemon never reads an
	// object's ACL — only the worker holds the descriptor — so the daemon's side of
	// it is always ACLUnknown, and a worker reading that is not believed leaves it
	// there. Unknown is the non-trivial rung, which is the worst of the two and so
	// exactly what the rule asks for. Underneath all of it the round-3 rule stands:
	// worker facts never LIFT the floor.
	return f, expect
}

// workerMountAgrees reports whether the worker's Props answer describes the same
// mount the daemon's own table places this path on, and whether the daemon has a
// row for it at all (Astra r3 #8).
//
// The mount POINT is the comparison that always applies: both sides took it from
// a mountinfo table, and a worker whose table is a refresh behind names the
// enclosing share where the daemon names the dataset. The domain and the mount ID
// are added where each is available — the ID only on a LIVE table, because statx
// STATX_MNT_ID is mountinfo's first field for the running kernel and a static
// fixture's IDs are the fixture's (PLAN decision 15).
//
// A worker that names NO mount — the dev box, where the mount half of the ladder
// is inert by design (§14) — is not contradicting anything, and the caller reads
// the pair accordingly.
func (s *Server) workerMountAgrees(apiPath string, resp wproto.PropsResp) (agrees, haveRow bool) {
	if s.platform == nil {
		return false, false
	}
	osPath := s.osPathFor(apiPath)
	row, ok := s.platform.MountForLiteral(osPath)
	if !ok {
		return false, false
	}
	if resp.FS.Mount == "" {
		return false, true
	}
	if slashPath(resp.FS.Mount) != slashPath(row.MountPoint) {
		return false, true
	}
	if caps, ok := s.platform.ForLiteral(osPath); ok &&
		resp.FS.Domain != "" && caps.Domain != "" && resp.FS.Domain != caps.Domain {
		return false, true
	}
	if s.platform.Live() && resp.Identity.HasMount && row.ID >= 0 && resp.Identity.Mount != uint64(row.ID) {
		return false, true
	}
	return true, true
}

// aclBackendRank orders the ACL backends by how much a chmod can destroy under
// one, which is the order in which they must be believed when two sources
// disagree: nfs4 (a mode change can take the whole ACL) beats posix (it rewrites
// the mask), which beats "not probed" — and "not probed" beats "none", because
// "we did not look" is not a report that there is nothing there.
func aclBackendRank(name string) int {
	switch name {
	case platform.ACLNFS4:
		return 3
	case platform.ACLPosix:
		return 2
	case platform.ACLNone:
		return 0
	default: // "" — nothing was probed
		return 1
	}
}

// worstAclmode folds the two sides of a mount disagreement into the aclmode the
// ladder may safely state (Astra r4 #1). "discard" is the mode that destroys an
// ACL and "" is the mode nobody has read, which §7 already treats as discard;
// either of them on either side means the change may destroy an ACL, and the
// only honest way to say so while the dataset itself is in doubt is the UNKNOWN
// aclmode — the L2 discard rung with the "could not be read" suffix, naming both
// candidates. The remaining modes (passthrough, groupmask, restricted) all keep
// the other entries and all grade L1, so when both sides name one of those the
// daemon's row is kept and the grade is unchanged.
func worstAclmode(daemon, worker string) string {
	if aclmodeDestroys(daemon) || aclmodeDestroys(worker) {
		return "" // unknown: the L2 rung, with the suffix that says why
	}
	return daemon
}

// aclmodeDestroys is the pessimistic half of §7's table: the modes under which a
// chmod can take the whole ACL with it, "not read" included.
func aclmodeDestroys(mode string) bool { return mode == "" || mode == "discard" }

// maxNamedDatasets bounds how many datasets an L2 sentence spells out. A
// crossing walk can reach every dataset of a pool, and a dialog that lists forty
// of them is one nobody reads.
const maxNamedDatasets = 3

// datasetList spells the datasets an L2 sentence is about, with an honest
// stand-in when the mount table names none (residual 7: QNAP's ZFS fork may
// spell Mount.Source differently from upstream, so this is display only). The
// list is bounded; what it cannot show, it counts.
func datasetList(sources []string) string {
	named := make([]string, 0, len(sources))
	extra := 0
	for _, source := range sources {
		if source == "" {
			extra++ // a dataset the table did not name still counts
			continue
		}
		named = append(named, source)
	}
	if len(named) == 0 {
		if extra > 1 {
			return "these datasets"
		}
		return "this dataset"
	}
	word := "dataset "
	if len(named)+extra > 1 {
		word = "datasets "
	}
	if len(named) > maxNamedDatasets {
		extra += len(named) - maxNamedDatasets
		named = named[:maxNamedDatasets]
	}
	out := word + strings.Join(named, ", ")
	if extra > 0 {
		out += fmt.Sprintf(" and %d more", extra)
	}
	return out
}

// chmodACLNotice applies the contract §7 table for a chmod. It returns the
// grade, the sentence, and whether the ladder decided the ACL would be
// DISCARDED — which is one of the three conditions that force a chmod onto the
// QuLog milestone path (§11).
//
// The table is applied exactly as written. In particular ACLNFS4Trivial is not
// promoted even under aclmode=discard (there is nothing to destroy), and a
// state this daemon could not read is treated as a real ACL, because a parse or
// read failure fails towards the pessimistic side.
//
// Two rungs are the pessimistic reading of a fact this daemon does NOT have,
// which is the half Astra's round-1 review found missing:
//
//   - On a POSIX backend an UNKNOWN state is the mask notice, not silence
//     (finding 9). A job grades every entry as unknown because it cannot probe a
//     tree it has not walked, and "we did not look" is not "there is no ACL" —
//     the same change through the sync route, which does look, is L1.
//   - A storage mount whose BACKEND is empty, or a path the mount table could
//     not place at all, is the L2 discard sentence with the unknown-aclmode
//     suffix (finding 1). An empty backend is the answer for a dataset that was
//     mounted after the table was probed, and reading it as "no ACLs here"
//     silently removed the one warning that exists for destroying them.
//
// The unplaced rung is tested BEFORE the POSIX one (Astra r4 #5). A path nobody
// can place is a path whose backend nobody can state either, and the daemon's
// row for it may be the very thing that is out of date — a cached POSIX parent
// with an NFSv4 dataset mounted underneath it. Reading the stale backend first
// answered "the mask is rewritten" for a change that destroys an ACL.
func chmodACLNotice(f aclFacts) (grade int, notice string, discards bool) {
	switch {
	case f.backend == platform.ACLPosix && !f.unknown:
		switch f.state {
		case fsx.ACLPosix, fsx.ACLUnknown, "":
			return gradeConfirm, aclPosixMaskNotice, false
		}
	case f.backend == platform.ACLNFS4, f.unknown, f.storage && f.backend == "":
		switch f.state {
		case fsx.ACLNone, fsx.ACLNFS4Trivial:
			// Nothing that the mode does not already describe: normal rules.
			return gradeNone, "", false
		}
		switch f.aclmode {
		case "groupmask":
			return gradeConfirm, aclGroupmaskNotice, false
		case "passthrough":
			return gradeConfirm, aclPassthroughNotice, false
		case "restricted":
			return gradeConfirm, aclRestrictedNotice, false
		default:
			// "discard", and "" — which is READ as discard, never as
			// passthrough: when zfs get is unavailable the pessimistic
			// reading is the only honest one (identity plan §4.4). An
			// unprobed backend has no aclmode either, so it lands here with
			// the suffix, which is what it should say.
			sentence := fmt.Sprintf(aclDiscardFmt, datasetList(f.datasetNames()))
			if f.aclmode == "" {
				sentence += aclUnknownModeSuffix
			}
			return gradeTyped, sentence, true
		}
	}
	return gradeNone, "", false
}

// --- shared ladder assembly ---------------------------------------------------

// permLadder accumulates one operation's confirmation grade and the sentences
// that justify it. Sentences are de-duplicated, because the same guard reason
// reaches it from both spellings of every root.
type permLadder struct {
	grade    int
	warnings []string
	seen     map[string]bool
	// discards records that the aclmode ladder decided an ACL would be
	// destroyed — an audit milestone condition of its own (§11).
	discards bool
}

func (l *permLadder) add(grade int, sentences ...string) {
	if grade > l.grade {
		l.grade = grade
	}
	for _, sentence := range sentences {
		if sentence == "" {
			continue
		}
		if l.seen == nil {
			l.seen = map[string]bool{}
		}
		if l.seen[sentence] {
			continue
		}
		l.seen[sentence] = true
		l.warnings = append(l.warnings, sentence)
	}
}

// guardReasons folds the guard's own path-free reasons in at L2 (contract §7:
// "chmod/chown under a protected (warn-class) path → L2"). The reasons never
// contain the path itself (guard.Reasons), so a resolved spelling cannot leak
// into the summary — the M1 disclosure rule, unchanged.
func (l *permLadder) guardReasons(g *guard.Guard, op guard.Op, paths ...string) {
	if g == nil {
		return
	}
	for _, p := range paths {
		for _, reason := range g.Reasons(op, p) {
			l.add(gradeTyped, reason)
		}
	}
}

// scaleNotice adds the recursive-scale rung. scanned is the pre-scanned entry
// count, or -1 when the scan failed or was bounded — which is treated as "over
// the threshold", because an unmeasurable recursion is the one this daemon can
// say least about.
func (l *permLadder) scaleNotice(scanned int64) {
	switch {
	case scanned < 0:
		l.add(gradeTyped, fmt.Sprintf(recursiveScaleFmt, "an unknown number of items"), recursiveNoUndoNotice)
	case scanned > recursiveScaleItems:
		l.add(gradeTyped, fmt.Sprintf(recursiveScaleFmt, fmt.Sprintf("%d items", scanned)), recursiveNoUndoNotice)
	default:
		l.add(gradeNone, recursiveNoUndoNotice)
	}
}

// --- confirmation-token parts (contract §7) ----------------------------------

// permTokenParts is the ordered, structured descriptor every M3 confirmation
// token binds, in the exact order the contract fixes:
//
//	op, mask, value, dirs, uid, gid, recursive, cross, then the sorted resolved roots.
//
// Ordered (not a sorted multiset), so a token issued for 0755 cannot be redeemed
// for 4755 and one issued non-recursively cannot be redeemed recursively. Only
// the roots are sorted, so a client that reorders its own selection between the
// challenge and the re-post still redeems — the same rule as the delete and
// transfer jobs.
//
// A leading kind= part separates the sync route's descriptor from the job
// route's, which is the one addition to the contract's list (round-3 finding 4).
// Their shapes otherwise coincide exactly for a single non-recursive item, and
// the two routes do not grade it the same way: the sync route PROBES the entry's
// ACL state, while a job cannot and reads the mount pessimistically. Without the
// separation a client could take the sync route's L1 confirmation and spend it
// on the job route, which would have demanded a typed phrase.
func permTokenParts(kind, op string, files, dirs perm.ModeSpec, uid, gid int, recursive, cross bool, roots []string) []string {
	parts := []string{
		"kind=" + kind,
		"op=" + op,
		"mask=" + perm.Octal(files.Mask),
		"value=" + perm.Octal(files.Value),
		"dirs=" + perm.Octal(dirs.Mask) + "/" + perm.Octal(dirs.Value),
		"uid=" + strconv.Itoa(uid),
		"gid=" + strconv.Itoa(gid),
		"recursive=" + strconv.FormatBool(recursive),
		"cross=" + strconv.FormatBool(cross),
	}
	sorted := append([]string(nil), roots...)
	sort.Strings(sorted)
	return append(parts, sorted...)
}

// --- the post-call diff (contract §3) ----------------------------------------

// diffWarnings turns the worker's perm.Diff list into the sentences the UI shows
// verbatim. They are WARNINGS on a 200: the call succeeded and the result is not
// what was asked for, which is a different thing from a refusal.
//
// The three silent cases identity plan §3.1 names each get their own sentence;
// anything else gets an honest generic one rather than a guess.
func diffWarnings(op string, resp wproto.ModeResp, groupmask bool) []string {
	out := make([]string, 0, len(resp.Diffs))
	for _, d := range resp.Diffs {
		switch {
		case op == "chown" && (d.Field == perm.FieldSetuid || d.Field == perm.FieldSetgid) && d.Got == "off":
			out = append(out, fmt.Sprintf("The %s bit was cleared by the change of owner — the kernel does this, and it cannot be kept.", d.Field))
		case op == "chmod" && d.Field == perm.FieldSetgid && d.Got == "off":
			out = append(out, fmt.Sprintf("The setgid bit was not applied: you are not a member of group %s.", groupLabel(resp.Before)))
		case d.Field == perm.FieldMode && groupmask:
			out = append(out, fmt.Sprintf("The filesystem reduced the permissions to the group bits (aclmode=groupmask): the mode is %s, not the %s that was asked for.", d.Got, d.Want))
		case d.Field == perm.FieldMode:
			out = append(out, fmt.Sprintf("The mode is %s, not the %s that was asked for.", d.Got, d.Want))
		default:
			out = append(out, fmt.Sprintf("%s was not applied as asked: %s was requested, %s is what it is now.", d.Field, d.Want, d.Got))
		}
	}
	return out
}

// groupLabel names an entry's group for the setgid sentence: the name when the
// id resolved, and the number otherwise — the number is always honest, and the
// wire carries numbers only (§5.4).
func groupLabel(e fsx.Entry) string {
	if e.Group != "" {
		return e.Group
	}
	return strconv.Itoa(e.GID)
}

// diffDetail is the path-free audit suffix recording what the kernel did
// differently. It is bounded: a handful of fields at most, and modes and ids are
// not paths, so they may travel (§11).
func diffDetail(diffs []perm.Diff) string {
	if len(diffs) == 0 {
		return ""
	}
	const maxNamed = 6
	named := diffs
	extra := 0
	if len(named) > maxNamed {
		extra, named = len(named)-maxNamed, named[:maxNamed]
	}
	parts := make([]string, 0, len(named))
	for _, d := range named {
		parts = append(parts, fmt.Sprintf("%s %s->%s", d.Field, d.Want, d.Got))
	}
	out := " (" + strings.Join(parts, ", ")
	if extra > 0 {
		out += fmt.Sprintf(", and %d more", extra)
	}
	return out + ")"
}

// --- refusals that are not confirmations --------------------------------------

// pathDepth counts an API path's components: "/" is 0, "/etc" is 1, "/etc/x" 2.
func pathDepth(p string) int {
	p = strings.Trim(p, "/")
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}

// refuseShallowRecursion applies contract §4.5: a recursive apply rooted at /
// or at any depth-1 path is refused outright, for EVERY session including root.
// It is the one place M3 adds a hard refusal rather than a confirmation, because
// there is no recursive chmod of / that anybody means. Both spellings are
// checked: a symlink that resolves to a volume root must not slip through.
func (s *Server) refuseShallowRecursion(w http.ResponseWriter, r *http.Request, sess *session, op string, requested []string, others ...[]string) bool {
	for i, p := range requested {
		spellings := []string{p}
		for _, set := range others {
			if i < len(set) && set[i] != "" && set[i] != p {
				spellings = append(spellings, set[i])
			}
		}
		for _, spelling := range spellings {
			if pathDepth(spelling) > 1 {
				continue
			}
			m := mutation{op: op, path: p}
			s.writeAudit(sess, r, m, "result", "denied", "protected", "recursive apply refused at the top of the filesystem", false)
			writeError(w, http.StatusForbidden, "protected", "A recursive permission change cannot be applied this close to the top of the filesystem.", p, op, "")
			return true
		}
	}
	return false
}

// --- POST /api/fs/chmod --------------------------------------------------------

func (s *Server) chmod(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Path    string `json:"path"`
		PathB64 string `json:"pathB64"`
		Mask    uint32 `json:"mask"`
		Value   uint32 `json:"value"`
		Follow  bool   `json:"follow"`
		Confirm string `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	p, err := bodyPath(body.Path, body.PathB64)
	if err != nil {
		s.fail(w, r, "bad_request", "Supply the item as path or pathB64.", "", err.Error())
		return
	}
	spec := perm.ModeSpec{Mask: body.Mask, Value: body.Value}
	if !validSpec(spec) {
		s.fail(w, r, "bad_request", "Supply mask and value as mode bits (07777 at most).", p, "")
		return
	}
	if !spec.Touches() {
		s.fail(w, r, "bad_request", "The request changes no permission bits.", p, "")
		return
	}
	// A chmod acts on the NAMED entry, not on a link's target, so the leaf stays
	// literal. Resolved AS THE USER inside the worker: a component the user
	// cannot search returns the kernel's permission error here (round-3 finding 2).
	guardPath, rerr := s.resolveForGuard(r.Context(), sess.who, p, false)
	if rerr != nil {
		s.failResolve(w, r, p, rerr)
		return
	}
	// follow:true means the change lands on the LINK'S TARGET, which is a
	// different object in a different place, so the route re-guards that target
	// as a path of its own (contract §1.4). Without it a symlink in an ordinary
	// folder would be a way to chmod something the guard protects. Resolving the
	// whole path is what names it; when follow is off, target is guardPath and
	// nothing below changes.
	target := guardPath
	if body.Follow {
		resolvedTarget, terr := s.resolveForGuard(r.Context(), sess.who, p, true)
		if terr != nil {
			s.failResolve(w, r, p, terr)
			return
		}
		target = resolvedTarget
	}
	m := mutation{op: "chmod", path: p, files: 1}
	verdict := worstGuard(
		s.guard.Check(guard.OpChmod, p),
		s.guard.Check(guard.OpChmod, guardPath),
		s.guard.Check(guard.OpChmod, target),
	)
	// A refusal is answered on the guard's own terms; nothing is measured or
	// probed for an operation that is not going to happen.
	if guardRefuses(verdict) {
		s.authorize(w, r, sess, verdict, false, m, p, nil, true, body.Confirm, guard.Summary{Files: 1})
		return
	}
	var ladder permLadder
	ladder.guardReasons(s.guard, guard.OpChmod, p, guardPath, target)
	// The ACL that is about to be rewritten belongs to the object the change
	// LANDS on, which is the target whenever one was followed.
	facts, expect := s.entryACLFacts(r.Context(), sess.who, target)
	grade, notice, discards := chmodACLNotice(facts)
	ladder.add(grade, notice)
	ladder.discards = discards
	if spec.Mask&spec.Value&perm.Setuid != 0 && !s.normalClass(p, guardPath, target) {
		ladder.add(gradeTyped, setuidOutsideNormalNotice)
	}
	summary := guard.Summary{Files: 1, Warnings: ladder.warnings}
	// The token's root is the spelling the change LANDS on, so a token issued
	// without follow cannot be redeemed with it: the two name different objects,
	// and for a non-symlink — where they are the same spelling — follow changes
	// nothing at all.
	parts := permTokenParts(tokenKindSync, "chmod", spec, perm.ModeSpec{}, -1, -1, false, false, []string{target})
	extra := ladder.grade > gradeNone || body.Confirm != ""
	if !s.authorizeGraded(w, r, sess, verdict, extra, m, p, parts, true, body.Confirm, summary, ladder.grade) {
		return
	}
	milestone := permMilestone("chmod", ladder.discards, s.normalClass(p, guardPath, target), false, 0)
	asked := specDetail(spec)
	if !s.auditIntentDetail(w, r, sess, m, milestone, asked) {
		return
	}
	// Dispatch the spelling the change LANDS on — the same one the guard cleared
	// and the token is bound to (PLAN.md §2.0 residual race). With follow that is
	// the fully resolved target, which is deliberately NOT a symlink: the worker
	// walks the canonical spelling O_NOFOLLOW and refuses a symlink leaf outright
	// (contract §1.4, there being no lchmod), so handing it the link and a Follow
	// flag could only ever answer unsupported. ChmodReq.Follow therefore stays off
	// the wire; the field remains, documented inert for M3.
	//
	// The PRECONDITION travels with it (Astra M3 round-1 finding 4). The ladder
	// above graded this change on an ACL state read by pathname in a separate
	// round trip; between that read and this one the name can be re-pointed at a
	// different object, and the ACL the user was told about is then not the ACL
	// the chmod destroys. Expect carries what Props OBSERVED — that state and the
	// object's identity, never the ladder's pessimistic fallback (Astra r2 #1) —
	// and the worker re-probes its held descriptor and answers `changed` when
	// either has moved, which is exactly the refusal a symlink among the canonical
	// components already gets. When nothing was learned (no Props answer) there is
	// nothing to promise and expect is nil.
	resp, err := s.mutator.Chmod(r.Context(), sess.who, wproto.ChmodReq{Path: []byte(target), Spec: spec, Expect: expect})
	detail := asked
	if err == nil {
		detail = asked + " -> " + resp.Entry.Mode + diffDetail(resp.Diffs)
	}
	if !s.finishMode(w, r, sess, m, err, milestone, detail) {
		return
	}
	s.writeModeResp(w, "chmod", p, resp, facts.aclmode == "groupmask")
}

// validSpec rejects any bit a chmod cannot set. A caller that smuggles a file
// type (S_IFMT) or an unknown high bit through the mask gets bad_request rather
// than having it silently dropped.
func validSpec(spec perm.ModeSpec) bool {
	return spec.Mask&^perm.ModeBits == 0 && spec.Value&^perm.ModeBits == 0
}

// normalClass reports whether every spelling classifies "normal" to the guard.
// It is the stricter-of-both rule mkdir established for CreateAs, applied here
// to the two places M3 asks "is this ordinary storage?".
func (s *Server) normalClass(paths ...string) bool {
	if s.guard == nil {
		return true
	}
	for _, p := range paths {
		if s.guard.Classify(p) != "normal" {
			return false
		}
	}
	return true
}

// writeModeResp answers a completed chmod/chown. Both entries are re-stamped
// with the REQUESTED spelling before they leave: the worker answered about the
// resolved path, and a client is only ever shown paths it named itself (adv 2).
func (s *Server) writeModeResp(w http.ResponseWriter, op, requested string, resp wproto.ModeResp, groupmask bool) {
	for _, e := range []*fsx.Entry{&resp.Before, &resp.Entry} {
		e.SetName([]byte(fsx.Base(requested)))
		e.SetPath([]byte(requested))
		e.Class = s.class(requested)
	}
	warnings := diffWarnings(op, resp, groupmask)
	if resp.Diffs == nil {
		resp.Diffs = []perm.Diff{}
	}
	writeJSON(w, map[string]any{"before": resp.Before, "entry": resp.Entry, "diffs": resp.Diffs, "warnings": warnings})
}

// finishMode is finish (routes_mutate.go) with a path-free result DETAIL: what
// was asked and what landed, which is the whole point of the M3 audit line
// (§11). Everything else — the code mapping, the raw error going to the server
// log alone, the requested path in the client's error — is unchanged.
func (s *Server) finishMode(w http.ResponseWriter, r *http.Request, sess *session, m mutation, err error, milestone bool, detail string) bool {
	if err != nil {
		code := fsx.Code(err)
		s.logRaw(r, m.op, m.path, err)
		s.writeAudit(sess, r, m, "result", "error", code, detail, milestone)
		s.fail(w, r, code, backendMessage(code), m.path, "")
		return false
	}
	s.writeAudit(sess, r, m, "result", "ok", "", detail, milestone)
	return true
}

// --- POST /api/fs/chown --------------------------------------------------------

func (s *Server) chown(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.mutationsReady(w, r) {
		return
	}
	var body struct {
		Path    string `json:"path"`
		PathB64 string `json:"pathB64"`
		UID     *int   `json:"uid"`
		GID     *int   `json:"gid"`
		Confirm string `json:"confirm"`
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	p, err := bodyPath(body.Path, body.PathB64)
	if err != nil {
		s.fail(w, r, "bad_request", "Supply the item as path or pathB64.", "", err.Error())
		return
	}
	uid, gid, ok := chownIDs(body.UID, body.GID)
	if !ok {
		s.fail(w, r, "bad_request", "Supply uid, gid, or both, as numbers between 0 and 4294967294.", p, "")
		return
	}
	guardPath, rerr := s.resolveForGuard(r.Context(), sess.who, p, false)
	if rerr != nil {
		s.failResolve(w, r, p, rerr)
		return
	}
	m := mutation{op: "chown", path: p, files: 1}
	verdict := worstGuard(
		s.guard.Check(guard.OpChown, p),
		s.guard.Check(guard.OpChown, guardPath),
	)
	if guardRefuses(verdict) {
		s.authorize(w, r, sess, verdict, false, m, p, nil, true, body.Confirm, guard.Summary{Files: 1})
		return
	}
	var ladder permLadder
	ladder.guardReasons(s.guard, guard.OpChown, p, guardPath)
	// Any chown is L1 at minimum: the kernel clears setuid, and setgid on a
	// group-executable file, and neither can be kept (contract §7).
	ladder.add(gradeConfirm, chownClearsNotice)
	summary := guard.Summary{Files: 1, Warnings: ladder.warnings}
	parts := permTokenParts(tokenKindSync, "chown", perm.ModeSpec{}, perm.ModeSpec{}, uid, gid, false, false, []string{guardPath})
	if !s.authorizeGraded(w, r, sess, verdict, true, m, p, parts, true, body.Confirm, summary, ladder.grade) {
		return
	}
	// Every chown is a forced QuLog milestone, sync or recursive (§11).
	asked := fmt.Sprintf("uid=%d gid=%d", uid, gid)
	if !s.auditIntentDetail(w, r, sess, m, true, asked) {
		return
	}
	// Ownership is not CreateAs: chown IS the ownership operation, so no As
	// travels with it and an admin's chown is a plain root chown (§5.3).
	resp, err := s.mutator.Chown(r.Context(), sess.who, wproto.ChownReq{Path: []byte(guardPath), UID: uid, GID: gid})
	detail := asked
	if err == nil {
		detail = fmt.Sprintf("uid %d->%d gid %d->%d", resp.Before.UID, resp.Entry.UID, resp.Before.GID, resp.Entry.GID) + diffDetail(resp.Diffs)
	}
	if !s.finishMode(w, r, sess, m, err, true, detail) {
		return
	}
	s.writeModeResp(w, "chown", p, resp, false)
}

// maxID is the largest id a chown may name. uid_t is 32 bits and (uid_t)-1 —
// 4294967295 — is the value chown(2) reads as "leave this half alone", so it is
// not an id anybody may ASK for: the route's own sentinel for that is an absent
// field.
//
// The bound matters beyond tidiness. Everything below the wire narrows an id to
// 32 bits, so without it 4294967296 truncates to 0 and chowns the item to ROOT
// while the audit line and the confirmation token both record the number that
// was typed — a change to root that the durable record does not describe
// (round-3 finding 1).
const maxID = 0xFFFFFFFE

// chownIDs reads the two optional halves of a chown. An absent half is -1,
// which is what chown(2) means by "leave this alone"; a request that names
// neither changes nothing and is refused, and a number outside 0..maxID is
// refused rather than being narrowed into some other user's id.
func chownIDs(uid, gid *int) (int, int, bool) {
	out := [2]int{-1, -1}
	for i, v := range []*int{uid, gid} {
		if v == nil {
			continue
		}
		if *v < 0 || *v > maxID {
			return 0, 0, false
		}
		out[i] = *v
	}
	if out[0] < 0 && out[1] < 0 {
		return 0, 0, false
	}
	return out[0], out[1], true
}

// --- the recursive jobs --------------------------------------------------------

// permJob is the shared spine of POST /api/jobs/chmod and POST /api/jobs/chown:
// they differ only in the ladder rungs, the wire body and the audit milestone
// rule, so everything else — roots, the two-spelling guard, the shallow-recursion
// refusal, the pre-scan, the token, the intent line, the submission and the
// start-of-job re-check — is written once.
type permJob struct {
	op        string // "chmod" | "chown"
	kind      jobs.Kind
	wireKind  string
	files     perm.ModeSpec
	dirs      perm.ModeSpec
	uid, gid  int
	recursive bool
	cross     bool
	confirm   string
	title     string
}

func (s *Server) jobChmod(w http.ResponseWriter, r *http.Request, sess *session) {
	var body struct {
		Paths       []pathRef `json:"paths"`
		Files       specBody  `json:"files"`
		Dirs        specBody  `json:"dirs"`
		Recursive   bool      `json:"recursive"`
		CrossMounts bool      `json:"crossMounts"`
		Confirm     string    `json:"confirm"`
	}
	if !s.mutationsReady(w, r) || !s.jobsReady(w, r) {
		return
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	files, dirs := body.Files.spec(), body.Dirs.spec()
	if !validSpec(files) || !validSpec(dirs) {
		s.fail(w, r, "bad_request", "Supply mask and value as mode bits (07777 at most).", "", "")
		return
	}
	if !files.Touches() && !dirs.Touches() {
		s.fail(w, r, "bad_request", "The request changes no permission bits.", "", "")
		return
	}
	// Contract §1.3: a recursive chmod may CLEAR a special bit and may never SET
	// one. Setting setuid across a tree is the single most effective way to make
	// a NAS exploitable, and no legitimate workflow needs it in one call — so
	// this is a refusal, not a confirmation.
	if body.Recursive && (files.SetsSpecial() || dirs.SetsSpecial()) {
		s.fail(w, r, "bad_request", "A recursive change cannot SET setuid, setgid or sticky. Clearing them recursively is allowed.", "", "")
		return
	}
	paths, ok := s.jobPaths(w, r, body.Paths)
	if !ok {
		return
	}
	s.submitPermJob(w, r, sess, paths, permJob{
		op: "chmod", kind: jobs.KindChmod, wireKind: wproto.JobChmod,
		files: files, dirs: dirs, uid: -1, gid: -1,
		recursive: body.Recursive, cross: body.CrossMounts, confirm: body.Confirm,
		title: permJobTitle("Changing permissions", paths),
	})
}

func (s *Server) jobChown(w http.ResponseWriter, r *http.Request, sess *session) {
	var body struct {
		Paths       []pathRef `json:"paths"`
		UID         *int      `json:"uid"`
		GID         *int      `json:"gid"`
		Recursive   bool      `json:"recursive"`
		CrossMounts bool      `json:"crossMounts"`
		Confirm     string    `json:"confirm"`
	}
	if !s.mutationsReady(w, r) || !s.jobsReady(w, r) {
		return
	}
	if !s.decodeBody(w, r, &body) {
		return
	}
	uid, gid, ok := chownIDs(body.UID, body.GID)
	if !ok {
		s.fail(w, r, "bad_request", "Supply uid, gid, or both, as numbers between 0 and 4294967294.", "", "")
		return
	}
	paths, ok := s.jobPaths(w, r, body.Paths)
	if !ok {
		return
	}
	s.submitPermJob(w, r, sess, paths, permJob{
		op: "chown", kind: jobs.KindChown, wireKind: wproto.JobChown,
		uid: uid, gid: gid,
		recursive: body.Recursive, cross: body.CrossMounts, confirm: body.Confirm,
		title: permJobTitle("Changing owner", paths), // always a milestone (§11)
	})
}

// specBody is the {mask, value} object the two job routes carry.
type specBody struct {
	Mask  uint32 `json:"mask"`
	Value uint32 `json:"value"`
}

func (b specBody) spec() perm.ModeSpec { return perm.ModeSpec{Mask: b.Mask, Value: b.Value} }

func permJobTitle(verb string, paths []string) string {
	if len(paths) == 1 {
		return verb + ": " + clipUTF8(fsx.Base(paths[0]), maxJobTitleBytes)
	}
	return fmt.Sprintf("%s: %d items", verb, len(paths))
}

func (s *Server) submitPermJob(w http.ResponseWriter, r *http.Request, sess *session, paths []string, pj permJob) {
	who := sess.who
	guardOp := guard.OpChmod
	if pj.op == "chown" {
		guardOp = guard.OpChown
	}
	// Resolve every root's parent AS THE USER, keeping the leaf literal. A root
	// that cannot be resolved refuses the WHOLE job rather than being silently
	// dropped: a job reports one outcome, so a partially-guarded selection must
	// never be dispatched (the M2-A rule).
	//
	// A RECURSIVE root is resolved all the way through its leaf as well, and that
	// target is what gets dispatched. Every share on a QTS box is reached through
	// a symlink (/share/Public → /share/CACHEDEV1_DATA/Public — the contract's own
	// hardware check), and the worker walks the canonical spelling O_NOFOLLOW: a
	// link handed to it as a recursive root is not a tree at all. chmod would skip
	// it outright and chown would lchown the link and report success for a tree it
	// never entered, which is the worst of the two — a job that says it changed
	// what it did not. Non-recursive roots keep the leaf literal: there the named
	// entry IS the object, exactly as in the sync routes.
	resolved := make([]string, len(paths)) // leaf-literal, for the guard
	targets := make([]string, len(paths))  // what is dispatched
	checks := make([]error, 0, 3*len(paths))
	for i, p := range paths {
		rp, rerr := s.resolveForGuard(r.Context(), who, p, false)
		if rerr != nil {
			s.failResolve(w, r, p, rerr)
			return
		}
		resolved[i], targets[i] = rp, rp
		if pj.recursive {
			target, terr := s.resolveForGuard(r.Context(), who, p, true)
			if terr != nil {
				s.failResolve(w, r, p, terr)
				return
			}
			targets[i] = target
		}
		// The stricter verdict over all three spellings: resolution can reveal a
		// protected location behind an alias and can equally erase a protected
		// prefix, and with a followed root the target is a path of its own.
		checks = append(checks, s.guard.Check(guardOp, p), s.guard.Check(guardOp, rp), s.guard.Check(guardOp, targets[i]))
	}
	// Every spelling the ladder, the class checks and the re-check must consider.
	allSpellings := append(append(append([]string(nil), paths...), resolved...), targets...)
	// A RECURSIVE job reaches everything BELOW its roots, and the guard's root
	// check never names any of it: /share/CACHEDEV1_DATA/.qpkg passes OpChmod
	// while the walk underneath it reaches this daemon's own config, credential
	// and audit files — the very paths that are refused when they are named
	// (Astra M3 round-1 finding 6). Containment is the static, INV-1-safe answer
	// the transfer and upload routes already use: the prefix table, on every
	// spelling, with a deny beneath a root refusing the job exactly as naming
	// that location would, and a warn-class one asking for the typed phrase.
	var containReasons []string
	if pj.recursive && s.guard != nil {
		for _, p := range allSpellings {
			hit, ok := s.guard.Contains(p)
			if !ok {
				continue
			}
			verdict := guard.ErrConfirmRequired
			if hit.Deny {
				verdict = guard.ErrProtected
			}
			checks = append(checks, verdict)
			containReasons = append(containReasons, hit.Reason)
		}
	}
	m := mutation{op: pj.op, path: paths[0], files: int64(len(paths))}
	verdict := worstGuard(checks...)
	if guardRefuses(verdict) {
		s.authorize(w, r, sess, verdict, false, m, "", nil, true, pj.confirm, guard.Summary{Files: int64(len(paths))})
		return
	}
	// §4.5, after the guard has had its say: a refusal of ours must never
	// pre-empt read-only or a protected path (the R3-WA1 ordering rule).
	if pj.recursive && s.refuseShallowRecursion(w, r, sess, pj.op, paths, resolved, targets) {
		return
	}
	var ladder permLadder
	ladder.guardReasons(s.guard, guardOp, allSpellings...)
	// The containment reasons are the guard's own path-free ones, as everywhere,
	// and they justify the confirmation the verdict above already demanded.
	if len(containReasons) > 0 {
		ladder.add(gradeTyped, containReasons...)
	}
	if pj.op == "chown" {
		ladder.add(gradeConfirm, chownClearsNotice)
	} else {
		// A recursive or multi-item chmod cannot be told in advance which
		// entries carry a non-trivial ACL — the roots' own state says nothing
		// about the tree — so the ladder reads the MOUNT alone and treats the
		// state as unreadable, which is the pessimistic side (§6.1). On a POSIX
		// backend that adds no rung (the mask rewrite is recoverable); on an
		// NFSv4 dataset whose aclmode discards, it is exactly the L2 the
		// contract asks for.
		// Crossing is inert without recursion: a non-recursive job never descends,
		// so grading it on child datasets would promote a two-folder multi-select to
		// L2 — and to a milestone — over ACLs it will not touch (round-5 nit 1).
		s.chmodJobLadder(&ladder, targets, pj.cross && pj.recursive)
		if (pj.files.Mask&pj.files.Value&perm.Setuid != 0 || pj.dirs.Mask&pj.dirs.Value&perm.Setuid != 0) &&
			!s.normalClass(allSpellings...) {
			ladder.add(gradeTyped, setuidOutsideNormalNotice)
		}
	}
	// The token binds the spellings the work LANDS on, so a token issued for one
	// link's target cannot be redeemed once that link points somewhere else.
	parts := permTokenParts(tokenKindJob, pj.op, pj.files, pj.dirs, pj.uid, pj.gid, pj.recursive, pj.cross, targets)
	// The scale rung takes the MEASURED count, the same bounded scan delete and
	// size use, run through the user's own worker (§7, §13).
	//
	// A token that verifies carries the count measured for the challenge it came
	// with, so the re-post reads it back instead of walking the tree a second
	// time. Peek does not spend the token — authorizeGraded below still redeems
	// it — and it fails closed: a forged, expired or already-spent token simply
	// falls through to a fresh measurement and a fresh challenge, which is what
	// the client needs anyway.
	scanned := int64(0)
	if pj.recursive {
		if measured, ok := s.peekScan(pj.confirm, pj.op, parts); ok {
			scanned = measured
		} else {
			scanned = s.permScan(r.Context(), who, targets, pj.cross)
		}
		ladder.scaleNotice(scanned)
	}
	// Files is what was MEASURED, and zero when nothing was: a recursion the
	// pre-scan could not finish reports no count rather than the root count,
	// which would read as "this touches three items".
	//
	// Zero is not the whole answer, though, and Astra's round-1 finding 11 is
	// what the missing half cost: a summary of zero looked like nothing worth
	// remembering, so the ledger dropped it and the CONFIRMED re-post walked the
	// tree again — the very tree whose walk had just proved too big to finish, a
	// second time, inside a token that expires in sixty seconds. Capped records
	// the outcome itself, so the redemption inherits "unknown" and dispatches.
	files := int64(len(paths))
	capped := false
	if pj.recursive {
		files, capped = max(scanned, 0), scanned < 0
	}
	summary := guard.Summary{Files: files, Capped: capped, Warnings: ladder.warnings}
	extra := ladder.grade > gradeNone || pj.confirm != ""
	m.files = summary.Files
	if !s.authorizeGraded(w, r, sess, verdict, extra, m, "", parts, true, pj.confirm, summary, ladder.grade) {
		return
	}
	big := permMilestone(pj.op, ladder.discards, s.normalClass(allSpellings...), pj.recursive, scanned)
	id, err := jobs.NewID()
	if err != nil {
		s.fail(w, r, "internal", "The change could not be prepared.", paths[0], err.Error())
		return
	}
	what := pj.op + " " + permJobWhat(pj)
	if pj.recursive {
		what = "recursive " + what + ", " + scannedLabel(scanned) + " scanned"
	}
	if err := s.writeAudit(sess, r, m, "intent", "", "", jobIntentDetail(id, what, paths), big); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_unavailable", "The change was refused: its audit record could not be saved.", paths[0], pj.op, err.Error())
		return
	}
	resultDetail := fmt.Sprintf("job %s: %s, %d root(s)", id, what, len(paths))
	// Dispatch the spellings the work LANDS on — a followed root for a recursive
	// job, the named entry otherwise — which are the ones the guard cleared and the
	// token binds (PLAN.md §2.0 residual race).
	wire := make([][]byte, len(targets))
	for i, p := range targets {
		wire[i] = []byte(p)
	}
	var reqBody []byte
	if pj.op == "chmod" {
		reqBody, err = json.Marshal(wproto.ChmodJobReq{Paths: wire, Files: pj.files, Dirs: pj.dirs, Recursive: pj.recursive, CrossMounts: pj.cross})
	} else {
		reqBody, err = json.Marshal(wproto.ChownJobReq{Paths: wire, UID: pj.uid, GID: pj.gid, Recursive: pj.recursive, CrossMounts: pj.cross})
	}
	if err != nil {
		s.fail(w, r, "internal", "The change could not be prepared.", paths[0], err.Error())
		return
	}
	roots := mappedRoots(paths, targets)
	meta := jobs.Meta{ID: id, Src: paths, Actor: who.User, UID: who.UID,
		OnFinish: s.jobFinishHook(jobActorOf(sess, r), pj.op, id, m.path, resultDetail, big)}
	job, err := s.jobMgr.Submit(pj.kind, pj.title, meta, func(ctx context.Context, p *jobs.Progress) (any, error) {
		// W1: the queue may have held this job while read-only was switched on.
		if derr := s.recheckGuard(guardCheck{op: guardOp, paths: allSpellings}); derr != nil {
			return nil, derr
		}
		res, err := s.jobRunner.Job(ctx, who, wproto.JobReq{JobID: id, Kind: pj.wireKind, Body: reqBody}, s.progressSink(roots, p), s.warnSink(roots, pj.op, id, p))
		// W3: a cancelled permissions job still publishes what it changed —
		// there is no rollback, and the result says so.
		return viewOf(res), s.jobErr(pj.op, id, err)
	})
	if err != nil {
		s.failJobSubmit(w, r, sess, m, id, err)
		return
	}
	s.writeJob(w, *job)
}

// permMilestone applies contract §11's milestone rule.
//
// Every chown is a forced QuLog milestone, sync or recursive — "any chown"
// (backend plan §6.5), because an ownership change is the one thing an operator
// always wants to be able to find afterwards. A chmod is a milestone in exactly
// three cases: a recursion over more than a hundred items, a warn- or deny-class
// path, and a ladder that decided the ACL would be discarded. An UNMEASURABLE
// recursion (scanned < 0) counts as large, on the same pessimistic footing as
// its confirmation grade: the daemon cannot say it was small.
func permMilestone(op string, discards, ordinaryPath, recursive bool, scanned int64) bool {
	if op == "chown" {
		return true
	}
	return discards || !ordinaryPath || (recursive && (scanned < 0 || scanned >= milestoneFiles))
}

// permJobWhat is the path-free description of what a permissions job will do,
// for the durable intent line. Modes and ids are not paths, so they travel.
func permJobWhat(pj permJob) string {
	if pj.op == "chown" {
		return fmt.Sprintf("uid=%d gid=%d", pj.uid, pj.gid)
	}
	return "files " + specDetail(pj.files) + ", dirs " + specDetail(pj.dirs)
}

// specDetail renders a mode change for an audit line and a job title: what was
// asked, in the octal chmod itself states ("mask=07777 value=02755").
func specDetail(spec perm.ModeSpec) string {
	return "mask=" + perm.Octal(spec.Mask) + " value=" + perm.Octal(spec.Value)
}

func scannedLabel(scanned int64) string {
	if scanned < 0 {
		return "an unknown number of items"
	}
	return strconv.FormatInt(scanned, 10) + " item(s)"
}

// permScan measures what a recursive apply will touch, through the user's own
// worker, so the ladder's L2 threshold and the audit milestone see a real count
// (§7, §4.3). It returns -1 when the scan failed, was cancelled or was bounded:
// a minimum is not a count, and the ladder reads "unknown" as "large".
func (s *Server) permScan(ctx context.Context, who backend.Principal, roots []string, cross bool) int64 {
	// The handler context already carries the route's whole budget; the scan gets
	// all of it but permScanReserve, which is what the audit intent, the job
	// submission and the 202 still need. With no deadline at all (a fixture) it
	// simply runs under ctx. Out of budget before it starts is -1, which the
	// ladder reads as "large" — the honest answer when nothing was measured.
	scanCtx, cancel := ctx, context.CancelFunc(func() {})
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) <= permScanReserve {
			return -1
		}
		scanCtx, cancel = context.WithDeadline(ctx, deadline.Add(-permScanReserve))
	}
	defer cancel()
	// A pre-scan is a full tree walk with a job's cost and no job's limits, and
	// contract §13's "nothing in M3 needs an admission slot" overlooked it: a
	// handful of unconfirmed POSTs put an unbounded number of these on a NAS that
	// deliberately allows four metadata jobs at a time (Astra M3 round-1 finding
	// 10). So it takes the same ClassMetadata slot the recursive job it is
	// measuring for will take, waits for it under the scan's own budget, and a
	// wait that outlives that budget is -1 — the ladder's pessimistic reading —
	// rather than a request that overstays it.
	if s.jobMgr != nil {
		release, err := s.jobMgr.Admit(scanCtx, jobs.ClassMetadata)
		if err != nil {
			return -1
		}
		defer release()
	}
	var total int64
	for _, root := range roots {
		// The budget is what is LEFT of the selection's allowance, not a fresh one
		// per root (Astra r2 #8). A per-root bound is no bound at all on a
		// selection: eight roots of half a million entries each walked four million
		// and reported the sum as a measured count, so the cap that exists to keep
		// an unconfirmed POST from walking a NAS was multiplied by the number of
		// paths in the body — which the caller chooses. A root that arrives with
		// nothing left is the capped case itself and answers -1 without walking.
		remaining := modeScanMaxEntries - total
		if remaining <= 0 {
			return -1
		}
		res, err := s.transferSize(scanCtx, who, root, cross, remaining)
		// Capped is not a count: the walk stopped at the entry bound, so what it
		// carries is a minimum and the ladder must read the whole answer as
		// unknown (which it grades as large).
		if err != nil || res.Cancelled || res.Capped || res.Files < 0 || res.Dirs < 0 {
			return -1
		}
		total += res.Files + res.Dirs
		if total < 0 { // saturation: an absurd selection must not wrap the ladder
			return -1
		}
	}
	return total
}

// peekScan reads back the entry count that was measured for the challenge this
// token came with, so a redemption does not walk the tree a second time.
//
// It never spends the token — authorizeGraded still redeems it, and redemption
// is what authorises anything — and it fails closed in every direction: no
// token, a token that does not verify against these exact parts, one already
// spent, or one whose record the ledger did not keep all mean "measure it
// yourself". A count that comes back is one this daemon measured and bound to an
// unforgeable token, never one a client supplied.
func (s *Server) peekScan(token, op string, parts []string) (int64, bool) {
	if token == "" || s.guard == nil {
		return 0, false
	}
	cost, ok := s.guard.Peek(token, op, parts, true)
	if !ok {
		return 0, false
	}
	// A capped outcome is an ANSWER, and the one most worth reusing: it is the
	// tree that could not be measured inside a request, so measuring it again on
	// the re-post is the one walk guaranteed to fail twice (finding 11). It comes
	// back as -1, which is what the ladder and the milestone rule already read as
	// "large, and we cannot say how large".
	if cost.Capped {
		return -1, true
	}
	if cost.Files <= 0 {
		return 0, false
	}
	return cost.Files, true
}

// --- GET /api/fs/properties ----------------------------------------------------

// properties answers the properties dialog.
//
// Unlike the M1 read routes (PLAN.md §2.5), this one RESOLVES before it
// dispatches. fsops.Props walks the canonical spelling O_NOFOLLOW per component
// and never resolves for itself, so a symlink among the components is `changed`
// (409) — and on a real NAS every share is reached through one
// (/share/Public → /share/CACHEDEV1_DATA/Public), which would make the dialog
// answer 409 for essentially every item. The leaf stays literal: properties
// describes the NAMED entry, and `follow` is what asks the worker to fill Target
// for a link.
//
// The guard is checked on both spellings and the stricter verdict governs, the
// M2-C settlement — resolution can reveal a protected target behind an alias and
// can equally erase a protected prefix.
//
// The route adds exactly two things to what the worker returns: the capability
// HINTS (perm.CapsFor, contract §5) and the guard's classification of the path.
// Both are front-end vocabulary that has no business in a worker.
func (s *Server) properties(w http.ResponseWriter, r *http.Request, sess *session) {
	p, ok := s.path(w, r)
	if !ok {
		return
	}
	if !s.guardRead(w, r, p, guard.OpRead) {
		return
	}
	follow, err := boolQuery(r, "follow")
	if err != nil {
		s.fail(w, r, "bad_request", "Invalid follow option.", p, "")
		return
	}
	// Resolved AS THE USER inside the worker, so a component the user cannot
	// search is the kernel's permission error rather than a root-resolved path.
	// A build without a mutator (a read-only fixture) has no resolver and falls
	// back to the requested spelling, which is what it dispatched before.
	dispatch := p
	target := "" // the guarded target spelling, empty when nothing is followed
	if s.mutator != nil {
		resolved, rerr := s.resolveForGuard(r.Context(), sess.who, p, false)
		if rerr != nil {
			s.failResolve(w, r, p, rerr)
			return
		}
		dispatch = resolved
		// Checked here rather than through guardRead so the refusal names the
		// REQUESTED spelling: the verdict is about the resolved path, and that
		// spelling must never reach the client (adv 2).
		if s.guard != nil {
			if gerr := s.guard.Check(guard.OpRead, dispatch); gerr != nil {
				s.logRaw(r, "properties", p, gerr)
				s.fail(w, r, "protected", "This location is protected and cannot be read.", p, "")
				return
			}
		}
		// follow asks the worker to describe the LINK'S TARGET — its mode, owner,
		// size — which is a read of a different object in a different place, so
		// that object is guarded as a path of its own. Without it a symlink into
		// the app's config or logs would report through this route exactly what
		// the route refuses when those paths are named (guard/rules.go declares
		// them OpRead denials because one holds the break-glass password hash and
		// the other the audit trail).
		//
		// A target that cannot be resolved — a dangling link, a directory the user
		// cannot search — is not an error for the dialog (§8.1 wants Target nil,
		// not a failed dialog); it means this daemon cannot guard it, so it simply
		// is not described. Only what can be vouched for is.
		//
		// The GUARDED spelling is what travels (PropsReq.Target), not a Follow
		// flag: the worker would have to resolve the link a second time to honour
		// a flag, and the gap between the guard's check and that resolution is the
		// client's to choose — a link re-pointed inside it would be described from
		// a path the guard never saw.
		if follow {
			resolvedTarget, terr := s.resolveForGuard(r.Context(), sess.who, p, true)
			switch {
			case terr != nil:
				// Nothing to describe and nothing to guard.
			case s.guard != nil && s.guard.Check(guard.OpRead, resolvedTarget) != nil:
				s.logRaw(r, "properties", p, s.guard.Check(guard.OpRead, resolvedTarget))
				s.fail(w, r, "protected", "This location is protected and cannot be read.", p, "")
				return
			default:
				target = resolvedTarget
			}
		}
	}
	resp, err := s.backend.Props(r.Context(), sess.who, wproto.PropsReq{Path: []byte(dispatch), Target: []byte(target)})
	if err != nil {
		s.backendError(w, r, p, err)
		return
	}
	// The worker answered about the paths it walked; the client is shown the
	// spellings this daemon authorised (adv 2). The entry is the one the client
	// named; the target is the spelling the guard cleared and sent, never
	// whatever the worker's own walk happened to spell it as.
	resp.Entry.SetName([]byte(fsx.Base(p)))
	resp.Entry.SetPath([]byte(p))
	resp.Entry.Class = s.class(p)
	if resp.Target != nil && target != "" {
		resp.Target.SetName([]byte(fsx.Base(target)))
		resp.Target.SetPath([]byte(target))
		resp.Target.Class = s.class(target)
	}
	writeJSON(w, map[string]any{
		"entry":  resp.Entry,
		"target": resp.Target,
		"fs":     resp.FS,
		"acl":    resp.ACL,
		"caps":   perm.CapsFor(sess.who.UID, sess.who.Groups, sess.who.Root, resp.Entry),
		"class":  s.guardClass(p),
	})
}

// guardClass is the guard's own classification — "normal", "warn" or
// "protected" — which is what the properties dialog reports, as distinct from
// the lexical display hint s.class gives a listing row. A fixture without a
// guard falls back to that hint rather than answering nothing.
func (s *Server) guardClass(p string) string {
	if s.guard == nil {
		return s.class(p)
	}
	return s.guard.Classify(p)
}

// --- GET /api/ids ---------------------------------------------------------------

// idItem is one pickable identity: a name for the list and the NUMBER that is
// actually applied. The wire carries numbers only (§5.4) — a name resolved here
// and the same name resolved in the worker can differ (NSS vs /etc/passwd), and
// the audit has to record what was applied — so the name is display alone.
type idItem struct {
	Name string `json:"name"`
	ID   int    `json:"id"`
}

// identities answers the owner and group pickers, NARROWED (contract §10).
//
// An administrator gets the full local lists, bounded at idsMax with truncated;
// anybody else gets only their own user entry and only the groups they belong
// to, because the picker should offer exactly what the session may set and the
// full local user roster was a disclosure nobody asked for.
//
// It reads /etc/passwd and /etc/group only (internal/idmap). There is no bulk
// NSS API, and getent passwd on a domain-joined NAS is both enormous and slow,
// so a domain user does not appear here; the dialog accepts a typed numeric
// uid/gid instead and shows the number when a name does not resolve.
func (s *Server) identities(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query().Get("q")
	if len(q) > idsQueryMax {
		s.fail(w, r, "bad_request", "The search prefix is too long.", "", "")
		return
	}
	var items []idItem
	switch r.URL.Query().Get("kind") {
	case "users":
		if sess.admin {
			for _, u := range s.ids.Users() {
				items = append(items, idItem{Name: u.Name, ID: u.UID})
			}
		} else {
			items = append(items, idItem{Name: sess.who.User, ID: sess.who.UID})
		}
	case "groups":
		if sess.admin {
			for _, g := range s.ids.Groups() {
				items = append(items, idItem{Name: g.Name, ID: g.GID})
			}
		} else {
			for _, gid := range sess.who.Groups {
				items = append(items, idItem{Name: s.ids.Group(gid), ID: gid})
			}
		}
	default:
		s.fail(w, r, "bad_request", "Choose kind=users or kind=groups.", "", "")
		return
	}
	items, truncated := filterIdentities(items, q, idsMax)
	writeJSON(w, map[string]any{"items": items, "truncated": truncated})
}

// filterIdentities applies the q= prefix filter and the idsMax bound. The prefix
// matches a name case-insensitively or the decimal id, so a picker can be driven
// by either half of what it displays. truncated says the list was cut, never
// that the filter removed something.
func filterIdentities(in []idItem, q string, limit int) ([]idItem, bool) {
	out := make([]idItem, 0, min(len(in), limit))
	fold := strings.ToLower(q)
	truncated := false
	for _, item := range in {
		if q != "" && !strings.HasPrefix(strings.ToLower(item.Name), fold) && !strings.HasPrefix(strconv.Itoa(item.ID), q) {
			continue
		}
		if len(out) >= limit {
			truncated = true
			break
		}
		out = append(out, item)
	}
	return out, truncated
}
