package audit

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"qnapfilemanager/internal/qnap"
)

// --- Astra r8 #5: an overflow of mirrors is not an overflow of stderr --------

// pacedMirror is a log_tool that answers one call per token, so a test can say
// exactly when the worker moves and therefore exactly when it may write a
// notice. It reports each entry on `entered` — buffered and offered rather than
// sent, so a call the test is not watching for cannot park on it.
//
// The release at the end is close(step), not a flag plus a send. `entered` is
// signalled before the call waits, so a test that has just read it cannot know
// whether the worker is already parked on step or still about to be: with a
// "free" flag stored in that gap, the worker saw it, never read step, and the
// test's last send waited for a receiver that would never come (CI run
// 35924016562, ten minutes under -race). A closed channel releases a worker
// that is parked and one that has not got there yet alike, and never blocks
// the goroutine that closes it.
type pacedMirror struct {
	step    chan struct{}
	entered chan struct{}

	mu   sync.Mutex
	msgs []string
}

func newPacedMirror() *pacedMirror {
	return &pacedMirror{step: make(chan struct{}), entered: make(chan struct{}, 256)}
}

func (p *pacedMirror) log(_ qnap.Severity, msg string) error {
	select {
	case p.entered <- struct{}{}:
	default:
	}
	<-p.step
	p.mu.Lock()
	p.msgs = append(p.msgs, msg)
	p.mu.Unlock()
	return nil
}

// A thousand milestones that could not be mirrored are a thousand atomic
// increments and ONE line of stderr.
//
// They used to be a thousand lines, written synchronously by whichever goroutine
// hit the full queue — the drain, or a durable writer holding one of the four
// slots. Stderr on the NAS is `logs/startup.log`, which the QPKG never rotates,
// so the bounded queue's overflow became unbounded disk and blocking I/O on the
// path that was already behind: the exact amplifier the bound existed to remove,
// reintroduced one line below it.
func TestSkippedMirrorsCostOneStderrNoticePerMinute(t *testing.T) {
	const burst = 1000
	l, _ := openTest(t, true)
	mirror := newPacedMirror()
	l.logFn = mirror.log
	var noticeMu sync.Mutex
	var notices []string
	l.errLog = func(msg string) { noticeMu.Lock(); notices = append(notices, msg); noticeMu.Unlock() }
	// The clock is an atomic, not a plain variable: the worker reads it and the
	// test moves it, and a seam that needs the race detector's indulgence is not
	// a seam.
	var clock atomic.Int64
	clock.Store(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC).UnixNano())
	l.mirrorClock = func() time.Time { return time.Unix(0, clock.Load()) }

	ev := Event{Op: "chown", Path: "/data/x", Phase: "result", Result: "ok"}
	// One event for the worker to be holding, so the queue behind it is the
	// test's to fill exactly.
	l.mirror(ev)
	<-mirror.entered
	for i := 0; i < mirrorDepth; i++ {
		l.mirror(ev)
	}
	for i := 0; i < burst; i++ {
		l.mirror(ev)
	}
	if drops := l.MilestoneDrops(); drops != burst {
		t.Fatalf("MilestoneDrops = %d after a full queue took %d more, want %d", drops, burst, burst)
	}
	noticeMu.Lock()
	early := len(notices)
	noticeMu.Unlock()
	if early != 0 {
		t.Fatalf("%d notices were written by the callers that were refused, want 0: %q", early, notices)
	}

	// The worker finishes its call and writes the notice for everything counted
	// while it was busy.
	mirror.step <- struct{}{}
	<-mirror.entered // it is inside the next call, so the notice is written
	noticeMu.Lock()
	got := append([]string(nil), notices...)
	noticeMu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d notices for a burst of %d, want exactly 1: %q", len(got), burst, got)
	}
	if want := fmt.Sprintf("%d milestones not mirrored to QuLog (%d total)", burst, burst); !strings.Contains(got[0], want) {
		t.Fatalf("the notice is %q, want it to carry %q", got[0], want)
	}

	// A second burst inside the same minute is counted and stays SILENT — and the
	// test has to stand inside that minute to say so (Astra r9 #3). It used to
	// advance the clock a full interval before letting the worker move again, so
	// the worker only ever reported on the far side of the window: deleting the
	// interval guard from reportMirrorDrops left the test green, and the one rule
	// it exists for was unasserted. The worker is released HERE, with more drops
	// behind it and the clock where it was, which is exactly the moment a missing
	// guard writes its second line.
	const second = 7
	l.mirror(ev) // the queue is one short of full again
	for i := 0; i < second; i++ {
		l.mirror(ev)
	}
	if drops := l.MilestoneDrops(); drops != burst+second {
		t.Fatalf("MilestoneDrops = %d, want %d", drops, burst+second)
	}
	mirror.step <- struct{}{}
	<-mirror.entered // the worker has finished a call and reported inside the minute
	noticeMu.Lock()
	got = append([]string(nil), notices...)
	noticeMu.Unlock()
	if len(got) != 1 {
		t.Fatalf("%d notices for a second burst inside the same minute, want the first one alone: %q", len(got), got)
	}

	// More still, also inside the minute, so what the next line reports is an
	// accumulation across two silent bursts rather than one.
	const third = 3
	l.mirror(ev) // full again behind the parked worker
	for i := 0; i < third; i++ {
		l.mirror(ev)
	}
	const silent = second + third
	if drops := l.MilestoneDrops(); drops != burst+silent {
		t.Fatalf("MilestoneDrops = %d, want %d", drops, burst+silent)
	}
	// A minute later it is reported, and the line carries what was dropped SINCE
	// the last one, not the running total.
	clock.Store(time.Unix(0, clock.Load()).Add(mirrorNoticeInterval).UnixNano())
	mirror.step <- struct{}{}
	<-mirror.entered
	noticeMu.Lock()
	got = append([]string(nil), notices...)
	noticeMu.Unlock()
	if len(got) != 2 {
		t.Fatalf("%d notices after the interval elapsed, want 2: %q", len(got), got)
	}
	if want := fmt.Sprintf("%d milestones not mirrored to QuLog (%d total)", silent, burst+silent); !strings.Contains(got[1], want) {
		t.Errorf("the second notice is %q, want it to carry %q", got[1], want)
	}

	// Let the rest through so Close is not waiting on a mirror the test parked.
	close(mirror.step)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Nothing new was dropped while it drained, so the shutdown's forced notice
	// has nothing to say and does not say it.
	noticeMu.Lock()
	defer noticeMu.Unlock()
	if len(notices) != 2 {
		t.Errorf("%d notices in total, want 2: %q", len(notices), notices)
	}
	if drops := l.MilestoneDrops(); drops != burst+silent {
		t.Errorf("MilestoneDrops = %d at the end, want %d — the counter must record every skip, however few lines report them", drops, burst+silent)
	}
}
