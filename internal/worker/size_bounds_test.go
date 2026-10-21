package worker

import (
	"math"
	"testing"
	"time"

	"taproot/internal/fsops"
	"taproot/internal/wproto"
)

// TestSizeOptionsCarryTheBounds is stabilization contract §2.1 at the worker:
// both of a measurement's bounds reach fsops as the caller sent them, the time
// bound turned from whole seconds into a duration — clamped, never wrapped,
// when the count of seconds is more than a duration can hold.
func TestSizeOptionsCarryTheBounds(t *testing.T) {
	const largest = int64(math.MaxInt64 / time.Second)
	cases := []struct {
		name string
		in   wproto.SizeReq
		want fsops.SizeOptions
	}{
		{"the folder-size route's bounds",
			wproto.SizeReq{CrossMounts: true, ReadCross: true, MaxEntries: 10_000_000, MaxDuration: 600},
			fsops.SizeOptions{CrossMounts: true, ReadCross: true, MaxEntries: 10_000_000, MaxDuration: 10 * time.Minute}},
		{"a pre-scan's entry budget alone",
			wproto.SizeReq{MaxEntries: 500_000},
			fsops.SizeOptions{MaxEntries: 500_000}},
		{"no bounds", wproto.SizeReq{}, fsops.SizeOptions{}},
		{"a negative duration is no bound", wproto.SizeReq{MaxDuration: -5}, fsops.SizeOptions{}},
		{"the largest duration that fits",
			wproto.SizeReq{MaxDuration: largest},
			fsops.SizeOptions{MaxDuration: time.Duration(largest) * time.Second}},
		{"one second more clamps instead of wrapping",
			wproto.SizeReq{MaxDuration: largest + 1},
			fsops.SizeOptions{MaxDuration: math.MaxInt64}},
		{"the largest count of seconds clamps instead of wrapping",
			wproto.SizeReq{MaxDuration: math.MaxInt64},
			fsops.SizeOptions{MaxDuration: math.MaxInt64}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sizeOptions(tc.in)
			if got != tc.want {
				t.Fatalf("sizeOptions(%+v) = %+v, want %+v", tc.in, got, tc.want)
			}
			if tc.in.MaxDuration > 0 && got.MaxDuration <= 0 {
				t.Fatalf("a bound of %d s became %v, which fsops reads as no bound at all", tc.in.MaxDuration, got.MaxDuration)
			}
		})
	}
}

// TestJobSizeStopsAtItsTimeBound is the time bound driven through the
// worker's own session, end to end: MaxDuration in seconds on the wire, the
// conversion, the walk's deadline. It ends like the entry bound below — an OK
// terminal frame, Capped set, not Cancelled — which is what the front-end
// records as a DONE job whose result says capped, and what the dialog renders
// as "At least …" (stabilization contract §2.1, §3.8). An err frame would be a
// failed job and a Cancelled result a cancelled one, and neither shows the
// floor the walk did count.
//
// The pipe is unbuffered, so the walk's first progress frame parks the walk
// until the test reads it. Holding that frame for longer than the one-second
// bound is a walk that has spent its time with nearly all of the tree still
// ahead, with no race against a fast disk. The one assumption is that the
// worker starts the walk — and its clock — within a second and a half of
// taking the job frame; a scheduler that stalls it for longer would let the
// bound expire later than the test reads, and the walk finish uncapped.
func TestJobSizeStopsAtItsTimeBound(t *testing.T) {
	const files = 400 // well past the items the walk counts between clock readings
	base := manyFiles(t, files)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 61, wproto.OpJob, wproto.JobReq{
		JobID: "job-timed",
		Kind:  wproto.JobSize,
		Body:  mustJSON(t, wproto.SizeReq{Paths: [][]byte{[]byte("/many")}, MaxDuration: 1}),
	})
	time.Sleep(2500 * time.Millisecond) // the walk waits on its first frame meanwhile
	res := readJob(t, tr, 61).result(t)
	if !res.Capped || res.Cancelled {
		t.Fatalf("result = %+v, want Capped and not Cancelled", res)
	}
	if got := res.Files + res.Dirs; got <= 0 || got > files {
		t.Fatalf("counted %d of %d items, want the walk stopped part-way by its time bound", got, files+1)
	}
	capped := false
	for _, w := range res.Warns {
		capped = capped || w.Code == "capped"
	}
	if !capped {
		t.Fatalf("warnings %+v, want the capped walk folded into the result", res.Warns)
	}
}

// TestJobSizeAnswersCappedAtItsBound: the bounds travel the whole way — over
// the wire, through the job dispatch and into the walk — and a walk that
// reaches one answers an OK terminal frame with Capped set, the counts so far
// and the folded "capped" warning. Not an error, and not a cancellation.
func TestJobSizeAnswersCappedAtItsBound(t *testing.T) {
	base := manyFiles(t, 50)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 51, wproto.OpJob, wproto.JobReq{
		JobID: "job-bounded",
		Kind:  wproto.JobSize,
		Body:  mustJSON(t, wproto.SizeReq{Paths: [][]byte{[]byte("/many")}, MaxEntries: 10, MaxDuration: 600}),
	})
	res := readJob(t, tr, 51).result(t)
	if !res.Capped || res.Cancelled {
		t.Fatalf("result = %+v, want Capped and not Cancelled", res)
	}
	if got := res.Files + res.Dirs; got != 10 {
		t.Fatalf("counted %d items, want the walk stopped at its bound of 10", got)
	}
	capped := false
	for _, w := range res.Warns {
		capped = capped || w.Code == "capped"
	}
	if !capped || res.Warnings == 0 {
		t.Fatalf("warnings = %d %+v, want the capped walk folded into the result", res.Warnings, res.Warns)
	}
}
