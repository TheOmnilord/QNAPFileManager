package workerpool

import (
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/wproto"
)

// TestEveryWorkerCodeIsReassembled is the pool's half of the M3 code-coverage
// contract (m3-contract §9).
//
// A worker puts a failure on the wire as a CODE, and the pool rebuilds an error
// from that code alone. When RemoteError.Unwrap has no case for one, fsx.Code of
// the rebuilt error is "internal" — a 500 on the real NAS, and a pass in every
// in-process test, because in-process the original sentinel never went through a
// socket at all. The M2-C loop found that gap three separate times
// (owner_unset, too_large, changed) and the M3 loop found a fourth (conflict),
// which is why the list of codes is a table in fsx and both sides assert against
// it: this test, and internal/web's over statusCode.
func TestEveryWorkerCodeIsReassembled(t *testing.T) {
	if len(fsx.WorkerCodes) == 0 {
		t.Fatal("fsx.WorkerCodes is empty")
	}
	for _, code := range fsx.WorkerCodes {
		t.Run(code, func(t *testing.T) {
			// Exactly what the pool does with an err frame off the wire.
			err := remoteError(&wproto.Err{Code: code, Message: "from a worker"})
			if err == nil {
				t.Fatal("remoteError returned nothing")
			}
			re, ok := err.(*RemoteError)
			if !ok {
				t.Fatalf("remoteError gave %T", err)
			}
			if re.Unwrap() == nil {
				t.Fatalf("RemoteError.Unwrap has no sentinel for %q, so the front-end will call it \"internal\" "+
					"and answer 500 on the NAS while every in-process test passes", code)
			}
			if got := fsx.Code(err); got != code {
				t.Fatalf("a %q from a worker comes back as %q", code, got)
			}
		})
	}
}

// TestWorkerCodesCoversWhatTheVocabularyHas guards the table itself: a code that
// exists in the app's vocabulary and is missing from WorkerCodes would make the
// test above pass by not looking. The three exclusions are deliberate and are
// asserted here so that removing one from the doc comment does not quietly
// remove it from the check.
func TestWorkerCodesCoversWhatTheVocabularyHas(t *testing.T) {
	have := map[string]bool{}
	for _, c := range fsx.WorkerCodes {
		if have[c] {
			t.Fatalf("%q appears twice in fsx.WorkerCodes", c)
		}
		have[c] = true
	}
	// The front-end guard's and the session layer's own refusals, made before
	// the RPC: no worker can emit them (INV-1).
	for _, c := range []string{"ramdisk", "confirm_required", "unauthorized", "internal"} {
		if have[c] {
			t.Fatalf("%q is not a code a worker can emit; see the doc comment on fsx.WorkerCodes", c)
		}
	}
	// Every code M3 can produce, named explicitly rather than inferred, because
	// the point of the table is that somebody has to look.
	for _, c := range []string{"changed", "unsupported", "permission", "protected", "readonly", "bad_request",
		"not_found", "cancelled", "too_large"} {
		if !have[c] {
			t.Fatalf("%q is missing from fsx.WorkerCodes", c)
		}
	}
}
