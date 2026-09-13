package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/wproto"
)

// The portable half of the M2-C worker tests: the job dispatch, which needs no
// descriptor passing, and the refusal every fd-carrying operation owes a
// transport that cannot pass one. The round trips through a real socketpair are
// in m2c_linux_test.go.

// TestJobSearchRoundTrip is the whole of §3.2 through the worker: the caps go
// out on the wire, the hits come back on the terminal frame, and the progress
// frames carry the visited count with no denominator.
func TestJobSearchRoundTrip(t *testing.T) {
	base := jobTree(t)
	if err := os.WriteFile(filepath.Join(base, "a", "report.txt"), []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 9, wproto.OpJob, wproto.JobReq{
		JobID: "search-1",
		Kind:  wproto.JobSearch,
		Body: mustJSON(t, wproto.SearchReq{
			Roots:       [][]byte{[]byte("/a")},
			Query:       "REPORT",
			MaxHits:     1000,
			MaxVisited:  500000,
			MaxDuration: 60,
		}),
	})
	s := readJob(t, tr, 9)
	res := s.result(t)
	if len(res.Hits) != 1 || res.Hits[0].Name != "report.txt" {
		t.Fatalf("hits = %+v", res.Hits)
	}
	if res.Hits[0].Path != "/a/report.txt" {
		t.Errorf("hit path = %q", res.Hits[0].Path)
	}
	if res.Files == 0 {
		t.Error("Files must report how many entries were visited")
	}
	if len(s.progs) == 0 {
		t.Fatal("a search must report progress while it runs")
	}
	for _, p := range s.progs {
		if p.FilesTotal != -1 {
			t.Fatalf("prog = %+v, want FilesTotal -1", p)
		}
	}
}

// TestJobSearchRefusesABadRequest: the refusals fsops makes before it walks
// anything come back as classified error frames, not as empty results.
func TestJobSearchRefusesABadRequest(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	send(t, tr, 11, wproto.OpJob, wproto.JobReq{
		JobID: "search-bad",
		Kind:  wproto.JobSearch,
		Body:  mustJSON(t, wproto.SearchReq{Roots: [][]byte{[]byte("/a")}, Query: ""}),
	})
	s := readJob(t, tr, 11)
	if s.term.Kind != wproto.KindErr || s.term.Err.Code != "bad_request" {
		t.Fatalf("terminal = %+v", s.term)
	}
}

// TestFDOperationsRefuseATransportThatCannotPassOne. A worker that answered OK
// and then failed to hand over a descriptor would leave the front-end waiting
// for bytes that are never coming.
func TestFDOperationsRefuseATransportThatCannotPassOne(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	f := req(t, tr, 20, wproto.OpOpenWrite, wproto.OpenWriteReq{Dir: []byte("/a"), Name: []byte("x.txt")})
	if f.Kind != wproto.KindErr || f.Err.Code != "unsupported" {
		t.Fatalf("openwrite over a pipe = %+v", f)
	}
	f = req(t, tr, 21, wproto.OpArchive, wproto.ArchiveReq{Paths: [][]byte{[]byte("/a")}, Format: "zip"})
	if f.Kind != wproto.KindErr || f.Err.Code != "unsupported" {
		t.Fatalf("archive over a pipe = %+v", f)
	}
	// Nothing was created for either of them.
	if _, err := os.Stat(filepath.Join(base, "a", "x.txt")); !os.IsNotExist(err) {
		t.Errorf("a refused openwrite created something: %v", err)
	}
}

// TestAnOversizedReplyIsAnErrorAndNotADisconnect is round 6 adversarial.
//
// A frame above wproto.MaxFrame is refused before a single byte reaches the
// socket, so the stream is intact — that is not the corruption fatal() exists
// for. Tearing the worker down there meant one oversized result disconnected
// the user's whole session: their listing, their upload in flight, their
// archive being produced. The request that could not be answered gets an error
// frame, and everything else carries on.
func TestAnOversizedReplyIsAnErrorAndNotADisconnect(t *testing.T) {
	base := jobTree(t)
	// The dispatch hook is the only way to make a handler produce a reply too
	// big to encode: no real operation can, now that the search weighs its own
	// hits (fsops.searchResultBytesCap).
	tr, done := dialWith(t, base, Options{
		dispatch: func(ctx context.Context, f wproto.Frame) (any, error) {
			if f.Op == wproto.OpPing {
				return nil, nil
			}
			return wproto.JobResult{Detail: strings.Repeat("x", wproto.MaxFrame+1024)}, nil
		},
	})
	helloIn(t, tr, base)

	big := req(t, tr, 90, wproto.OpList, wproto.ListReq{Dir: []byte("/")})
	if big.Kind != wproto.KindErr {
		t.Fatalf("an unsendable result must come back as an error frame, got %+v", big.Kind)
	}
	if big.Err.Code != "too_large" {
		t.Fatalf("code = %q, want too_large", big.Err.Code)
	}

	// The session is still there, and still serving.
	if p := req(t, tr, 91, wproto.OpPing, nil); p.Kind != wproto.KindOK {
		t.Fatalf("the worker stopped serving after an oversized reply: %+v", p)
	}
	select {
	case err := <-done:
		t.Fatalf("the worker loop exited over an oversized reply: %v", err)
	default:
	}
}

// TestFinalizeOfAnUnknownHandleIsNotFound: an id that expired, a second
// Finalize, or a front-end bug all get the same honest answer.
func TestFinalizeOfAnUnknownHandleIsNotFound(t *testing.T) {
	base := jobTree(t)
	tr, _ := dial(t, base)
	helloIn(t, tr, base)

	f := req(t, tr, 22, wproto.OpFinalize, wproto.FinalizeReq{Tmp: []byte("deadbeefdeadbeef"), Final: []byte("x.txt")})
	if f.Kind != wproto.KindErr || f.Err.Code != "not_found" {
		t.Fatalf("finalize of an unknown handle = %+v", f)
	}
}
