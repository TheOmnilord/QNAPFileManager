package wproto

import (
	"encoding/json"
	"testing"
)

// TestSizeReqBoundsWireSpelling pins the two bounds of a size job on the wire
// (stabilization contract §2.1): "me" and "md", the same spellings SearchReq
// uses for its own caps, and both omitted when zero so that a measurement
// without bounds is byte-identical to what an older peer sent.
func TestSizeReqBoundsWireSpelling(t *testing.T) {
	b, err := json.Marshal(SizeReq{Paths: [][]byte{[]byte("/a")}, MaxEntries: 10_000_000, MaxDuration: 600})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"p":["L2E="],"me":10000000,"md":600}`; got != want {
		t.Fatalf("wire = %s, want %s", got, want)
	}
	b, err = json.Marshal(SizeReq{Paths: [][]byte{[]byte("/a")}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"p":["L2E="]}`; got != want {
		t.Fatalf("unbounded wire = %s, want %s", got, want)
	}
	var back SizeReq
	if err := json.Unmarshal([]byte(`{"p":["L2E="],"me":5,"md":7}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.MaxEntries != 5 || back.MaxDuration != 7 {
		t.Fatalf("decoded %+v", back)
	}
}
