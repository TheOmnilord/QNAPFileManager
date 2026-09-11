package wproto

import (
	"bytes"
	"testing"
)

// TestProgAndWarnFramesRoundTrip proves the M2 job contract's non-terminal
// frames encode and decode losslessly, keep the job's request id (the property
// the whole in-band progress design rests on, identity plan §2.5), and carry
// raw non-UTF-8 paths intact.
func TestProgAndWarnFramesRoundTrip(t *testing.T) {
	raw := []byte("/data/\xff\xfe")
	prog, err := NewProg(42, Prog{Files: 3, FilesTotal: 10, Bytes: 8 << 20, BytesTotal: -1, Current: raw, Phase: "working"})
	if err != nil {
		t.Fatal(err)
	}
	if prog.ID != 42 || prog.Kind != KindProg {
		t.Fatalf("prog frame = %+v", prog)
	}
	warn, err := NewWarn(42, Warn{Path: raw, Code: "permission", Message: "EACCES", Errno: 13})
	if err != nil {
		t.Fatal(err)
	}
	if warn.ID != 42 || warn.Kind != KindWarn {
		t.Fatalf("warn frame = %+v", warn)
	}
	for _, f := range []Frame{prog, warn} {
		var buf bytes.Buffer
		if err := Encode(&buf, f); err != nil {
			t.Fatal(err)
		}
		back, err := Decode(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if back.ID != f.ID || back.Kind != f.Kind {
			t.Fatalf("round trip changed id/kind: %+v", back)
		}
	}
	var p Prog
	if err := prog.Unmarshal(&p); err != nil {
		t.Fatal(err)
	}
	if string(p.Current) != string(raw) || p.BytesTotal != -1 || p.Phase != "working" {
		t.Fatalf("prog body = %+v", p)
	}
	var w Warn
	if err := warn.Unmarshal(&w); err != nil {
		t.Fatal(err)
	}
	if string(w.Path) != string(raw) || w.Errno != 13 || w.Code != "permission" {
		t.Fatalf("warn body = %+v", w)
	}
}

// TestJobResultFoldsWarnings pins the backstop that makes a dropped Warn frame
// harmless: the terminal result carries the count and the first WarnCap entries.
func TestJobResultFoldsWarnings(t *testing.T) {
	r := JobResult{Files: 5, Warnings: 3, Warns: []Warn{{Path: []byte("/a"), Code: "permission"}}}
	f, err := NewOK(7, r)
	if err != nil {
		t.Fatal(err)
	}
	var back JobResult
	if err := f.Unmarshal(&back); err != nil {
		t.Fatal(err)
	}
	if back.Files != 5 || back.Warnings != 3 || len(back.Warns) != 1 || string(back.Warns[0].Path) != "/a" {
		t.Fatalf("JobResult round trip = %+v", back)
	}
	if WarnCap != 100 {
		t.Fatalf("WarnCap = %d, want 100 (design §3)", WarnCap)
	}
}
