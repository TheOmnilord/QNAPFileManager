package wproto

import (
	"bytes"
	"encoding/json"
	"testing"

	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/perm"
)

// TestChmodReqCarriesAMaskAndAValue pins the one property the whole permissions
// feature rests on (m3-contract §1.1): the wire carries a CHANGE, not an
// absolute mode. A ChmodReq that had gone back to a bare mode would silently
// turn a mixed selection into "set every entry to this", which is the bug the
// mask exists to make impossible.
func TestChmodReqCarriesAMaskAndAValue(t *testing.T) {
	req := ChmodReq{Path: []byte("/share/\xff/f"), Spec: perm.ModeSpec{Mask: 0o7777, Value: 0o2755}}
	f, err := NewReq(1, OpChmod, req)
	if err != nil {
		t.Fatal(err)
	}
	var back ChmodReq
	if err := f.Unmarshal(&back); err != nil {
		t.Fatal(err)
	}
	if string(back.Path) != string(req.Path) {
		t.Fatalf("a non-UTF-8 path did not survive: %q", back.Path)
	}
	if back.Spec != req.Spec {
		t.Fatalf("spec = %+v, want %+v", back.Spec, req.Spec)
	}
	if back.Spec.Apply(0o0644) != 0o2755 {
		t.Fatalf("the decoded spec applies to %s", perm.Octal(back.Spec.Apply(0o0644)))
	}
}

// TestModeRespCarriesBeforeEntryAndDiffs is §3.1: the reply carries the pre-call
// state of the same inode, because the worker is the only side that holds it.
func TestModeRespCarriesBeforeEntryAndDiffs(t *testing.T) {
	resp := ModeResp{
		Before: fsx.Entry{Name: "f", Mode: "2755", UID: 1000, GID: 100},
		Entry:  fsx.Entry{Name: "f", Mode: "0755", UID: 1000, GID: 100},
		Diffs: []perm.Diff{
			{Field: perm.FieldMode, Want: "2755", Got: "0755"},
			{Field: perm.FieldSetgid, Want: "on", Got: "off"},
		},
	}
	f, err := NewOK(2, resp)
	if err != nil {
		t.Fatal(err)
	}
	var back ModeResp
	if err := f.Unmarshal(&back); err != nil {
		t.Fatal(err)
	}
	if back.Before.Mode != "2755" || back.Entry.Mode != "0755" {
		t.Fatalf("before/after = %q/%q", back.Before.Mode, back.Entry.Mode)
	}
	if len(back.Diffs) != 2 || back.Diffs[1].Field != perm.FieldSetgid {
		t.Fatalf("diffs = %+v", back.Diffs)
	}
	// An empty diff list must not travel at all: the UI shows a success toast
	// for its absence and a warning toast for its presence, so "[]" and "absent"
	// had better be the same thing on the wire.
	clean, err := json.Marshal(ModeResp{})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(clean); got != `{"b":{"name":"","path":"","type":"","size":0,"mode":"","modeStr":"","uid":0,"gid":0,"mtime":"0001-01-01T00:00:00Z","nlink":0},`+
		`"e":{"name":"","path":"","type":"","size":0,"mode":"","modeStr":"","uid":0,"gid":0,"mtime":"0001-01-01T00:00:00Z","nlink":0}}` {
		t.Fatalf("an empty ModeResp encodes as %s", got)
	}
}

// TestJobReqBodiesRoundTrip: the two specs of a recursive chmod and the two ids
// of a recursive chown survive the wire, zero mask included — "apply to folders
// only" IS a zero mask, so it must not be dropped as an empty value.
func TestJobReqBodiesRoundTrip(t *testing.T) {
	chmod := ChmodJobReq{
		Paths:       [][]byte{[]byte("/share/Public"), []byte("/share/\xfe")},
		Dirs:        perm.ModeSpec{Mask: 0o7777, Value: 0o0755},
		Recursive:   true,
		CrossMounts: true,
	}
	b, err := json.Marshal(chmod)
	if err != nil {
		t.Fatal(err)
	}
	var backChmod ChmodJobReq
	if err := json.Unmarshal(b, &backChmod); err != nil {
		t.Fatal(err)
	}
	if backChmod.Files.Touches() {
		t.Fatalf("a folders-only job grew a files spec: %+v", backChmod.Files)
	}
	if backChmod.Dirs != chmod.Dirs || len(backChmod.Paths) != 2 || string(backChmod.Paths[1]) != "/share/\xfe" {
		t.Fatalf("chmod job = %+v", backChmod)
	}

	chown := ChownJobReq{Paths: [][]byte{[]byte("/share/Public")}, UID: 1003, GID: -1, Recursive: true}
	b, err = json.Marshal(chown)
	if err != nil {
		t.Fatal(err)
	}
	var backChown ChownJobReq
	if err := json.Unmarshal(b, &backChown); err != nil {
		t.Fatal(err)
	}
	if backChown.UID != 1003 || backChown.GID != -1 {
		t.Fatalf("chown job = %+v; -1 must survive as -1, not as an omitted zero", backChown)
	}
}

// TestPropsRespRoundTrips: the properties reply is the one message forwarded to
// the client essentially as it stands, so its field names are part of the
// contract rather than an implementation detail.
func TestPropsRespRoundTrips(t *testing.T) {
	resp := PropsResp{
		Entry: fsx.Entry{Name: "f", Mode: "0644", ACL: fsx.ACLNFS4, HasACL: true},
		FS:    FSInfo{FSType: "zfs", Mount: "/share/ZFS530_DATA/Public", Domain: "zfs:zpool1", Avail: 1 << 30, Total: 1 << 40},
		ACL: ACLInfo{
			Backend: "nfs4", Xattr: "system.nfs4_acl", State: fsx.ACLNFS4,
			Aclmode: "discard", Dataset: "zpool1/vol/Public",
		},
		Identity: FSIdentityResp{Dev: 7, Ino: 42},
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	fsm, ok := m["fs"].(map[string]any)
	if !ok {
		t.Fatalf("no fs object in %s", b)
	}
	for _, k := range []string{"fsType", "mount", "domain", "avail", "total"} {
		if _, ok := fsm[k]; !ok {
			t.Fatalf("FSInfo lost %q: %v", k, fsm)
		}
	}
	aclm, ok := m["acl"].(map[string]any)
	if !ok {
		t.Fatalf("no acl object in %s", b)
	}
	for _, k := range []string{"backend", "xattr", "state", "aclmode", "dataset"} {
		if _, ok := aclm[k]; !ok {
			t.Fatalf("ACLInfo lost %q: %v", k, aclm)
		}
	}
	var back PropsResp
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Entry.ACL != fsx.ACLNFS4 || !back.Entry.HasACL {
		t.Fatalf("the badge did not survive: %+v", back.Entry)
	}
	if back.FS.Total != 1<<40 || back.Identity.Ino != 42 {
		t.Fatalf("resp = %+v", back)
	}
}

// TestM3OpsAndJobKindsExist guards the vocabulary the routes and the worker both
// switch on. A rename here is a silent "unsupported" on the NAS.
func TestM3OpsAndJobKindsExist(t *testing.T) {
	for op, want := range map[Op]string{OpChmod: "chmod", OpChown: "chown", OpProps: "props"} {
		if string(op) != want {
			t.Fatalf("op %q, want %q", op, want)
		}
	}
	if JobChmod != "chmod" || JobChown != "chown" {
		t.Fatalf("job kinds = %q/%q", JobChmod, JobChown)
	}
}

// TestChmodReqExpectIsAPrecondition is Astra round-1 finding 4 on the wire: the
// ACL state and the identity the confirmation ladder graded travel with the
// chmod, so the worker can prove on the held leaf that it is about to change the
// object the user was warned about.
//
// The nil case matters as much as the set one. A job grades nothing per entry
// and sends no precondition, and "no precondition" has to be ABSENT on the wire
// rather than a zero ACLExpect — an empty State and a zero identity would
// otherwise read as "expect an object with inode 0", which nothing matches.
func TestChmodReqExpectIsAPrecondition(t *testing.T) {
	req := ChmodReq{
		Path: []byte("/share/Public/f"),
		Spec: perm.ModeSpec{Mask: 0o7777, Value: 0o0644},
		Expect: &ACLExpect{
			State: fsx.ACLNFS4,
			Identity: FSIdentityResp{
				Dev: 66305, Ino: 4242, Btime: 1758000000000000000, HasBtime: true,
			},
		},
	}
	f, err := NewReq(7, OpChmod, req)
	if err != nil {
		t.Fatal(err)
	}
	var back ChmodReq
	if err := f.Unmarshal(&back); err != nil {
		t.Fatal(err)
	}
	if back.Expect == nil {
		t.Fatal("the precondition did not survive the wire")
	}
	if back.Expect.State != fsx.ACLNFS4 {
		t.Fatalf("expected state = %q", back.Expect.State)
	}
	if !back.Expect.Identity.SameInode(req.Expect.Identity) {
		t.Fatalf("identity = %+v, want %+v", back.Expect.Identity, req.Expect.Identity)
	}

	b, err := json.Marshal(ChmodReq{Path: []byte("/x"), Spec: perm.ModeSpec{Mask: 0o777}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`"x"`)) {
		t.Fatalf("a request with no precondition still encodes one: %s", b)
	}
}

// TestSizeReqCarriesAnEntryBudget is finding 10's half of the wire: a caller
// that measures in order to DECIDE something — the permissions pre-scan, inside
// a 15 s request — bounds the walk, and a bounded walk says when it stopped
// short. Zero stays unbounded, which is what the ordinary folder-size job asks
// for, so neither field may travel when nobody set it.
func TestSizeReqCarriesAnEntryBudget(t *testing.T) {
	f, err := NewReq(8, OpJob, SizeReq{Paths: [][]byte{[]byte("/share/Public")}, MaxEntries: 500000})
	if err != nil {
		t.Fatal(err)
	}
	var back SizeReq
	if err := f.Unmarshal(&back); err != nil {
		t.Fatal(err)
	}
	if back.MaxEntries != 500000 {
		t.Fatalf("MaxEntries = %d", back.MaxEntries)
	}

	capped, err := json.Marshal(JobResult{Files: 12, Dirs: 3, Capped: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(capped, []byte(`"cp":true`)) {
		t.Fatalf("a capped result does not say so: %s", capped)
	}
	plain, err := json.Marshal(JobResult{Files: 12})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(plain, []byte(`"cp"`)) || bytes.Contains(plain, []byte(`"me"`)) {
		t.Fatalf("an unbounded measurement carries the bound anyway: %s", plain)
	}
}
