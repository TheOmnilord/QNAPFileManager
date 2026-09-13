package fsops

import (
	"os"
	"syscall"
	"testing"
)

// M2-C review round 15: birth-time availability is its own fact, cached on its
// own, and never on the mount id's.

// TestBtimeFromStatxDecidesPerResult is the table the three kernels nobody has
// would otherwise be needed for.
//
// The case that matters is the middle one: Linux 4.11 to 5.7 has statx and
// STATX_BTIME but no STATX_MNT_ID, so the mount-id probe comes back empty while
// birth time is perfectly available. Anything that treated those as one fact
// switched the inode-reuse protection off on exactly the older ext4 systems
// that most need it.
func TestBtimeFromStatxDecidesPerResult(t *testing.T) {
	withBtime := &statxData{Mask: statxBtime}
	withBtime.Btime.Sec = 1_700_000_000
	withBtime.Btime.Nsec = 123

	// What a 4.11–5.7 kernel answers: the birth time is there, the mount id is
	// not. Both bits are asked for separately, so the reply mask carries only
	// what was available.
	noMountID := &statxData{Mask: statxBtime}
	noMountID.Btime.Sec = 42

	cases := []struct {
		name        string
		errno       syscall.Errno
		stx         *statxData
		wantBtime   int64
		wantOK      bool
		wantDisable bool
	}{
		{"an ordinary answer", 0, withBtime, 1_700_000_000*1e9 + 123, true, false},
		{"no mount id but a birth time", 0, noMountID, 42 * 1e9, true, false},
		{"a filesystem with no birth time", 0, &statxData{Mask: statxMntID}, 0, false, false},
		{"an empty reply mask", 0, &statxData{}, 0, false, false},
		{"statx itself is not implemented", syscall.ENOSYS, &statxData{}, 0, false, true},
		// EINVAL is a bad call, not a missing syscall: statx ignores unknown
		// mask bits, so it must never disable the feature for the process.
		{"a refused call", syscall.EINVAL, &statxData{}, 0, false, false},
		{"a permission failure", syscall.EACCES, &statxData{}, 0, false, false},
	}
	for _, c := range cases {
		btime, ok, disable := btimeFromStatx(c.errno, c.stx)
		if btime != c.wantBtime || ok != c.wantOK || disable != c.wantDisable {
			t.Errorf("%s: btimeFromStatx = (%d, %v, %v), want (%d, %v, %v)",
				c.name, btime, ok, disable, c.wantBtime, c.wantOK, c.wantDisable)
		}
	}
}

// TestBirthTimeIsNotKeyedOnTheMountIDFlag is the bug itself: a kernel that has
// no STATX_MNT_ID makes mountIDOf set statxNoMntID, and birth time must go on
// working regardless.
func TestBirthTimeIsNotKeyedOnTheMountIDFlag(t *testing.T) {
	dir := tempDir(t)
	// Skipped BEFORE the flag is touched, so that a filesystem with no birth
	// time skips and the bug this guards FAILS rather than skipping too.
	requireBirthTimes(t, dir)

	// What a 4.11–5.7 kernel leaves behind after the first mount-id lookup.
	prev := statxNoMntID.Load()
	statxNoMntID.Store(true)
	t.Cleanup(func() { statxNoMntID.Store(prev) })

	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var (
		btime int64
		ok    bool
	)
	if cerr := rc.Control(func(fd uintptr) { btime, ok = birthTimeOf(int(fd)) }); cerr != nil {
		t.Fatal(cerr)
	}
	if !ok || btime == 0 {
		t.Fatal("a kernel with statx but no STATX_MNT_ID must still report a birth time")
	}
}

// TestBirthTimeReachesTheIdentity: the same, one level up, so the property is
// pinned where it is actually consumed rather than only at the syscall.
func TestBirthTimeReachesTheIdentityWithoutAMountID(t *testing.T) {
	base := tempDir(t)
	requireBirthTimes(t, base)
	mkdir(t, base, "dst")
	r := newRoot(t, base)

	prev := statxNoMntID.Load()
	statxNoMntID.Store(true)
	t.Cleanup(func() { statxNoMntID.Store(prev) })

	id, err := FSIdentity(t.Context(), r, nil, "/dst")
	if err != nil {
		t.Fatal(err)
	}
	if !id.HasBtime || id.Btime == 0 {
		t.Fatalf("identity = %+v; a kernel with no mount id must still report a birth time", id)
	}
	// HasMount is deliberately not asserted: with statx's mount id disabled,
	// mountIDOf still answers from /proc/self/fdinfo on a kernel that has it, and
	// that fallback is not what this test is about. What matters is that the
	// birth time did not go with the flag.
}
