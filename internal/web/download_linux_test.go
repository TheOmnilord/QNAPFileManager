package web

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestDownloadRawDescriptorCancellation(t *testing.T) {
	var fds [2]int
	if err := syscall.Pipe2(fds[:], syscall.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	// Match a blocking descriptor received from the worker via SCM_RIGHTS.
	r := os.NewFile(uintptr(fds[0]), "raw pipe reader")
	w := os.NewFile(uintptr(fds[1]), "raw pipe writer")
	testDownloadStreamCancellation(t, r, w)
}

func TestPseudoFilesystemClassifier(t *testing.T) {
	for _, tc := range []struct {
		name  string
		magic int64
		want  bool
	}{
		{"procfs", 0x9fa0, true},
		{"sysfs", 0x62656572, true},
		{"debugfs", 0x64626720, true},
		{"tracefs", 0x74726163, true},
		{"cgroup2", 0x63677270, true},
		{"bpf", 0xcafe4a11, true},
		{"securityfs", 0x73636673, true},
		{"configfs", 0x62656570, true},
		{"efivarfs", 0xde5e81e4, true},
		{"ext4", 0xef53, false},
		{"tmpfs", 0x01021994, false},
		{"zfs", 0x2fc12fc1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := pseudoFilesystemWithStatfs(123, func(fd int, st *syscall.Statfs_t) error {
				if fd != 123 {
					t.Fatalf("statfs descriptor = %d", fd)
				}
				st.Type = tc.magic
				return nil
			})
			if got != tc.want {
				t.Fatalf("classifier = %v, want %v", got, tc.want)
			}
		})
	}
	if !pseudoFilesystemWithStatfs(123, func(int, *syscall.Statfs_t) error { return fmt.Errorf("statfs failed") }) {
		t.Fatal("unknown filesystem must stream")
	}
}
