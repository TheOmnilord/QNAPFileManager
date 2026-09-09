// Package platform builds a data-driven view of the machine's mount table so
// that every file operation can ask "what are the capabilities of the
// filesystem holding this path?" instead of branching on the product name.
//
// The package is deliberately independent of every other internal package and
// uses only the standard library. It compiles on Linux (the deployment target)
// and on Windows and macOS (development), where it degrades to an empty mount
// table and a family of "unknown".
package platform

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// Mount is one line of /proc/self/mountinfo.
//
// The kernel documents the format in Documentation/filesystems/proc.txt:
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//	(1)(2) (3)   (4)   (5)      (6)      (7)   (8)  (9)   (10)         (11)
//
// Fields 7..n are optional and are terminated by a single "-" separator, which
// is why a naive field split is not enough.
type Mount struct {
	ID           int      // (1) unique mount ID
	ParentID     int      // (2) ID of the parent mount
	Major        int      // (3) major device number
	Minor        int      // (3) minor device number
	Root         string   // (4) root of the mount within the filesystem
	MountPoint   string   // (5) mount point relative to the process root
	FSType       string   // (9) filesystem type, e.g. "ext4", "zfs", "fuse.sshfs"
	Source       string   // (10) filesystem-specific source, e.g. "/dev/md1" or "zpool1/vol"
	Options      []string // (6) per-mount options
	SuperOptions []string // (11) per-superblock options
}

// Dev renders the mount's device number the way "dev:major:minor" domains do.
func (m Mount) Dev() string {
	return strconv.Itoa(m.Major) + ":" + strconv.Itoa(m.Minor)
}

// ParseMountinfo parses mountinfo-formatted data. Lines that cannot be
// understood are skipped rather than failing the whole table: /proc content
// varies between kernels and a single odd mount must not blind the app to the
// rest of the system. Only a read error from r is reported.
func ParseMountinfo(r io.Reader) ([]Mount, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Mount
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m, ok := parseMountinfoLine(line)
		if !ok {
			continue
		}
		out = append(out, m)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func parseMountinfoLine(line string) (Mount, bool) {
	f := strings.Fields(line)
	if len(f) < 10 {
		return Mount{}, false
	}
	// Locate the "-" separator that ends the optional fields.
	sep := -1
	for i := 6; i < len(f); i++ {
		if f[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || len(f) < sep+3 {
		return Mount{}, false
	}

	var m Mount
	var err error
	if m.ID, err = strconv.Atoi(f[0]); err != nil {
		return Mount{}, false
	}
	if m.ParentID, err = strconv.Atoi(f[1]); err != nil {
		return Mount{}, false
	}
	maj, min, ok := strings.Cut(f[2], ":")
	if !ok {
		return Mount{}, false
	}
	if m.Major, err = strconv.Atoi(maj); err != nil {
		return Mount{}, false
	}
	if m.Minor, err = strconv.Atoi(min); err != nil {
		return Mount{}, false
	}
	m.Root = unescapeOctal(f[3])
	m.MountPoint = unescapeOctal(f[4])
	m.Options = splitOptions(f[5])
	m.FSType = unescapeOctal(f[sep+1])
	m.Source = unescapeOctal(f[sep+2])
	if len(f) > sep+3 {
		m.SuperOptions = splitOptions(f[sep+3])
	}
	return m, true
}

func splitOptions(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, unescapeOctal(p))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// unescapeOctal decodes the kernel's \NNN octal escapes (space \040, tab \011,
// newline \012, backslash \134). A backslash that does not introduce three
// octal digits is kept verbatim.
func unescapeOctal(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' || i+3 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		d := s[i+1 : i+4]
		if !isOctal(d) {
			b.WriteByte(c)
			i++
			continue
		}
		v, err := strconv.ParseUint(d, 8, 16)
		if err != nil || v > 0xFF {
			b.WriteByte(c)
			i++
			continue
		}
		b.WriteByte(byte(v))
		i += 4
	}
	return b.String()
}

func isOctal(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return false
		}
	}
	return len(s) > 0
}
