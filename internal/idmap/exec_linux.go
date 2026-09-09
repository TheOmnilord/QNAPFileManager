package idmap

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// execDirs are the only directories searched for a helper. PATH is deliberately
// not consulted: the front-end runs as root and must not inherit a lookup path.
var execDirs = []string{"/usr/bin", "/bin"}

// defaultExec runs one helper with no shell, a minimal environment and no
// stdin. Only stdout is returned; the caller applies the deadline via ctx.
func defaultExec(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin := findHelper(name)
	if bin == "" {
		return nil, fmt.Errorf("%w: %s not found in %s", ErrNoHelper, name, strings.Join(execDirs, ", "))
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// findHelper returns the absolute path of a helper, or "" when absent.
func findHelper(name string) string {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return ""
	}
	for _, dir := range execDirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return ""
}
