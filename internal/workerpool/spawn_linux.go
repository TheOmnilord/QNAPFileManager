package workerpool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/wproto"
)

// spawnProcess re-executes this binary as the user (identity plan §2.4).
//
// The transport is an anonymous socketpair rather than a named unix socket:
// there is no filesystem rendezvous, so there is no path to get the permissions
// of wrong, nothing in /tmp (which on QTS is the RAM disk), no way for a second
// process to connect, and nothing to clean up after a crash.
func (p *Pool) spawnProcess(who backend.Principal) (*client, error) {
	exe := p.opts.Executable
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return nil, fmt.Errorf("finding this binary to re-execute: %w", err)
		}
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("creating the worker socketpair: %w", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "qfm-worker-parent")
	childFile := os.NewFile(uintptr(fds[1]), "qfm-worker-child")
	// The child's end must be closed in this process once it has been handed
	// over, or the worker's death never shows up as EOF here.
	defer childFile.Close()

	conn, err := net.FileConn(parentFile)
	parentFile.Close() // FileConn duplicates it
	if err != nil {
		return nil, fmt.Errorf("wrapping the worker socket: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("the worker socket came back as %T, not a unix connection", conn)
	}

	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		uc.Close()
		return nil, fmt.Errorf("opening %s for the worker's stdin: %w", os.DevNull, err)
	}
	defer devnull.Close()

	c := newClient(who)
	c.tr = wproto.NewTransport(uc)
	logw := &prefixWriter{logger: p.opts.Logger, prefix: "worker[" + c.key + "] "}

	// The uid on the command line is the one the worker will actually come up
	// with, so it can check the kernel agreed: a root-mode worker gets no
	// Credential and therefore inherits uid 0, whatever uid the administrator
	// signed in as.
	uid := who.UID
	if who.Root {
		uid = 0
	}

	// Try the staged tmpfs copy of the binary first, then the install path.
	// On QTS the QPKG lives on an ext4 shared folder whose access QNAP enforces
	// beyond the POSIX mode: a worker that dropped to the user's uid could not
	// even reach the binary, so every fork/exec returned EACCES. A root-owned
	// copy on a system tmpfs (outside that enforcement) is where the worker is
	// exec'd from instead. The install path still works where it is reachable
	// — QuTS hero's ZFS volumes, and the dev box — so it stays as the fallback.
	candidates := p.workerExes(exe, who.Root)
	var cmd *exec.Cmd
	var startErr error
	for i, cand := range candidates {
		cmd = buildWorkerCmd(p.shutdownCtx, cand, uid, who, devnull, logw, childFile)
		if startErr = cmd.Start(); startErr == nil {
			break
		}
		if i == len(candidates)-1 || !isExecDenied(startErr) {
			uc.Close()
			return nil, fmt.Errorf("starting the worker for %s: %w", c.key, startErr)
		}
		p.opts.Logger.Printf("workerpool: worker %s could not exec %s (%v); trying the next binary", c.key, cand, startErr)
	}
	c.cmd = cmd
	c.pid = cmd.Process.Pid
	go func() {
		defer close(c.exited)
		if err := cmd.Wait(); err != nil {
			p.opts.Logger.Printf("workerpool: worker %s (pid %d) exited: %v", c.key, c.pid, err)
		}
	}()
	c.kill = func(ctx context.Context) { stopProcess(ctx, c) }
	return c, nil
}

// buildWorkerCmd assembles the exec.Cmd for one worker from a candidate binary
// path. It is a function of the path alone so a failed Start can be retried
// against the next candidate with the same fds and credentials.
func buildWorkerCmd(shutdownCtx context.Context, exe string, uid int, who backend.Principal, devnull *os.File, logw io.Writer, childFile *os.File) *exec.Cmd {
	// The pool's context, not the requesting user's: a worker outlives the
	// request that spawned it. What it buys is the end of the shutdown, where a
	// process forked by a startup nothing had a handle for yet — one whose
	// cmd.Start returned after the shutdown had finished sweeping — would
	// otherwise be left running with a user's credentials and the front-end's
	// descriptors, with nobody left to signal it.
	cmd := exec.CommandContext(shutdownCtx, exe, "-worker", "-uid", strconv.Itoa(uid))
	// The cancellation aims at the process group, the way the signal ladder
	// does, so anything the worker started dies with it rather than being
	// reparented; os/exec's default would signal the leader alone. WaitDelay
	// bounds the copy of the worker's stdout and stderr into the log after the
	// process is gone: without it a grandchild holding the pipe open keeps
	// cmd.Wait — and therefore the client's exited channel, and therefore a
	// shutdown waiting on it — running for as long as it likes.
	cmd.Cancel = func() error {
		signalGroup(cmd.Process.Pid, syscall.SIGKILL)
		return nil
	}
	cmd.WaitDelay = termGrace
	// Never hold a working directory on a volume: it would block an unmount.
	cmd.Dir = "/"
	cmd.Env = workerEnv(who)
	cmd.Stdin = devnull
	cmd.Stdout = logw
	cmd.Stderr = logw
	cmd.ExtraFiles = []*os.File{childFile} // fd 3 in the child
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Its own process group, so a signal aimed at the front-end's group
		// does not reach the workers and so the whole group can be killed.
		Setpgid: true,
		// Best-effort only, and documented as cleared for a set-uid binary.
		// The guarantee that actually holds is the worker's read on fd 3
		// returning EOF when this process dies.
		Pdeathsig: syscall.SIGKILL,
	}
	if !who.Root {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:    uint32(who.UID),
			Gid:    uint32(who.GID),
			Groups: credGroups(who),
		}
	}
	return cmd
}

// isExecDenied reports whether a cmd.Start failure is the kind a different
// binary path might avoid: the file could not be reached or executed. It is the
// only failure worth retrying another candidate for — a bad flag or an OOM is
// not.
func isExecDenied(err error) bool {
	return errors.Is(err, fs.ErrPermission) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.ENOEXEC) ||
		errors.Is(err, syscall.ENOENT)
}

// workerExes returns the binaries to try execing a worker from, best first.
//
// A ROOT worker is never given the staged tmpfs copy: root can exec the
// install-path binary directly (the daemon itself runs from there), so it has
// no need of /tmp — and routing it through a world-adjacent location would be
// the one place a tampered staged binary could run as root. Root uses the
// install path alone.
//
// A non-root worker tries the staged copy first, because on a QTS ext4 shared
// folder the install tree is unreachable to a non-root uid whatever its mode.
// Staging is cached only on success, so a transient failure is retried on the
// next spawn rather than disabling non-root workers until a restart.
func (p *Pool) workerExes(install string, root bool) []string {
	if root {
		return dedupNonEmpty(install)
	}
	p.stageMu.Lock()
	if p.stagedExe == "" {
		if staged, err := stageWorkerBinary(install, p.tmpDir()); err != nil {
			p.opts.Logger.Printf("workerpool: could not stage the worker binary on tmpfs (%v); using the install path", err)
		} else {
			p.stagedExe = staged
		}
	}
	staged := p.stagedExe
	p.stageMu.Unlock()
	return dedupNonEmpty(staged, install)
}

func dedupNonEmpty(paths ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, e := range paths {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

func (p *Pool) tmpDir() string {
	if p.opts.TmpDir != "" {
		return p.opts.TmpDir
	}
	return "/tmp"
}

// stageWorkerBinary copies src to a root-owned 0755 directory on the given
// tmpfs and returns the copy's path, so a non-root worker can exec the binary
// even where the install tree denies it.
//
// The security of this rests on two things the function verifies rather than
// assumes, because /tmp is world-writable:
//
//   - The parent must be root-owned and sticky. Sticky is what stops a non-root
//     user renaming or deleting our directory once it exists, and root-owned is
//     what stops them having created a decoy we would adopt.
//   - Our directory must be a real directory (not a symlink), root-owned, and
//     not writable by group or other. It is created exclusively; a pre-existing
//     entry is reused only if it passes those checks, and otherwise removed and
//     recreated. So a directory an attacker pre-created is never written into.
//
// The copy itself is atomic and pathname-race-free: a CreateTemp file in the
// verified directory, fchmod on the open descriptor, then a rename into place.
func stageWorkerBinary(src, tmpDir string) (string, error) {
	if src == "" {
		return "", errors.New("no source binary to stage")
	}
	if err := requireRootStickyDir(tmpDir); err != nil {
		return "", fmt.Errorf("staging parent %s is not a safe root-owned sticky directory: %w", tmpDir, err)
	}
	dir := filepath.Join(tmpDir, ".qnapfilemanager")
	if err := ensureRootOwnedDir(dir); err != nil {
		return "", err
	}

	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(dir, "qfm-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }
	if _, err := io.Copy(tmp, in); err != nil {
		cleanup()
		return "", err
	}
	// Fchmod the open descriptor, not the pathname: the directory is root-owned
	// and not group/other-writable, but chmod-by-name is still the wrong habit
	// in a shared /tmp.
	if err := tmp.Chmod(0o755); err != nil {
		cleanup()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	dst := filepath.Join(dir, "qnapfilemanager")
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return dst, nil
}

// requireRootStickyDir verifies that path is a directory (not a symlink) owned
// by root with the sticky bit set. Nothing under a parent that is not both is
// safe from a non-root user in /tmp.
func requireRootStickyDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("not a directory")
	}
	if fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("not sticky")
	}
	if !rootOwned(fi) {
		return fmt.Errorf("not owned by root")
	}
	return nil
}

// ensureRootOwnedDir makes dir a root-owned directory that is not writable by
// group or other, creating it exclusively and removing any decoy an attacker
// pre-created. The bounded loop closes the tiny window between removing a decoy
// and recreating it; once our root-owned directory exists under a sticky parent
// no non-root user can disturb it.
func ensureRootOwnedDir(dir string) error {
	for try := 0; try < 8; try++ {
		err := os.Mkdir(dir, 0o755)
		if err == nil {
			return nil // we created it, so it is ours
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		fi, lerr := os.Lstat(dir)
		if lerr != nil {
			continue
		}
		if fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && rootOwned(fi) && fi.Mode().Perm()&0o022 == 0 {
			return nil // a pre-existing directory that is safe to reuse
		}
		// A decoy: a symlink, an attacker-owned directory, or a group/other
		// writable one. Root may remove it (RemoveAll unlinks a symlink as-is
		// rather than following it), then the loop recreates it.
		if rerr := os.RemoveAll(dir); rerr != nil {
			return rerr
		}
	}
	return fmt.Errorf("could not create a safe %s", dir)
}

// rootOwned reports whether the file is owned by uid 0.
func rootOwned(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// workerEnv is the whole environment a worker gets. Nothing is inherited: the
// front-end's environment belongs to App Center and may hold anything.
func workerEnv(who backend.Principal) []string {
	env := []string{
		"PATH=/bin:/sbin:/usr/bin:/usr/sbin",
		"HOME=" + safeHome(who),
	}
	// The timezone decides how mtimes are rendered, and GOMEMLIMIT is how an
	// operator bounds N workers on a 1 GB ARM NAS. Both are passed through
	// when the front-end has them, and nothing else is.
	for _, name := range []string{"TZ", "GOMEMLIMIT"} {
		if v := os.Getenv(name); v != "" {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// safeHome never points a worker at a volume: a home directory on a share
// would give the process a reference that blocks an unmount, and the worker
// has no use for one.
func safeHome(who backend.Principal) string {
	if who.Root {
		return "/root"
	}
	return "/"
}

// credGroups builds the supplementary group set. It must be explicit and it
// must contain the primary gid: with Groups nil and NoSetGroups false, Go
// calls setgroups(0, nil), which wipes the user's supplementary groups and
// silently costs them access to every group-shared folder. That bug would look
// like a permissions problem on the NAS, not like a bug here.
func credGroups(who backend.Principal) []uint32 {
	out := make([]uint32, 0, len(who.Groups)+1)
	seen := map[int]bool{}
	add := func(g int) {
		if g < 0 || seen[g] {
			return
		}
		seen[g] = true
		out = append(out, uint32(g))
	}
	add(who.GID)
	for _, g := range who.Groups {
		add(g)
	}
	return out
}

// stopProcess is the signal ladder of §2.6: SIGTERM to the worker's process
// group, then SIGKILL five seconds later.
func stopProcess(ctx context.Context, c *client) {
	if c.cmd == nil || c.cmd.Process == nil {
		return
	}
	select {
	case <-c.exited:
		return
	default:
	}
	pid := c.cmd.Process.Pid
	signalGroup(pid, syscall.SIGTERM)
	select {
	case <-c.exited:
		return
	case <-ctx.Done():
	case <-time.After(termGrace):
	}
	signalGroup(pid, syscall.SIGKILL)
	select {
	case <-c.exited:
	case <-time.After(termGrace):
	}
}

// signalGroup aims at the worker's process group, which Setpgid made it the
// leader of, so anything it started dies with it. If the group is already gone
// the process itself is tried, which covers the window before setpgid took.
func signalGroup(pid int, sig syscall.Signal) {
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(-pid, sig); err != nil {
		_ = syscall.Kill(pid, sig)
	}
}

// prefixWriter turns a worker's stdout and stderr into tagged lines in the app
// log, so a panic in a worker is diagnosable without SSH.
type prefixWriter struct {
	logger *log.Logger
	prefix string

	mu  sync.Mutex
	buf []byte
}

// maxWorkerLogLine flushes a worker that writes a lot without ever ending a
// line, so the buffer cannot grow without bound.
const maxWorkerLogLine = 8 << 10

func (w *prefixWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		if line := bytes.TrimRight(w.buf[:i], "\r"); len(line) > 0 {
			w.logger.Printf("%s%s", w.prefix, line)
		}
		w.buf = append(w.buf[:0], w.buf[i+1:]...)
	}
	if len(w.buf) > maxWorkerLogLine {
		w.logger.Printf("%s%s", w.prefix, w.buf)
		w.buf = w.buf[:0]
	}
	return len(p), nil
}
