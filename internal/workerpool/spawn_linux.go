package workerpool

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
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
	cmd := exec.Command(exe, "-worker", "-uid", strconv.Itoa(uid))
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

	if err := cmd.Start(); err != nil {
		uc.Close()
		return nil, fmt.Errorf("starting the worker for %s: %w", c.key, err)
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
