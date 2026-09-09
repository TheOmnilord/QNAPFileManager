// Copied from GitBackup internal/qnap/qnap.go

// Package qnap writes entries to the QNAP system event log, which QuLog
// Center displays and which QTS Notification Center can forward by email or
// push — but only through an *Alert* notification rule, which matches on
// severity and a keyword in the message text. Event notification rules are
// reserved for applications registered with QNAP and are not available to
// third-party packages, so every message carries a stable keyword instead.
package qnap

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// LogTool is the firmware binary that appends to the event log. It exists on
// QTS and QuTS hero and requires root, which QPKG service scripts have.
const LogTool = "/sbin/log_tool"

// Keyword prefixes every message. Users filter on it when creating an alert
// notification rule, so it must stay identical across releases.
const Keyword = "QNAPFileManager"

// Severity maps to log_tool's -t values and to the levels selectable in a
// notification rule.
type Severity int

const (
	Info    Severity = 0
	Warning Severity = 1
	Error   Severity = 2
)

// IsQTS reports whether this host is a QNAP NAS running QTS/QuTS hero,
// detected by the firmware config every install carries. A generic Linux box
// may have a /share directory for entirely unrelated reasons, so /share
// existing is not evidence of QTS on its own.
func IsQTS() bool {
	_, err := os.Stat("/etc/config/uLinux.conf")
	return err == nil
}

// Available reports whether system logging can be used at all.
func Available() bool {
	fi, err := os.Stat(LogTool)
	return err == nil && !fi.IsDir() && os.Geteuid() == 0
}

// Log appends one entry to the QNAP event log. It is strictly best-effort:
// any failure is returned for logging but never interrupts a backup. Only
// the append flags are ever used — log_tool can also initialise, flush and
// truncate the system log table, and those flags must never appear here.
func Log(ctx context.Context, sev Severity, message string) error {
	if !Available() {
		return nil
	}
	if sev < Info || sev > Error {
		sev = Info
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The message is passed as the argument of -a, never interpolated into
	// a command line, so it cannot be read as an option.
	cmd := exec.CommandContext(ctx, LogTool,
		"-t", strconv.Itoa(int(sev)),
		"-u", "System",
		"-p", "127.0.0.1",
		"-m", "localhost",
		"-a", clean(message))
	return cmd.Run()
}

// clean keeps an entry to a single bounded line: the event log stores one
// row per message and long or multi-line text renders badly.
func clean(msg string) string {
	msg = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(msg)
	msg = strings.Join(strings.Fields(msg), " ")
	if !strings.HasPrefix(msg, "["+Keyword+"]") {
		msg = "[" + Keyword + "] " + msg
	}
	const max = 480
	if len(msg) > max {
		// Drop only a trailing partial character. Validating the whole
		// prefix would rewind to the first invalid byte anywhere in the
		// message and throw away everything after it.
		trimmed := msg[:max-3]
		for len(trimmed) > 0 {
			r, size := utf8.DecodeLastRuneInString(trimmed)
			if r != utf8.RuneError || size > 1 {
				break
			}
			trimmed = trimmed[:len(trimmed)-1]
		}
		msg = trimmed + "..."
	}
	return msg
}
