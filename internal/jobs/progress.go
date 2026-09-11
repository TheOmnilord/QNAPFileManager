package jobs

import (
	"context"
	"math"
	"time"
)

// ewmaWindow is the time constant of the transfer-rate estimate. Five seconds
// is long enough that a single slow file does not make the ETA jump, and short
// enough that the number still tracks a real slowdown.
const ewmaWindow = 5 * time.Second

// maxETA bounds what is reported as an estimate. Beyond a year the honest
// answer is "unknown", not a number nobody will wait for.
const maxETA = 365 * 24 * 3600

// Progress is the handle a work function reports through. Every method is safe
// to call from any goroutine, and safe on a nil receiver, so a caller that has
// no progress to report does not have to guard each call.
type Progress struct {
	m   *Manager
	e   *entry
	ctx context.Context
}

// Step is the cancellation check: it returns the context's error once the job
// has been cancelled (or the manager closed), and nil otherwise. A loop that
// calls it every item — and a copy that calls it every buffer — is what makes
// cancellation prompt.
func (p *Progress) Step() error {
	if p == nil || p.ctx == nil {
		return nil
	}
	return p.ctx.Err()
}

// Context is the job's context, for work that must pass one on (an RPC, say).
func (p *Progress) Context() context.Context {
	if p == nil || p.ctx == nil {
		return context.Background()
	}
	return p.ctx
}

// Set records the counters and recomputes the rate and the ETA. -1 means
// indeterminate for either total, which is what a capped scan reports.
func (p *Progress) Set(files, filesTotal, bytes, bytesTotal int64) {
	if p == nil || p.e == nil {
		return
	}
	now := p.m.now()
	e := p.e
	e.mu.Lock()
	defer e.mu.Unlock()
	j := &e.job
	j.Files, j.FilesTotal = files, filesTotal
	j.Bytes, j.BytesTotal = bytes, bytesTotal
	j.UpdatedAt = now
	e.sampleLocked(now, bytes)
	e.etaLocked(now)
}

// Current names the item being worked on.
func (p *Progress) Current(path string) {
	if p == nil || p.e == nil {
		return
	}
	now := p.m.now()
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	p.e.job.Current = path
	p.e.job.UpdatedAt = now
}

// Phase moves the job between "scanning", "working" and "finishing".
func (p *Progress) Phase(phase string) {
	if p == nil || p.e == nil {
		return
	}
	now := p.m.now()
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	p.e.job.Phase = phase
	p.e.job.UpdatedAt = now
}

// Warn records one per-item failure. It never ends the job: the first WarnCap
// warnings are kept verbatim and the total is always counted, which is what
// makes a Warn frame dropped by a slow reader harmless — the job's terminal
// result carries the count as well.
func (p *Progress) Warn(path, code, msg string) {
	if p == nil || p.e == nil {
		return
	}
	now := p.m.now()
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	j := &p.e.job
	j.WarningCount++
	if len(j.Warnings) < WarnCap {
		j.Warnings = append(j.Warnings, formatWarn(path, code, msg))
	}
	j.UpdatedAt = now
}

// Warnings reports how many per-item failures have been recorded so far.
func (p *Progress) Warnings() int {
	if p == nil || p.e == nil {
		return 0
	}
	p.e.mu.Lock()
	defer p.e.mu.Unlock()
	return p.e.job.WarningCount
}

func formatWarn(path, code, msg string) string {
	out := ""
	if path != "" {
		out = path + ": "
	}
	if msg == "" {
		msg = code
	}
	out += msg
	if code != "" && msg != code {
		out += " (" + code + ")"
	}
	return out
}

// sampleLocked folds one observation into the exponentially weighted rate. The
// weight is derived from the elapsed time rather than fixed per sample, so a
// job that reports ten times a second and one that reports once a second
// converge on the same estimate.
func (e *entry) sampleLocked(now time.Time, bytes int64) {
	if e.lastSample.IsZero() {
		e.lastSample = now
		e.lastBytes = bytes
		return
	}
	dt := now.Sub(e.lastSample).Seconds()
	if dt <= 0 {
		// Two samples inside the clock's resolution: there is no rate to be had
		// from them, and dividing by zero would produce an infinity that would
		// then be reported as an ETA of zero.
		return
	}
	delta := bytes - e.lastBytes
	if delta < 0 {
		delta = 0 // a restarted or re-scanned job never has a negative rate
	}
	inst := float64(delta) / dt
	if !e.rateSeen {
		e.rate = inst
		e.rateSeen = true
	} else {
		alpha := 1 - math.Exp(-dt/ewmaWindow.Seconds())
		e.rate += alpha * (inst - e.rate)
	}
	e.lastSample = now
	e.lastBytes = bytes
	if e.rate < 0 || math.IsNaN(e.rate) || math.IsInf(e.rate, 0) {
		e.rate = 0
	}
	e.job.Rate = int64(math.Round(e.rate))
}

// etaLocked estimates the seconds remaining: from the byte rate where there is
// a byte total, otherwise from the average file rate, otherwise -1 (unknown).
func (e *entry) etaLocked(now time.Time) {
	j := &e.job
	j.ETA = -1

	if j.BytesTotal > 0 && e.rate > 0 {
		remain := j.BytesTotal - j.Bytes
		if remain <= 0 {
			j.ETA = 0
			return
		}
		j.ETA = clampETA(float64(remain) / e.rate)
		return
	}
	if j.FilesTotal > 0 && j.Files > 0 && !e.runStart.IsZero() {
		elapsed := now.Sub(e.runStart).Seconds()
		if elapsed <= 0 {
			return
		}
		perSecond := float64(j.Files) / elapsed
		if perSecond <= 0 {
			return
		}
		remain := j.FilesTotal - j.Files
		if remain <= 0 {
			j.ETA = 0
			return
		}
		j.ETA = clampETA(float64(remain) / perSecond)
	}
}

func clampETA(seconds float64) int {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return -1
	}
	v := math.Ceil(seconds)
	if v > maxETA {
		return -1
	}
	return int(v)
}
