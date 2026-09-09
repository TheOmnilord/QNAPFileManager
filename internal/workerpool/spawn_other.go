//go:build !linux

package workerpool

import (
	"fmt"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
)

// spawnProcess needs SysProcAttr.Credential, socketpair(2) and SCM_RIGHTS,
// none of which exist off Linux. PLAN.md decision 5 rejects in-process setuid,
// so there is no fallback to offer here: the dev box runs the pool in
// ModeInProcess, which impersonates nobody and says so.
func (p *Pool) spawnProcess(who backend.Principal) (*client, error) {
	return nil, fmt.Errorf("spawning a worker as %s: impersonation needs Linux: %w", who.Key(), fsx.ErrUnsupported)
}
