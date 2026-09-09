//go:build !linux && !windows

package idmap

import (
	"context"
	"fmt"
)

// defaultExec is unavailable on platforms this app is not deployed to. Only
// linux ships; darwin exists so `go test` on a developer machine still builds.
func defaultExec(_ context.Context, name string, _ ...string) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s is not available on this platform", ErrNoHelper, name)
}
