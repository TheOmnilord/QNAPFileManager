package idmap

import (
	"context"
	"fmt"
)

// defaultExec has no NSS fallback on Windows: there are no id(1)/getent(1)
// helpers and nothing to impersonate. Development on Windows uses fixture
// passwd/group files or an injected Map.Exec.
func defaultExec(_ context.Context, name string, _ ...string) ([]byte, error) {
	return nil, fmt.Errorf("%w: %s is not available on windows", ErrNoHelper, name)
}
