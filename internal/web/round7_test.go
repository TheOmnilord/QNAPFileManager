package web

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestUnsafeFirstRequestNeverValidatesCredentials(t *testing.T) {
	var calls atomic.Int32
	s := authTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "<r><authPassed>1</authPassed><username>dev</username></r>")
	})
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			w := request(s, method, "/api/logout?sid=valid", nil, nil)
			assertAuthError(t, w, http.StatusUnauthorized, "unauthorized", "")
			if calls.Load() != 0 || len(s.sessions) != 0 || len(w.Result().Cookies()) != 0 {
				t.Fatalf("unsafe bootstrap performed authentication: calls=%d sessions=%d cookies=%v", calls.Load(), len(s.sessions), w.Result().Cookies())
			}
		})
	}
	// The same credential still bootstraps normally through api/session.
	w := request(s, "GET", "/api/session?sid=valid", nil, nil)
	if w.Code != http.StatusOK || calls.Load() != 1 || len(s.sessions) != 1 {
		t.Fatalf("safe bootstrap: calls=%d sessions=%d status=%d body=%s", calls.Load(), len(s.sessions), w.Code, w.Body)
	}
}
