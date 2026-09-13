package web

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"qnapfilemanager/internal/audit"
)

// The transfer notices are a contract between the two halves (see the const
// block in routes_transfer.go): the client grades its confirm dialog by
// recognising exactly these sentences, and treats any other summary line as a
// guard reason that demands the typed phrase. This is the same pin as
// TestPermanentWarningIsPinnedToTheClient.
func TestTransferNoticesArePinnedToTheClient(t *testing.T) {
	js, err := assets.ReadFile("static/js/transfer.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(js)
	for _, sentence := range []string{noticeSizeMinimum, noticeSizeOverflow, noticeCrossUnknown, noticeOverwrite} {
		if !strings.Contains(src, "'"+sentence+"'") {
			t.Errorf("transfer.js TRANSFER_NOTICES no longer carries %q", sentence)
		}
	}
	if !strings.Contains(src, "CROSS_DEVICE_MARK='"+crossDeviceMark+"'") {
		t.Errorf("transfer.js CROSS_DEVICE_MARK differs from the server's %q", crossDeviceMark)
	}
	// And the server really emits the fragment inside its prediction sentence.
	if !strings.Contains(crossDeviceMark, "different volumes") {
		t.Fatalf("crossDeviceMark lost its meaning: %q", crossDeviceMark)
	}
}

// The transfer routes are mutation routes for the sessionless-denial audit
// (adv 10), exactly like delete: an expired or forged session hitting them
// must leave the same denial line. Round 17 of the M2-B review found them
// missing from isMutationRoute.
func TestUnauthenticatedTransferIsAudited(t *testing.T) {
	for _, route := range []string{"/api/jobs/copy", "/api/jobs/move"} {
		t.Run(route, func(t *testing.T) {
			s, _ := fixture(t, false)
			s.guard.SetReadOnly(false)
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			logger, err := audit.Open(path, false)
			if err != nil {
				t.Fatal(err)
			}
			s.auditor = logger
			r := httptest.NewRequest("POST", route, strings.NewReader(`{"paths":[{"path":"/x"}],"dest":{"path":"/y"}}`))
			r.Header.Set("Origin", "http://example.com")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != 401 {
				t.Fatalf("status %d, want 401", w.Code)
			}
			if err := logger.Close(); err != nil {
				t.Fatal(err)
			}
			events, _ := logger.Tail(50)
			for _, e := range events {
				if e.Op == "auth" && e.Result == "denied" && e.Path == route {
					return
				}
			}
			t.Fatalf("no denial audit for %s among %d events", route, len(events))
		})
	}
}
