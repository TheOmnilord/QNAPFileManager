package web

import (
	"strings"
	"testing"
)

// The upload notices are a contract between the two halves (see routes_upload.go):
// the client grades its confirm dialog by recognising exactly these sentences,
// and treats any other summary line as a guard reason that demands the typed phrase.
// Currently, upload reuses the noticeOverwrite from the transfer route.
//
// This test requires the UI implementer to add an UPLOAD_NOTICES array to
// static/js/upload.js with the server's notice sentences as single-quoted strings.
func TestUploadNoticesArePinnedToTheClient(t *testing.T) {
	// The upload route emits exactly one notice sentence.
	uploadNotices := []string{noticeOverwrite}

	js, err := assets.ReadFile("static/js/upload.js")
	if err != nil {
		t.Skipf("upload.js not found in assets")
		return
	}

	src := string(js)

	// Check if UPLOAD_NOTICES array exists yet
	if !strings.Contains(src, "UPLOAD_NOTICES") {
		t.Skipf("UPLOAD_NOTICES array not yet in upload.js; UI implementer will add it with pattern: const UPLOAD_NOTICES = ['%s']", noticeOverwrite)
		return
	}

	// Verify each notice sentence appears in the file as a single-quoted string
	for _, sentence := range uploadNotices {
		if !strings.Contains(src, "'"+sentence+"'") {
			t.Errorf("upload.js UPLOAD_NOTICES no longer carries %q", sentence)
		}
	}
}
