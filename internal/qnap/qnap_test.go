// Copied from GitBackup internal/qnap/qnap_test.go

package qnap

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanKeepsOneBoundedLine(t *testing.T) {
	got := clean("backup finished\nwith 2 failures\r\nand notes")
	if strings.ContainsAny(got, "\n\r") {
		t.Errorf("message still spans lines: %q", got)
	}
	if !strings.HasPrefix(got, "["+Keyword+"] ") {
		t.Errorf("missing the alert-rule keyword: %q", got)
	}
	if strings.Contains(got, "  ") {
		t.Errorf("collapsed whitespace expected: %q", got)
	}
}

func TestCleanTruncates(t *testing.T) {
	got := clean(strings.Repeat("x", 2000))
	if len(got) > 480 {
		t.Errorf("message not truncated: %d bytes", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncation not marked: %q", got[len(got)-10:])
	}
}

func TestCleanTruncatesOnRuneBoundary(t *testing.T) {
	// Multi-byte characters must not be cut in half by truncation.
	got := clean(strings.Repeat("æ", 400))
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
	if len(got) > 480 {
		t.Errorf("message not truncated: %d bytes", len(got))
	}
}

func TestCleanDoesNotDoublePrefix(t *testing.T) {
	got := clean("[" + Keyword + "] already tagged")
	if strings.Count(got, Keyword) != 1 {
		t.Errorf("keyword duplicated: %q", got)
	}
}
