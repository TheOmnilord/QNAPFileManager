package web

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"qnapfilemanager/internal/audit"
)

// breakGlassBannerText is the sentence the UI shows for the whole life of a
// break-glass session (M4 contract §8.4). It is pinned on the Go side as well
// as in internal/web/banners_test.mjs because it is the one statement standing
// between an operator and a support tree full of root-owned files nobody else
// can delete (§2.4, §18.5).
const breakGlassBannerText = "Emergency access. You are signed in with the local administrator account, not a QTS user. Everything you create here will be owned by root."

// TestUIBreakGlassDoorPin keeps the UI's idea of the three doors and the Go
// side's constants identical.
//
// The banner is shown only for door "local". A backend that renamed the value,
// or a UI that read a different field, would fail nothing at all: the app would
// simply never warn an operator that everything they create is owned by root.
// That silence is what this pins — the two halves are written by different
// people, in different languages, and nothing else compares them.
func TestUIBreakGlassDoorPin(t *testing.T) {
	js, err := assets.ReadFile("static/js/banners.js")
	if err != nil {
		t.Fatal(err)
	}
	ui := string(js)
	for _, want := range []string{
		fmt.Sprintf("export const DOORS = ['%s', '%s', '%s'];", audit.DoorQTS, audit.DoorCredential, audit.DoorLocal),
		fmt.Sprintf("export const BREAK_GLASS_DOOR = '%s';", audit.DoorLocal),
		"String(session.door || '') === BREAK_GLASS_DOOR",
		breakGlassBannerText,
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("banners.js no longer pins %q", want)
		}
	}
	// The field the UI reads must be the one the session payload writes.
	// session.go is read from disk rather than embedded: it is the file that
	// decides what /api/session says.
	session, err := os.ReadFile("session.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(session), `"door"`) {
		t.Error(`the session payload no longer carries "door"; the break-glass banner can never appear`)
	}
}
