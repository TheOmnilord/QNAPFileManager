package web

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The selection bound is one number with two homes (stabilization contract
// §3.5). maxJobRoots is what the job routes refuse past; why.js's MAX_ROOTS is
// what the UI refuses past before it asks — the toolbar's reason, Ctrl+A's
// limit and selectionEntries' refusal all read it. If the two drift apart the
// UI either offers a Delete the server answers with a 400, or refuses one the
// server would have run. This reads the embedded why.js, the asset the browser
// actually runs, and fails when its literal is not the server's constant: the
// same pin as TestTransferNoticesArePinnedToTheClient.
func TestMaxRootsIsPinnedToTheClient(t *testing.T) {
	js, err := assets.ReadFile("static/js/why.js")
	if err != nil {
		t.Fatal(err)
	}
	found := regexp.MustCompile(`(?m)^export const MAX_ROOTS\s*=\s*([0-9_]+)\s*;`).FindAllSubmatch(js, -1)
	if len(found) != 1 {
		t.Fatalf("why.js must declare MAX_ROOTS exactly once, as a numeric literal; found %d declarations", len(found))
	}
	n, err := strconv.Atoi(strings.ReplaceAll(string(found[0][1]), "_", ""))
	if err != nil {
		t.Fatalf("why.js MAX_ROOTS is not a number: %v", err)
	}
	if n != maxJobRoots {
		t.Fatalf("why.js MAX_ROOTS = %d, but the server's maxJobRoots = %d", n, maxJobRoots)
	}
	// The reason table bounds the Trash panel's Restore by the same number, and
	// the restore route has a constant of its own for it (routes_trash.go).
	if n != maxTrashIDs {
		t.Fatalf("why.js MAX_ROOTS = %d also bounds trashRestore, but the server's maxTrashIDs = %d", n, maxTrashIDs)
	}
}
