package web

import (
	"strings"
	"testing"

	"taproot/internal/fsx"
)

// TestListDirsFirstQuery: GET /api/fs/list groups folders first unless the
// request says otherwise (stabilization contract §1.2). The flag is parsed like
// the listing's other booleans — an empty value is an absent one, and anything
// strconv.ParseBool refuses is the same 400 "hidden=maybe" gets, answered before
// the backend is asked for anything — except that its absence means true.
func TestListDirsFirstQuery(t *testing.T) {
	s, b := fixture(t, true)
	c, _ := sessionCookie(t, s)
	untouched := fsx.ListOptions{Sort: "not-called"}

	for _, tc := range []struct {
		query     string
		status    int
		dirsFirst bool
	}{
		{"", 200, true},
		{"&dirsFirst=", 200, true},
		{"&dirsFirst=true", 200, true},
		{"&dirsFirst=1", 200, true},
		{"&dirsFirst=false", 200, false},
		{"&dirsFirst=0", 200, false},
		{"&dirsFirst=maybe", 400, false},
		{"&dirsFirst=yes", 400, false},
		{"&dirsFirst=no", 400, false},
		{"&dirsFirst=truee", 400, false},
	} {
		b.opts = untouched
		target := "/api/fs/list?path=/" + tc.query
		w := request(s, "GET", target, c, nil)
		if w.Code != tc.status {
			t.Errorf("%s: %d %s, want %d", target, w.Code, w.Body, tc.status)
			continue
		}
		if tc.status != 200 {
			if !strings.Contains(w.Body.String(), `"code":"bad_request"`) {
				t.Errorf("%s: body %s, want bad_request", target, w.Body)
			}
			if b.opts != untouched {
				t.Errorf("%s: a refused request reached the backend with %+v", target, b.opts)
			}
			continue
		}
		if b.opts.DirsFirst != tc.dirsFirst {
			t.Errorf("%s: DirsFirst = %v, want %v", target, b.opts.DirsFirst, tc.dirsFirst)
		}
	}

	// The flag sits beside the others without disturbing them.
	w := request(s, "GET", "/api/fs/list?path=/&sort=size&desc=true&hidden=true&dirsFirst=false", c, nil)
	if w.Code != 200 || b.opts.DirsFirst || !b.opts.Desc || !b.opts.ShowHidden || b.opts.Sort != fsx.SortSize {
		t.Fatalf("options: %d %+v", w.Code, b.opts)
	}
	w = request(s, "GET", "/api/fs/list?path=/&sort=size&desc=true", c, nil)
	if w.Code != 200 || !b.opts.DirsFirst || !b.opts.Desc || b.opts.Sort != fsx.SortSize {
		t.Fatalf("options with dirsFirst absent: %d %+v", w.Code, b.opts)
	}
}
