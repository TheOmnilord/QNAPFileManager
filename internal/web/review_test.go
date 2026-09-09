package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
	"qnapfilemanager/internal/qtsauth"
)

func TestBusyVerificationDoesNotBlockOtherSessions(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		fmt.Fprint(w, "<r><authPassed>0</authPassed></r>")
	}))
	defer endpoint.Close()
	s, _ := fixture(t, false)
	s.verifier = qtsauth.NewVerifier(qtsauth.New(endpoint.URL))
	now := time.Now()
	s.sessions["slow"] = &session{id: "slow", who: backend.Principal{User: "dev"}, cred: qtsauth.Cred{Kind: qtsauth.KindSID, Token: "slow"}, checked: now.Add(-time.Minute), expires: now.Add(sessionTTL)}
	s.sessions["fast"] = &session{id: "fast", who: backend.Principal{User: "other"}, checked: now, expires: now.Add(sessionTTL)}
	s.sessions["expired"] = &session{id: "expired", expires: now.Add(-time.Second)}
	slowDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		slowDone <- request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: "slow"}, nil)
	}()
	defer func() {
		close(release)
		if w := <-slowDone; w.Code != http.StatusUnauthorized {
			t.Errorf("denied verification: %d %s", w.Code, w.Body)
		}
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("slow request did not enter verification")
	}
	fastDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		fastDone <- request(s, "GET", "/api/session", &http.Cookie{Name: "qfm_sid", Value: "fast"}, nil)
	}()
	select {
	case w := <-fastDone:
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"user":"other"`) {
			t.Fatalf("other session: %d %s", w.Code, w.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("unrelated session blocked on QTS verification")
	}
	s.mu.Lock()
	_, retained := s.sessions["expired"]
	s.mu.Unlock()
	if retained {
		t.Fatal("idle expired session was retained")
	}
}

func TestListNegotiatedPageSize(t *testing.T) {
	s, b := fixture(t, true)
	dir := filepath.Join(b.dir, "many")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 350; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("entry-%03d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cookie, _ := sessionCookie(t, s)
	readPage := func(offset int) (fsx.Listing, int) {
		t.Helper()
		w := request(s, "GET", fmt.Sprintf("/api/fs/list?path=/many&sort=name&offset=%d&limit=500", offset), cookie, nil)
		var page struct {
			fsx.Listing
			Limit int `json:"limit"`
		}
		if w.Code != http.StatusOK {
			t.Fatalf("listing: %d %s", w.Code, w.Body)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		return page.Listing, page.Limit
	}
	unpaged, _ := readPage(0)
	if len(unpaged.Entries) != 350 {
		t.Fatalf("unpaged entries: %d", len(unpaged.Entries))
	}
	s.cfg.Limits.ListMax = 100
	var entries []fsx.Entry
	pages := 0
	for offset := 0; ; {
		page, limit := readPage(offset)
		pages++
		if limit != 100 || page.Total != 350 || len(page.Entries) != min(limit, 350-offset) {
			t.Fatalf("offset=%d limit=%d total=%d entries=%d", offset, limit, page.Total, len(page.Entries))
		}
		entries = append(entries, page.Entries...)
		offset += limit
		if page.Truncated != (offset < page.Total) {
			t.Fatalf("incorrect truncated flag at offset %d", offset)
		}
		if offset >= page.Total {
			break
		}
	}
	if pages != 4 || !reflect.DeepEqual(entries, unpaged.Entries) {
		t.Fatalf("concatenation differs from unpaged listing (%d pages, %d entries)", pages, len(entries))
	}
}
