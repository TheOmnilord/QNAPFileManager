package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/backend"
	"qnapfilemanager/internal/fsx"
)

type downloadBackend struct {
	backend.Backend
	open func() (*os.File, fsx.Entry, error)
}

func (b downloadBackend) OpenRead(context.Context, backend.Principal, string) (*os.File, fsx.Entry, error) {
	return b.open()
}

func TestDownloadSizing(t *testing.T) {
	const body = "pseudo-file contents\n"
	for _, tc := range []struct {
		name string
		size int64
		pipe bool
	}{
		{"zero size", 0, false},
		{"misleading size", 4096, false},
		{"failed seek", int64(len(body)), true},
		{"regular file", int64(len(body)), false},
	} {
		for _, ranged := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{true: "/range", false: "/full"}[ranged], func(t *testing.T) {
				s, _ := fixture(t, true)
				name := filepath.Join(t.TempDir(), "body")
				if err := os.WriteFile(name, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
				s.backend = downloadBackend{open: func() (*os.File, fsx.Entry, error) {
					entry := fsx.Entry{Size: tc.size, Type: "file"}
					if tc.pipe {
						r, w, err := os.Pipe()
						if err != nil {
							return nil, entry, err
						}
						go func() { defer w.Close(); _, _ = io.WriteString(w, body) }()
						return r, entry, nil
					}
					f, err := os.Open(name)
					return f, entry, err
				}}
				// Use a real server to detect net/http's automatic Content-Length.
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					s.download(w, r, &session{})
				}))
				defer srv.Close()
				req, err := http.NewRequest(http.MethodGet, srv.URL+"/?path=/meminfo", nil)
				if err != nil {
					t.Fatal(err)
				}
				if ranged {
					req.Header.Set("Range", "bytes=1-3")
				}
				resp, err := srv.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				data, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatal(err)
				}
				wantStatus, wantBody := http.StatusOK, body
				regular := tc.name == "regular file"
				if regular && ranged {
					wantStatus, wantBody = http.StatusPartialContent, body[1:4]
				}
				if resp.StatusCode != wantStatus || string(data) != wantBody {
					t.Fatalf("download: status=%d body=%q", resp.StatusCode, data)
				}
				if resp.Header.Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") {
					t.Fatalf("download headers: %v", resp.Header)
				}
				if !regular && (resp.ContentLength != -1 || resp.Header.Get("Content-Length") != "" || resp.Header.Get("Accept-Ranges") != "" || resp.Header.Get("Content-Range") != "") {
					t.Fatalf("stream advertises size/ranges: %v", resp.Header)
				}
				if regular && ranged && resp.Header.Get("Content-Range") != "bytes 1-3/21" {
					t.Fatalf("regular range: %v", resp.Header)
				}
			})
		}
	}
}

func TestDownloadStreamCancellation(t *testing.T) {
	s, _ := fixture(t, true)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	opened := make(chan struct{})
	s.backend = downloadBackend{open: func() (*os.File, fsx.Entry, error) {
		close(opened)
		return r, fsx.Entry{Type: "file"}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/?path=/meminfo", nil).WithContext(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.download(httptest.NewRecorder(), req, &session{})
	}()
	<-opened
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled download remained blocked reading the pipe")
	}
}
