package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows os.Pipe reads are synchronous and cannot reliably be interrupted by Close")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	testDownloadStreamCancellation(t, r, w)
}

type downloadProgressRecorder struct {
	*httptest.ResponseRecorder
	wrote chan struct{}
}

func (w downloadProgressRecorder) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	select {
	case w.wrote <- struct{}{}:
	default:
	}
	return n, err
}

func testDownloadStreamCancellation(t *testing.T, r, w *os.File) {
	t.Helper()
	defer r.Close()
	defer w.Close()
	s, _ := fixture(t, true)
	s.backend = downloadBackend{open: func() (*os.File, fsx.Entry, error) {
		return r, fsx.Entry{Type: "file"}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/?path=/meminfo", nil).WithContext(ctx)
	done := make(chan struct{})
	recorder := downloadProgressRecorder{httptest.NewRecorder(), make(chan struct{}, 1)}
	go func() {
		defer close(done)
		s.download(recorder, req, &session{})
	}()
	go func() { _, _ = io.WriteString(w, "stream started\n") }()
	select {
	case <-recorder.wrote:
	case <-done:
		t.Fatal("download returned before reading the pipe")
	case <-time.After(10 * time.Second):
		t.Fatal("download did not start reading the pipe")
	}
	// Keep the writer open and give the copy time to block on its next read.
	// This also detects an unregistered non-blocking descriptor returning EAGAIN.
	select {
	case <-done:
		t.Fatal("download returned before cancellation or pipe EOF")
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled download remained blocked reading the pipe")
	}
}

func TestDownloadReaderAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := downloadReader{ctx: ctx, reader: strings.NewReader("must not be copied")}
	if n, err := io.Copy(io.Discard, reader); n != 0 || err != context.Canceled {
		t.Fatalf("cancelled copy = (%d, %v), want (0, context.Canceled)", n, err)
	}
}

func TestDownloadStreamHEADDoesNotRead(t *testing.T) {
	s, _ := fixture(t, true)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close() // Keep the empty pipe open: any read would block.
	s.backend = downloadBackend{open: func() (*os.File, fsx.Entry, error) {
		return reader, fsx.Entry{Type: "file"}, nil
	}}
	req := httptest.NewRequest(http.MethodHead, "/?path=/stream", nil)
	req.Header.Set("Range", "bytes=1-3")
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.download(w, req, &session{})
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = writer.Close()
		<-done
		t.Fatal("HEAD tried to consume the stream")
	}
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("HEAD response: %d %v %s", w.Code, w.Header(), w.Body)
	}
	for _, header := range []string{"Content-Length", "Content-Range", "Accept-Ranges"} {
		if w.Header().Get(header) != "" {
			t.Fatalf("stream HEAD advertised %s", header)
		}
	}
}
