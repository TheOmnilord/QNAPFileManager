package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"qnapfilemanager/internal/fsx"
)

func TestTextStreamCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows os.Pipe reads cannot reliably be interrupted by Close")
	}
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			testTextStreamCancellation(t, r, w, deadline)
		})
	}
}

func testTextStreamCancellation(t *testing.T, reader, writer *os.File, deadline bool) {
	t.Helper()
	defer reader.Close()
	defer writer.Close()
	s, _ := fixture(t, true)
	s.backend = downloadBackend{open: func() (*os.File, fsx.Entry, error) {
		return reader, fsx.Entry{Type: "file"}, nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	if deadline {
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
	}
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/fs/text?path=/stream", nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.text(recorder, req, &session{})
	}()
	const partial = "partial preview\n"
	if _, err := io.WriteString(writer, partial); err != nil {
		t.Fatal(err)
	}
	// Leave the writer open so the next read blocks instead of reaching EOF.
	select {
	case <-done:
		t.Fatal("preview returned before cancellation or EOF")
	case <-time.After(100 * time.Millisecond):
	}
	if !deadline {
		cancel()
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = writer.Close() // Unblock even a regressed implementation.
		<-done
		t.Fatal("preview remained blocked after cancellation")
	}
	var body struct {
		Content   string
		Bytes     int
		Truncated bool
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || body.Content != partial || body.Bytes != len(partial) || !body.Truncated {
		t.Fatalf("partial preview: %d %+v", recorder.Code, body)
	}
	if fd := reader.Fd(); fd != ^uintptr(0) {
		t.Fatalf("original descriptor still open: %v", fd)
	}
	if _, err := writer.Write([]byte("x")); err == nil {
		t.Fatal("pollable descriptor still open")
	}
}

func TestTextStreamByteCap(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	s, _ := fixture(t, true)
	s.backend = downloadBackend{open: func() (*os.File, fsx.Entry, error) {
		return reader, fsx.Entry{Type: "file"}, nil
	}}
	// Exactly the probe cap, with no EOF: one extra read would hang.
	go func() { _, _ = io.WriteString(writer, strings.Repeat("x", 8192)) }()
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.text(recorder, httptest.NewRequest(http.MethodGet, "/api/fs/text?path=/stream&max=4", nil), &session{})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = writer.Close()
		<-done
		t.Fatal("preview read beyond its byte cap")
	}
	var body struct {
		Content   string
		Truncated bool
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusOK || body.Content != "xxxx" || !body.Truncated {
		t.Fatalf("capped preview: %d %+v", recorder.Code, body)
	}
	if fd := reader.Fd(); fd != ^uintptr(0) {
		t.Fatalf("original descriptor still open: %v", fd)
	}
}
