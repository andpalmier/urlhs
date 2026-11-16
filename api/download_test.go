package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

const partialHash = "cd24da0069d1d15c28538a0e9cb9610d0a47d6e7b36f00ac380ddfd0362afb93"

func TestDownloadSampleRemovesPartialFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("PK\x03\x04partial"))
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	dest := filepath.Join(t.TempDir(), "partial.zip")
	if _, err := c.DownloadSample(context.Background(), partialHash, dest); err == nil {
		t.Fatal("expected an error for a truncated body")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatalf("partial file was not removed: %v", err)
	}
}

func TestDownloadSampleWritesFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/download/"+partialHash+"/" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte{'P', 'K', 3, 4, 'd', 'a', 't', 'a'})
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	dest := filepath.Join(t.TempDir(), "sample.zip")
	got, err := c.DownloadSample(context.Background(), partialHash, dest)
	if err != nil {
		t.Fatal(err)
	}
	if got != dest {
		t.Errorf("path = %q, want %q", got, dest)
	}
	b, err := os.ReadFile(dest)
	if err != nil || string(b) != string([]byte{'P', 'K', 3, 4, 'd', 'a', 't', 'a'}) {
		t.Errorf("file = %q, %v", b, err)
	}
}

func TestDownloadSampleReportsPlainNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not_found"))
	}))
	defer server.Close()

	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	_, err := c.DownloadSample(context.Background(), partialHash, filepath.Join(t.TempDir(), "x.zip"))
	if err == nil || err.Error() != "that sample is unknown to URLhaus" {
		t.Fatalf("error = %v", err)
	}
}

func TestDownloadSampleRefusesOverwrite(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte{'P', 'K', 3, 4})
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "taken.zip")
	if err := os.WriteFile(dest, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := NewClient("test-key", WithBaseURL(server.URL+"/"))
	if _, err := c.DownloadSample(context.Background(), partialHash, dest); err == nil {
		t.Fatal("expected existing destination to be rejected")
	}
	if got := requests.Load(); got != 0 {
		t.Errorf("API was contacted %d times for an existing destination", got)
	}
}
