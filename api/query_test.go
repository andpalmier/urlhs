package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetRecentURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"urls": [
				{
					"id": 12345,
					"url": "http://example.com/malware",
					"url_status": "online",
					"threat": "malware_download",
					"tags": ["tag1", "tag2"]
				}
			]
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	urls, err := c.QueryRecentURLs(context.Background(), 1)
	if err != nil {
		t.Fatalf("QueryRecentURLs() error = %v", err)
	}

	if len(urls) != 1 {
		t.Errorf("Expected 1 URL, got %d", len(urls))
	}
	if urls[0].ID.String() != "12345" {
		t.Errorf("Expected ID 12345, got %s", urls[0].ID)
	}
}

func TestClient_GetRecentPayloads(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"payloads": [
				{
					"firstseen": "2023-01-01 12:00:00",
					"filename": "malware.exe",
					"file_type": "exe",
					"response_md5": "d41d8cd98f00b204e9800998ecf8427e"
				}
			]
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	payloads, err := c.QueryRecentPayloads(context.Background(), 1)
	if err != nil {
		t.Fatalf("QueryRecentPayloads() error = %v", err)
	}

	if len(payloads) != 1 {
		t.Errorf("Expected 1 payload, got %d", len(payloads))
	}
	if payloads[0].MD5Hash != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("Got wrong MD5: %s", payloads[0].MD5Hash)
	}
}

func TestClient_QueryURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"id": "12345",
			"url": "http://example.com/malware",
			"threat": "malware_download"
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	info, err := c.QueryURL(context.Background(), "http://example.com/malware")
	if err != nil {
		t.Fatalf("QueryURL() error = %v", err)
	}

	if info.URL != "http://example.com/malware" {
		t.Errorf("Got wrong URL: %s", info.URL)
	}
}

func TestClient_QueryTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{
			"query_status": "ok",
			"urls": [
				{
					"id": "123",
					"url": "http://example.com/1",
					"url_status": "offline"
				}
			]
		}`)
	}))
	defer server.Close()

	c := NewClient("test-key")
	c.baseURL = server.URL + "/"

	info, err := c.QueryTag(context.Background(), "Emotet")
	if err != nil {
		t.Fatalf("QueryTag() error = %v", err)
	}

	if len(info.URLs) != 1 {
		t.Errorf("Expected 1 URL, got %d", len(info.URLs))
	}
}

// TestPayloadHashSpellings pins the normalisation between the two shapes the
// API uses for the same fields. /v1/url/ sends response_md5, response_sha256
// and response_size; /v1/payloads/recent/ sends md5_hash, sha256_hash and
// file_size.
func TestPayloadHashSpellings(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"recent payloads spelling", `{
			"firstseen": "2026-01-01 00:00:00",
			"md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
			"sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"file_size": 27383
		}`},
		{"url query spelling", `{
			"firstseen": "2026-01-01 00:00:00",
			"response_md5": "d41d8cd98f00b204e9800998ecf8427e",
			"response_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"response_size": "27383"
		}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p Payload
			if err := json.Unmarshal([]byte(tt.body), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if p.MD5Hash != "d41d8cd98f00b204e9800998ecf8427e" {
				t.Errorf("MD5Hash = %q, want it populated", p.MD5Hash)
			}
			if p.SHA256Hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
				t.Errorf("SHA256Hash = %q, want it populated", p.SHA256Hash)
			}
			if p.FileSize.String() != "27383" {
				t.Errorf("FileSize = %q, want 27383", p.FileSize.String())
			}
		})
	}
}

// takedown_time_seconds arrives quoted from /v1/host/ and unquoted elsewhere.
func TestTakedownTimeBothForms(t *testing.T) {
	for _, body := range []string{`{"takedown_time_seconds": "46393"}`, `{"takedown_time_seconds": 46393}`} {
		var e URLEntry
		if err := json.Unmarshal([]byte(body), &e); err != nil {
			t.Errorf("%s failed to decode: %v", body, err)
			continue
		}
		if e.TakedownTimeSeconds == nil || e.TakedownTimeSeconds.String() != "46393" {
			t.Errorf("%s decoded to %v", body, e.TakedownTimeSeconds)
		}
	}
}
