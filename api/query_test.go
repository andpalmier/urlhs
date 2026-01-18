package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_GetRecentURLs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
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
		fmt.Fprintln(w, `{
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
	if payloads[0].ResponseMD5 != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("Got wrong MD5: %s", payloads[0].ResponseMD5)
	}
}

func TestClient_QueryURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{
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
		fmt.Fprintln(w, `{
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
