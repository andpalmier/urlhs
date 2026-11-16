package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const methodsSHA256 = "cd24da0069d1d15c28538a0e9cb9610d0a47d6e7b36f00ac380ddfd0362afb93"
const methodsMD5 = "d41d8cd98f00b204e9800998ecf8427e"

func urlhsTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return NewClient("test-key", WithBaseURL(server.URL+"/"))
}

func TestQueryEndpointsForwardParameters(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		key      string
		value    string
		call     func(context.Context, *Client) error
	}{
		{"url", "/url/", "url", "https://evil.example/a", func(ctx context.Context, c *Client) error {
			_, err := c.QueryURL(ctx, "https://evil.example/a")
			return err
		}},
		{"url id", "/urlid/", "urlid", "123", func(ctx context.Context, c *Client) error {
			_, err := c.QueryURLID(ctx, "123")
			return err
		}},
		{"host", "/host/", "host", "evil.example", func(ctx context.Context, c *Client) error {
			_, err := c.QueryHost(ctx, "evil.example")
			return err
		}},
		{"payload sha256", "/payload/", "sha256_hash", methodsSHA256, func(ctx context.Context, c *Client) error {
			_, err := c.QueryPayload(ctx, methodsSHA256)
			return err
		}},
		{"payload md5", "/payload/", "md5_hash", methodsMD5, func(ctx context.Context, c *Client) error {
			_, err := c.QueryPayload(ctx, methodsMD5)
			return err
		}},
		{"tag", "/tag/", "tag", "emotet", func(ctx context.Context, c *Client) error {
			_, err := c.QueryTag(ctx, "emotet")
			return err
		}},
		{"signature", "/signature/", "signature", "Emotet", func(ctx context.Context, c *Client) error {
			_, err := c.QuerySignature(ctx, "Emotet")
			return err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := urlhsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.endpoint {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.endpoint)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("ParseForm: %v", err)
				}
				if got := r.Form.Get(tt.key); got != tt.value {
					t.Errorf("%s = %q, want %q", tt.key, got, tt.value)
				}
				switch tt.name {
				case "url", "url id":
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","id":123,"url":%q}`, tt.value)
				case "host":
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","host":%q,"url_count":"1"}`, tt.value)
				case "tag":
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","url_count":"1","urls":[{"url_id":"1","url":"https://evil.example/"}]}`)
				case "signature":
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","payload_count":"1","urls":[{"url_id":"1","url":"https://evil.example/"}]}`)
				default:
					_, _ = fmt.Fprintf(w, `{"query_status":"ok","md5_hash":%q,"sha256_hash":%q}`, methodsMD5, methodsSHA256)
				}
			})
			if err := tt.call(context.Background(), c); err != nil {
				t.Fatalf("call failed: %v", err)
			}
		})
	}
}

func TestQueryNoResultsReturnsNil(t *testing.T) {
	c := urlhsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"query_status":"no_results"}`)
	})
	if got, err := c.QueryURL(context.Background(), "https://evil.example/"); err != nil || got != nil {
		t.Fatalf("QueryURL = %+v, %v; want nil, nil", got, err)
	}
}

func TestSubmitURLsWireFormatAndErrors(t *testing.T) {
	original := submitURL
	defer func() { submitURL = original }()

	t.Run("success", func(t *testing.T) {
		var got map[string]any
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Auth-Key") != "test-key" {
				t.Errorf("Auth-Key = %q", r.Header.Get("Auth-Key"))
			}
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			_, _ = fmt.Fprint(w, "ok")
		}))
		defer server.Close()
		submitURL = server.URL + "/"

		c := NewClient("test-key")
		answer, err := c.SubmitURLs(context.Background(), SubmitOptions{
			URLs:      []string{"https://evil.example/a", "https://evil.example/b"},
			Tags:      []string{"emotet"},
			Anonymous: true,
		})
		if err != nil || answer != "ok" {
			t.Fatalf("SubmitURLs = %q, %v", answer, err)
		}
		if got["anonymous"] != "1" {
			t.Errorf("anonymous = %#v", got["anonymous"])
		}
		submission, ok := got["submission"].([]any)
		if !ok || len(submission) != 2 {
			t.Fatalf("submission = %#v", got["submission"])
		}
		entry := submission[0].(map[string]any)
		if entry["url"] != "https://evil.example/a" || entry["threat"] != "malware_download" {
			t.Errorf("entry = %#v", entry)
		}
	})

	t.Run("api error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, "illegal_url: bad")
		}))
		defer server.Close()
		submitURL = server.URL + "/"

		c := NewClient("test-key")
		if _, err := c.SubmitURLs(context.Background(), SubmitOptions{URLs: []string{"https://evil.example/"}}); err == nil {
			t.Fatal("expected submission error")
		}
	})

	t.Run("all matching errors", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, "illegal_threat: xillegal_url")
		}))
		defer server.Close()
		submitURL = server.URL + "/"

		c := NewClient("test-key")
		_, err := c.SubmitURLs(context.Background(), SubmitOptions{URLs: []string{"https://evil.example/"}})
		if err == nil {
			t.Fatal("expected submission error")
		}
		for _, want := range []string{"rejected the threat type", "rejected a URL as malformed"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, want %q", err, want)
			}
		}
	})
}

func TestValidateURLRejectsMalformedHosts(t *testing.T) {
	for _, raw := range []string{"http://", "https://", "http:///path", "example.com"} {
		if err := ValidateURL(raw); err == nil {
			t.Errorf("ValidateURL(%q) accepted malformed URL", raw)
		}
	}
}
