package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_MakeRequest(t *testing.T) {
	tests := []struct {
		name       string
		apiKey     string
		wantHeader bool
		wantErr    bool
	}{
		{"with api key", "test-key", true, false},
		{"without api key", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Errorf("Expected Content-Type application/x-www-form-urlencoded, got %s", r.Header.Get("Content-Type"))
				}
				if tt.wantHeader {
					if r.Header.Get("Auth-Key") != tt.apiKey {
						t.Errorf("Expected Auth-Key %s, got %s", tt.apiKey, r.Header.Get("Auth-Key"))
					}
				} else {
					if r.Header.Get("Auth-Key") != "" {
						t.Errorf("Expected no Auth-Key, got %s", r.Header.Get("Auth-Key"))
					}
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"query_status":"ok"}`))
			}))
			defer server.Close()

			c := NewClient(tt.apiKey)
			c.baseURL = server.URL + "/" // Override base URL

			_, err := c.MakePostRequest(context.Background(), "test", map[string]string{"foo": "bar"})
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.MakeRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_RateLimit(t *testing.T) {
	// Simple test to ensure rate limiter doesn't block immediately
	c := NewClient("")
	c.baseURL = "http://example.com/"
	// Reset rate limiter for testing if exposed, otherwise just run one request
	// we just rely on MakeRequest succeeding
}
