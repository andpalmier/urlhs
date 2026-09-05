package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The files under testdata are real responses captured from the live URLhaus
// API. Decoding them with DisallowUnknownFields means a field the API returns
// but the structs do not model fails the build, which is how the missing
// hashes and the takedown_time_seconds type mismatch went unnoticed before.
func TestLiveResponsesDecodeCompletely(t *testing.T) {
	tests := []struct {
		file string
		into func() any
	}{
		{"urls_recent.json", func() any { return &RecentURLsResponse{} }},
		{"payloads_recent.json", func() any { return &RecentPayloadsResponse{} }},
		{"url.json", func() any { return &URLInfoResponse{} }},
		{"urlid.json", func() any { return &URLInfoResponse{} }},
		{"host.json", func() any { return &HostInfoResponse{} }},
		{"payload.json", func() any { return &PayloadInfoResponse{} }},
		{"tag.json", func() any { return &TagInfoResponse{} }},
		{"signature.json", func() any { return &SignatureInfoResponse{} }},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatal(err)
			}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(tt.into()); err != nil {
				t.Errorf("live response does not fit the structs: %v", err)
			}
		})
	}
}

// Recent payloads must come back with their hashes populated. They did not
// before, because the struct only knew the /v1/url/ spelling.
func TestRecentPayloadsCarryHashes(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "payloads_recent.json"))
	if err != nil {
		t.Fatal(err)
	}
	var resp RecentPayloadsResponse
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Payloads) == 0 {
		t.Fatal("no payloads in the capture")
	}
	for i, p := range resp.Payloads {
		if p.SHA256Hash == "" {
			t.Errorf("payload %d has no sha256_hash", i)
		}
		if p.MD5Hash == "" {
			t.Errorf("payload %d has no md5_hash", i)
		}
		if p.FileSize.String() == "" {
			t.Errorf("payload %d has no file_size", i)
		}
	}
}
