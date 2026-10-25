package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// submitURL is the URLhaus submission endpoint. It lives on urlhaus.abuse.ch,
// not on the query API host.
var submitURL = "https://urlhaus.abuse.ch/api/"

// SubmitOptions describes a URL submission. URLs is required; Tags are
// applied to every URL.
type SubmitOptions struct {
	URLs      []string
	Tags      []string
	Anonymous bool
}

// submitErrors explains the plain-text answers the submission API gives when
// it rejects a request. The replies are not documented; these were observed
// against the live API. One answer can carry a reply per URL, run together,
// e.g. "illegal_threat: xillegal_url".
var submitErrors = map[string]string{
	"no_auth_key":      "no API key was sent: set ABUSECH_API_KEY",
	"unknown_auth_key": "the API key was not accepted: check ABUSECH_API_KEY",
	"user_unknown":     "your abuse.ch account is not known to URLhaus yet: log in once at https://urlhaus.abuse.ch/login/",
	"invalid_json":     "the API could not parse the submission",
	"no_data":          "the submission contained no URLs",
	"illegal_url":      "URLhaus rejected a URL as malformed",
	"illegal_threat":   "URLhaus rejected the threat type",
}

// SubmitURLs reports malware distribution URLs to URLhaus and returns the
// API's plain-text answer.
func (c *Client) SubmitURLs(ctx context.Context, opts SubmitOptions) (string, error) {
	if len(opts.URLs) == 0 {
		return "", fmt.Errorf("at least one URL is required")
	}
	for _, u := range opts.URLs {
		if err := ValidateURL(u); err != nil {
			return "", err
		}
	}
	for _, t := range opts.Tags {
		if err := ValidateTag(t); err != nil {
			return "", err
		}
	}

	submission := make([]map[string]interface{}, 0, len(opts.URLs))
	for _, u := range opts.URLs {
		entry := map[string]interface{}{
			"url":    u,
			"threat": "malware_download",
		}
		if len(opts.Tags) > 0 {
			entry["tags"] = opts.Tags
		}
		submission = append(submission, entry)
	}

	anonymous := "0"
	if opts.Anonymous {
		anonymous = "1"
	}

	payload, err := json.Marshal(map[string]interface{}{
		"anonymous":  anonymous,
		"submission": submission,
	})
	if err != nil {
		return "", fmt.Errorf("encoding submission: %w", err)
	}

	c.wait()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, submitURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "urlhs-client/1.0")
	req.Header.Set("Auth-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	answer := strings.TrimSpace(string(body))
	for token, msg := range submitErrors {
		if strings.Contains(answer, token) {
			return "", fmt.Errorf("%s (URLhaus answered: %s)", msg, answer)
		}
	}

	return answer, nil
}
