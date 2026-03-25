package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// API constants
const (
	defaultAPIURL   = "https://urlhaus-api.abuse.ch/v1/"
	defaultTimeout  = 30 * time.Second
	maxResponseSize = 10 * 1024 * 1024 // prevents OOM from large responses (10MB)
)

// Client interacts with the URLhaus API
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
	interval   time.Duration
	lastReq    time.Time
}

// Option configures the Client
type Option func(*Client)

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.httpClient.Timeout = timeout
	}
}

// WithBaseURL sets the API base URL
func WithBaseURL(url string) Option {
	return func(c *Client) {
		c.baseURL = url
	}
}

// NewClient creates a new URLhaus API client
// Note: API key is required
func NewClient(apiKey string, options ...Option) *Client {
	c := &Client{
		apiKey:   apiKey,
		baseURL:  defaultAPIURL,
		interval: 100 * time.Millisecond, // 10 requests per second
		httpClient: &http.Client{
			Timeout: defaultTimeout,
		},
	}

	for _, opt := range options {
		opt(c)
	}

	return c
}

// wait handles simple rate limiting
func (c *Client) wait() {
	elapsed := time.Since(c.lastReq)
	if elapsed < c.interval {
		time.Sleep(c.interval - elapsed)
	}
	c.lastReq = time.Now()
}

// buildPostRequest creates an HTTP POST request with form data
func (c *Client) buildPostRequest(ctx context.Context, endpoint string, data map[string]string) (*http.Request, error) {
	formData := url.Values{}
	for key, value := range data {
		formData.Add(key, value)
	}

	reqURL := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "urlhs-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	return req, nil
}

// buildGetRequest creates an HTTP GET request
func (c *Client) buildGetRequest(ctx context.Context, endpoint string) (*http.Request, error) {
	reqURL := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", "urlhs-client/1.0")
	if c.apiKey != "" {
		req.Header.Set("Auth-Key", c.apiKey)
	}

	return req, nil
}

// MakePostRequest makes an HTTP POST request to the API and returns the response as a string
func (c *Client) MakePostRequest(ctx context.Context, endpoint string, data map[string]string) (string, error) {
	c.wait()

	req, err := c.buildPostRequest(ctx, endpoint, data)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if len(body) == maxResponseSize {
		return "", fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return string(body), nil
}

// MakeGetRequest makes an HTTP GET request to the API and returns the response as a string
func (c *Client) MakeGetRequest(ctx context.Context, endpoint string) (string, error) {
	c.wait()

	req, err := c.buildGetRequest(ctx, endpoint)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %s", resp.Status)
	}

	limitedReader := io.LimitReader(resp.Body, maxResponseSize)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if len(body) == maxResponseSize {
		return "", fmt.Errorf("response too large: exceeded %d bytes", maxResponseSize)
	}

	return string(body), nil
}

// MakeGetRequestRaw makes an HTTP GET request and returns the raw response body
func (c *Client) MakeGetRequestRaw(ctx context.Context, endpoint string) (io.ReadCloser, error) {
	c.wait()

	req, err := c.buildGetRequest(ctx, endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return nil, fmt.Errorf("closing response body: %w", closeErr)
		}
		return nil, fmt.Errorf("API returned status %s", resp.Status)
	}

	return resp.Body, nil
}
