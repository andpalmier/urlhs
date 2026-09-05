package api

import (
	"context"
	"fmt"
)

// QueryRecentURLs retrieves recently added URLs from URLhaus
func (c *Client) QueryRecentURLs(ctx context.Context, limit int) ([]URLEntry, error) {
	endpoint := "urls/recent/"
	if limit > 0 {
		if err := ValidateLimit(limit); err != nil {
			return nil, err
		}
		endpoint = fmt.Sprintf("urls/recent/limit/%d/", limit)
	}

	response, err := c.MakeGetRequest(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("error retrieving recent URLs: %w", err)
	}

	resp, err := ParseRecentURLsResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return []URLEntry{}, nil
	}

	if err := newStatusError(resp.QueryStatus, "urls/recent"); err != nil {
		return nil, err
	}

	return resp.URLs, nil
}

// QueryRecentPayloads retrieves recently added payloads from URLhaus
func (c *Client) QueryRecentPayloads(ctx context.Context, limit int) ([]Payload, error) {
	endpoint := "payloads/recent/"
	if limit > 0 {
		if err := ValidateLimit(limit); err != nil {
			return nil, err
		}
		endpoint = fmt.Sprintf("payloads/recent/limit/%d/", limit)
	}

	response, err := c.MakeGetRequest(ctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("error retrieving recent payloads: %w", err)
	}

	resp, err := ParseRecentPayloadsResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return []Payload{}, nil
	}

	if err := newStatusError(resp.QueryStatus, "payloads/recent"); err != nil {
		return nil, err
	}

	return resp.Payloads, nil
}
