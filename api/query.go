package api

import (
	"context"
	"fmt"
)

// QueryURL retrieves information about a specific URL
func (c *Client) QueryURL(ctx context.Context, url string) (*URLInfoResponse, error) {
	if err := ValidateURL(url); err != nil {
		return nil, err
	}

	data := map[string]string{
		"url": url,
	}

	response, err := c.MakePostRequest(ctx, "url/", data)
	if err != nil {
		return nil, fmt.Errorf("error querying URL: %w", err)
	}

	resp, err := ParseURLInfoResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return nil, nil
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}

// QueryURLID retrieves information about a URL by its ID
func (c *Client) QueryURLID(ctx context.Context, id string) (*URLInfoResponse, error) {
	if err := ValidateURLID(id); err != nil {
		return nil, err
	}

	data := map[string]string{
		"urlid": id,
	}

	response, err := c.MakePostRequest(ctx, "urlid/", data)
	if err != nil {
		return nil, fmt.Errorf("error querying URL ID: %w", err)
	}

	resp, err := ParseURLInfoResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return nil, nil
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}

// QueryHost retrieves information about a specific host
func (c *Client) QueryHost(ctx context.Context, host string) (*HostInfoResponse, error) {
	if err := ValidateHost(host); err != nil {
		return nil, err
	}

	data := map[string]string{
		"host": host,
	}

	response, err := c.MakePostRequest(ctx, "host/", data)
	if err != nil {
		return nil, fmt.Errorf("error querying host: %w", err)
	}

	resp, err := ParseHostInfoResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return nil, nil
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}

// QueryPayload retrieves information about a payload by its hash (MD5 or SHA256)
func (c *Client) QueryPayload(ctx context.Context, hash string) (*PayloadInfoResponse, error) {
	hashType, err := ValidateHash(hash)
	if err != nil {
		return nil, err
	}

	var data map[string]string
	if hashType == "sha256" {
		data = map[string]string{
			"sha256_hash": hash,
		}
	} else {
		data = map[string]string{
			"md5_hash": hash,
		}
	}

	response, err := c.MakePostRequest(ctx, "payload/", data)
	if err != nil {
		return nil, fmt.Errorf("error querying payload: %w", err)
	}

	resp, err := ParsePayloadInfoResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return nil, nil
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}

// QueryTag retrieves URLs associated with a specific tag
func (c *Client) QueryTag(ctx context.Context, tag string) (*TagInfoResponse, error) {
	if err := ValidateTag(tag); err != nil {
		return nil, err
	}

	data := map[string]string{
		"tag": tag,
	}

	response, err := c.MakePostRequest(ctx, "tag/", data)
	if err != nil {
		return nil, fmt.Errorf("error querying tag: %w", err)
	}

	resp, err := ParseTagInfoResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return nil, nil
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}

// QuerySignature retrieves URLs associated with a specific malware signature
func (c *Client) QuerySignature(ctx context.Context, signature string) (*SignatureInfoResponse, error) {
	if err := ValidateSignature(signature); err != nil {
		return nil, err
	}

	data := map[string]string{
		"signature": signature,
	}

	response, err := c.MakePostRequest(ctx, "signature/", data)
	if err != nil {
		return nil, fmt.Errorf("error querying signature: %w", err)
	}

	resp, err := ParseSignatureInfoResponse([]byte(response))
	if err != nil {
		return nil, fmt.Errorf("error parsing response: %w", err)
	}

	// Handle no_results as empty response, not an error
	if resp.QueryStatus == "no_results" {
		return nil, nil
	}

	if resp.QueryStatus != "ok" {
		return nil, fmt.Errorf("API returned status: %s", resp.QueryStatus)
	}

	return resp, nil
}
