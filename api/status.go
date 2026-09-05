package api

import "fmt"

// StatusError is returned when the API answers with a query_status that
// indicates failure. It keeps the raw status so callers can match on it, and
// renders an explanation the user can act on.
type StatusError struct {
	Status string
	Query  string
}

func (e *StatusError) Error() string {
	if msg, ok := statusMessages[e.Status]; ok {
		return msg
	}
	if e.Query != "" {
		return fmt.Sprintf("the API rejected the %s query with status %q", e.Query, e.Status)
	}
	return fmt.Sprintf("the API returned status %q", e.Status)
}

// newStatusError returns nil when the status reports success, and a
// *StatusError describing the failure otherwise.
func newStatusError(status, query string) error {
	if status == "ok" {
		return nil
	}
	return &StatusError{Status: status, Query: query}
}

// statusMessages explains every query_status documented at
// https://urlhaus-api.abuse.ch/
var statusMessages = map[string]string{
	"no_results":         "the query returned no results",
	"http_get_expected":  "the API expected an HTTP GET request",
	"http_post_expected": "the API expected an HTTP POST request",
	"invalid_url":        "the API rejected that URL as malformed",
	"invalid_host":       "the API rejected that host as malformed",
	"invalid_md5":        "the API rejected that MD5 hash as malformed",
	"invalid_sha256":     "the API rejected that SHA256 hash as malformed",
	"not_found":          "that sample is unknown to URLhaus",
	"copy_error":         "URLhaus could not read its copy of that sample",
}
