package api

import (
	"fmt"
	"regexp"
	"strings"
)

// sha256Regex matches valid SHA256 hashes (64 hexadecimal characters)
var sha256Regex = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// md5Regex matches valid MD5 hashes (32 hexadecimal characters)
var md5Regex = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

// tagRegex matches valid tags (alphanumeric, dots, dashes, spaces)
// Note: API documentation specifies [A-Za-z0-9.- ], underscores are NOT allowed
var tagRegex = regexp.MustCompile(`^[A-Za-z0-9. -]+$`)

// ValidateSHA256 checks if the input is a valid SHA256 hash
func ValidateSHA256(hash string) error {
	if !sha256Regex.MatchString(hash) {
		return fmt.Errorf("invalid SHA256 hash: must be 64 hexadecimal characters")
	}
	return nil
}

// ValidateMD5 checks if the input is a valid MD5 hash
func ValidateMD5(hash string) error {
	if !md5Regex.MatchString(hash) {
		return fmt.Errorf("invalid MD5 hash: must be 32 hexadecimal characters")
	}
	return nil
}

// ValidateHash checks if the input is either a valid SHA256 or MD5 hash
// Returns "sha256", "md5", or an error if neither
func ValidateHash(hash string) (string, error) {
	if sha256Regex.MatchString(hash) {
		return "sha256", nil
	}
	if md5Regex.MatchString(hash) {
		return "md5", nil
	}
	return "", fmt.Errorf("invalid hash: must be SHA256 (64 hex) or MD5 (32 hex)")
}

// ValidateTag checks if the input is a valid tag
func ValidateTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag cannot be empty")
	}
	if len(tag) > 100 {
		return fmt.Errorf("tag too long: maximum 100 characters")
	}
	if !tagRegex.MatchString(tag) {
		return fmt.Errorf("invalid tag: only alphanumeric characters, dots, dashes, and spaces allowed")
	}
	return nil
}

// ValidateURL performs basic URL validation
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}
	if len(urlStr) > 4096 {
		return fmt.Errorf("URL too long: maximum 4096 characters")
	}
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	return nil
}

// ValidateHost performs basic host validation
func ValidateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if len(host) > 255 {
		return fmt.Errorf("host too long: maximum 255 characters")
	}
	// Basic check: must contain at least one dot or be an IP address
	if !strings.Contains(host, ".") {
		return fmt.Errorf("invalid host format")
	}
	return nil
}

// ValidateURLID checks if the input is a valid URL ID (numeric)
func ValidateURLID(id string) error {
	if id == "" {
		return fmt.Errorf("URL ID cannot be empty")
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid URL ID: must be numeric")
		}
	}
	return nil
}

// ValidateSignature performs basic signature validation
func ValidateSignature(sig string) error {
	if sig == "" {
		return fmt.Errorf("signature cannot be empty")
	}
	if len(sig) > 100 {
		return fmt.Errorf("signature too long: maximum 100 characters")
	}
	return nil
}

// ValidateLimit checks if the limit is within acceptable range
func ValidateLimit(limit int) error {
	if limit < 0 {
		return fmt.Errorf("limit cannot be negative")
	}
	if limit > 1000 {
		return fmt.Errorf("limit too large: maximum 1000")
	}
	return nil
}
