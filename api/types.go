package api

import "encoding/json"

// RecentURLsResponse represents the response from the recent URLs endpoint
type RecentURLsResponse struct {
	QueryStatus string     `json:"query_status"`
	URLs        []URLEntry `json:"urls,omitempty"`
}

// RecentPayloadsResponse represents the response from the recent payloads endpoint
type RecentPayloadsResponse struct {
	QueryStatus string    `json:"query_status"`
	Payloads    []Payload `json:"payloads,omitempty"`
}

// URLInfoResponse represents the response from the URL info endpoint
type URLInfoResponse struct {
	QueryStatus         string      `json:"query_status"`
	ID                  json.Number `json:"id,omitempty"`
	URLHausReference    string      `json:"urlhaus_reference,omitempty"`
	URL                 string      `json:"url,omitempty"`
	URLStatus           string      `json:"url_status,omitempty"`
	Host                string      `json:"host,omitempty"`
	DateAdded           string      `json:"date_added,omitempty"`
	LastOnline          *string     `json:"last_online,omitempty"`
	Threat              string      `json:"threat,omitempty"`
	Blacklists          Blacklists  `json:"blacklists,omitempty"`
	Reporter            string      `json:"reporter,omitempty"`
	Larted              string      `json:"larted,omitempty"`
	TakedownTimeSeconds *int        `json:"takedown_time_seconds,omitempty"`
	Tags                []string    `json:"tags,omitempty"`
	Payloads            []Payload   `json:"payloads,omitempty"`
}

// HostInfoResponse represents the response from the host info endpoint
type HostInfoResponse struct {
	QueryStatus      string     `json:"query_status"`
	URLHausReference string     `json:"urlhaus_reference,omitempty"`
	Host             string     `json:"host,omitempty"`
	FirstSeen        string     `json:"firstseen,omitempty"`
	URLCount         string     `json:"url_count,omitempty"`
	Blacklists       Blacklists `json:"blacklists,omitempty"`
	URLs             []URLEntry `json:"urls,omitempty"`
}

// PayloadInfoResponse represents the response from the payload info endpoint
type PayloadInfoResponse struct {
	QueryStatus     string       `json:"query_status"`
	MD5Hash         string       `json:"md5_hash,omitempty"`
	SHA256Hash      string       `json:"sha256_hash,omitempty"`
	FileType        string       `json:"file_type,omitempty"`
	FileSize        string       `json:"file_size,omitempty"`
	Signature       *string      `json:"signature,omitempty"`
	FirstSeen       string       `json:"firstseen,omitempty"`
	LastSeen        string       `json:"lastseen,omitempty"`
	URLCount        string       `json:"url_count,omitempty"`
	URLHausDownload string       `json:"urlhaus_download,omitempty"`
	VirusTotal      *VirusTotal  `json:"virustotal,omitempty"`
	Imphash         string       `json:"imphash,omitempty"`
	SSDeep          string       `json:"ssdeep,omitempty"`
	TLSH            string       `json:"tlsh,omitempty"`
	URLs            []PayloadURL `json:"urls,omitempty"`
}

// TagInfoResponse represents the response from the tag info endpoint
type TagInfoResponse struct {
	QueryStatus string   `json:"query_status"`
	FirstSeen   string   `json:"firstseen,omitempty"`
	LastSeen    string   `json:"lastseen,omitempty"`
	URLCount    string   `json:"url_count,omitempty"`
	URLs        []TagURL `json:"urls,omitempty"`
}

// SignatureInfoResponse represents the response from the signature info endpoint
type SignatureInfoResponse struct {
	QueryStatus  string         `json:"query_status"`
	FirstSeen    string         `json:"firstseen,omitempty"`
	LastSeen     string         `json:"lastseen,omitempty"`
	URLCount     string         `json:"url_count,omitempty"`
	PayloadCount string         `json:"payload_count,omitempty"`
	URLs         []SignatureURL `json:"urls,omitempty"`
}

// URLEntry represents a URL entry from URLhaus
type URLEntry struct {
	ID                  json.Number `json:"id"`
	URLHausReference    string      `json:"urlhaus_reference"`
	URL                 string      `json:"url"`
	URLStatus           string      `json:"url_status"`
	Host                string      `json:"host"`
	DateAdded           string      `json:"date_added"`
	Threat              string      `json:"threat"`
	Blacklists          Blacklists  `json:"blacklists,omitempty"`
	Reporter            string      `json:"reporter"`
	Larted              string      `json:"larted"`
	TakedownTimeSeconds *int        `json:"takedown_time_seconds,omitempty"`
	Tags                []string    `json:"tags,omitempty"`
}

// Blacklists represents blacklist status from various sources
type Blacklists struct {
	SpamhausDBL string `json:"spamhaus_dbl"`
	SURBL       string `json:"surbl"`
}

// Payload represents a payload/malware sample
type Payload struct {
	FirstSeen       string      `json:"firstseen"`
	Filename        string      `json:"filename"`
	FileType        string      `json:"file_type"`
	ResponseSize    string      `json:"response_size"`
	ResponseMD5     string      `json:"response_md5"`
	ResponseSHA256  string      `json:"response_sha256"`
	URLHausDownload string      `json:"urlhaus_download"`
	Signature       *string     `json:"signature"`
	VirusTotal      *VirusTotal `json:"virustotal"`
	Imphash         string      `json:"imphash"`
	SSDeep          string      `json:"ssdeep"`
	TLSH            string      `json:"tlsh"`
	Magika          string      `json:"magika,omitempty"`
}

// PayloadURL represents a URL associated with a payload
type PayloadURL struct {
	URLID            string `json:"url_id"`
	URL              string `json:"url"`
	URLStatus        string `json:"url_status"`
	URLHausReference string `json:"urlhaus_reference"`
	FirstSeen        string `json:"firstseen"`
	LastSeen         string `json:"lastseen"`
}

// TagURL represents a URL entry from tag query
type TagURL struct {
	URLID            string `json:"url_id"`
	URL              string `json:"url"`
	URLStatus        string `json:"url_status"`
	DateAdded        string `json:"dateadded"`
	Reporter         string `json:"reporter"`
	Threat           string `json:"threat"`
	URLHausReference string `json:"urlhaus_reference"`
}

// SignatureURL represents a URL entry from signature query
type SignatureURL struct {
	URLID            string      `json:"url_id"`
	URL              string      `json:"url"`
	URLStatus        string      `json:"url_status"`
	FirstSeen        string      `json:"firstseen"`
	LastSeen         string      `json:"lastseen"`
	Filename         string      `json:"filename"`
	FileType         string      `json:"file_type"`
	FileSize         string      `json:"file_size"`
	MD5Hash          string      `json:"md5_hash"`
	SHA256Hash       string      `json:"sha256_hash"`
	VirusTotal       *VirusTotal `json:"virustotal"`
	Imphash          string      `json:"imphash"`
	SSDeep           string      `json:"ssdeep"`
	TLSH             string      `json:"tlsh"`
	Magika           string      `json:"magika,omitempty"`
	URLHausReference string      `json:"urlhaus_reference"`
	URLHausDownload  string      `json:"urlhaus_download"`
}

// VirusTotal represents VirusTotal detection information
type VirusTotal struct {
	Result  string `json:"result"`
	Percent string `json:"percent"`
	Link    string `json:"link"`
}

// ParseRecentURLsResponse parses the raw JSON response into a RecentURLsResponse struct
func ParseRecentURLsResponse(data []byte) (*RecentURLsResponse, error) {
	var resp RecentURLsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseRecentPayloadsResponse parses the raw JSON response into a RecentPayloadsResponse struct
func ParseRecentPayloadsResponse(data []byte) (*RecentPayloadsResponse, error) {
	var resp RecentPayloadsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseURLInfoResponse parses the raw JSON response into a URLInfoResponse struct
func ParseURLInfoResponse(data []byte) (*URLInfoResponse, error) {
	var resp URLInfoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseHostInfoResponse parses the raw JSON response into a HostInfoResponse struct
func ParseHostInfoResponse(data []byte) (*HostInfoResponse, error) {
	var resp HostInfoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParsePayloadInfoResponse parses the raw JSON response into a PayloadInfoResponse struct
func ParsePayloadInfoResponse(data []byte) (*PayloadInfoResponse, error) {
	var resp PayloadInfoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseTagInfoResponse parses the raw JSON response into a TagInfoResponse struct
func ParseTagInfoResponse(data []byte) (*TagInfoResponse, error) {
	var resp TagInfoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseSignatureInfoResponse parses the raw JSON response into a SignatureInfoResponse struct
func ParseSignatureInfoResponse(data []byte) (*SignatureInfoResponse, error) {
	var resp SignatureInfoResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
