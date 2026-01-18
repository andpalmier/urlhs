package api

import "testing"

func TestValidateSHA256(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"valid lowercase", "88d862aeb067278155c67a6d4e5be927b36f08149c950d75a3a419eb20560aa1", false},
		{"valid uppercase", "88D862AEB067278155C67A6D4E5BE927B36F08149C950D75A3A419EB20560AA1", false},
		{"too short", "88d862", true},
		{"too long", "88d862aeb067278155c67a6d4e5be927b36f08149c950d75a3a419eb20560aa1a", true},
		{"invalid chars", "y8d862aeb067278155c67a6d4e5be927b36f08149c950d75a3a419eb20560aa1", true},
		{"empty", "", true},
		{"whitespace", " 88d862aeb067278155c67a6d4e5be927b36f08149c950d75a3a419eb20560aa1 ", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSHA256(tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("ValidateSHA256() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMD5(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		wantErr bool
	}{
		{"valid lowercase", "d41d8cd98f00b204e9800998ecf8427e", false},
		{"valid uppercase", "D41D8CD98F00B204E9800998ECF8427E", false},
		{"too short", "d41d8c", true},
		{"too long", "d41d8cd98f00b204e9800998ecf8427e1", true},
		{"invalid chars", "z41d8cd98f00b204e9800998ecf8427e", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateMD5(tt.hash); (err != nil) != tt.wantErr {
				t.Errorf("ValidateMD5() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTag(t *testing.T) {
	tests := []struct {
		name    string
		tag     string
		wantErr bool
	}{
		{"valid simple", "Emotet", false},
		{"valid dots", "Win.Emotet", false},
		{"valid underscore", "Win_Emotet", false},
		{"too short", "E", false},
		{"too long", "ThisTagIsWayTooLongAndShouldDefinitelyFailBecauseItExceedsTheLimitOfSixtyFourCharactersWhichIsArbitraryButGood", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTag(tt.tag); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		urlStr  string
		wantErr bool
	}{
		{"valid http", "http://example.com/malware.exe", false},
		{"valid https", "https://example.com/malware.exe", false},
		{"valid ip", "http://1.2.3.4/bin.sh", false},
		{"no scheme", "example.com/malware.exe", true},
		{"ftp", "ftp://example.com", true}, // Assuming validation rejects non-http/https
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateURL(tt.urlStr); (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
