package cmd

import "testing"

func TestExecuteQueryRejectsMultipleSelectors(t *testing.T) {
	err := executeQuery([]string{"-url", "https://example.com", "-host", "example.com"})
	if err == nil {
		t.Fatal("expected multiple query selectors to be rejected")
	}
}
