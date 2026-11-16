package cmd

import "testing"

func TestCommandValidationRejectsBeforeNetwork(t *testing.T) {
	tests := []struct {
		name string
		fn   func([]string) error
		args []string
	}{
		{"recent no type", executeRecent, []string{}},
		{"recent both types", executeRecent, []string{"-urls", "-payloads"}},
		{"query no selector", executeQuery, []string{}},
		{"query multiple selectors", executeQuery, []string{"-url", "https://evil.example/", "-host", "evil.example"}},
		{"submit missing url", executeSubmit, nil},
		{"download missing hash", executeDownload, nil},
		{"export missing file", executeExport, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(tt.args); err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestRepeatableFlag(t *testing.T) {
	var r repeatableFlag
	if err := r.Set(""); err == nil {
		t.Error("empty value accepted")
	}
	if err := r.Set("https://evil.example/"); err != nil {
		t.Fatal(err)
	}
	if got := r.String(); got != "https://evil.example/" {
		t.Errorf("String() = %q", got)
	}
}
