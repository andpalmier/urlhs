package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/andpalmier/urlhs/api"
)

// Global flags
var (
	verbose bool
	// requestTimeout bounds a single API request. The default suits most
	// queries; large result sets need longer.
	requestTimeout = 30 * time.Second
)

// printRootHelp displays the help message for the root command
func printRootHelp() {
	fmt.Println("urlhs - URLhaus CLI Client")
	fmt.Println("  A command-line tool for interacting with the URLhaus API")
	fmt.Println("  Built by @andpalmier")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  urlhs [command] [flags]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  recent             Query recent URLs or payloads from URLhaus")
	fmt.Println("  query              Query URLhaus for URL, host, payload, tag, or signature info")
	fmt.Println("  download           Download a malware sample by SHA256 hash")
	fmt.Println("  version            Show version information")
	fmt.Println()
	fmt.Println("Global Flags:")
	fmt.Println("  -v, --verbose      Enable verbose output")
	fmt.Println("  -t, --timeout      Per-request timeout (default 30s, e.g. 2m)")
	fmt.Println("  -V, --version      Show version information")
	fmt.Println("  -h, --help         Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Query recent URLs")
	fmt.Println("  urlhs recent -urls -limit 10")
	fmt.Println()
	fmt.Println("  # Query recent payloads")
	fmt.Println("  urlhs recent -payloads -limit 10")
	fmt.Println()
	fmt.Println("  # Query by tag")
	fmt.Println("  urlhs query -tag Emotet")
	fmt.Println()
	fmt.Println("  # Query by host")
	fmt.Println("  urlhs query -host example.com")
	fmt.Println()
	fmt.Println("  # Download a sample")
	fmt.Println("  urlhs download -sha256 <sha256_hash>")
	fmt.Println()
	fmt.Println("Environment Variables:")
	fmt.Println("  ABUSECH_API_KEY    Your abuse.ch API key (required)")
	fmt.Println("                     Get one at https://auth.abuse.ch/")
	fmt.Println()
	fmt.Println("For more information about a command:")
	fmt.Println("  urlhs [command] --help")
}

// getAPIClient creates and returns an API client with the API key from environment
// Returns an error if the API key is not set
func getAPIClient() (*api.Client, error) {
	apiKey := os.Getenv("ABUSECH_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("ABUSECH_API_KEY environment variable is required. Get one at https://auth.abuse.ch/")
	}

	if verbose {
		printVerbose("Creating API client")
	}

	return api.NewClient(apiKey, api.WithTimeout(requestTimeout)), nil
}

// getContext returns a context with timeout and its cancel function
// Default timeout is 30 seconds for API requests
// Callers must defer cancel() to avoid context leaks
func getContext() (context.Context, context.CancelFunc) {
	if verbose {
		printVerbose(fmt.Sprintf("Setting request timeout to %v", requestTimeout))
	}

	return context.WithTimeout(context.Background(), requestTimeout)
}

// printUsageHeader prints a standard usage header for commands
func printUsageHeader(command, description string) {
	fmt.Printf("Usage:\n  urlhs %s [flags]\n", command)
	fmt.Println(description)
}

// printWarning prints a non-fatal warning
func printWarning(message string) {
	fmt.Fprintf(os.Stderr, "Warning: %s\n", message)
}

// reportNoResults tells the user the query succeeded but matched nothing.
// URLhaus answers no_results, which is not a failure, so this goes to stderr
// and the command still exits 0.
func reportNoResults(what, value string) {
	fmt.Fprintf(os.Stderr, "No results: URLhaus has nothing for %s %q\n", what, value)
}

// printError prints an error message
func printError(message string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", message)
}

// printDetailedError prints a detailed error message with context
func printDetailedError(err error, context string) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	if context != "" {
		fmt.Fprintf(os.Stderr, "Context: %s\n", context)
	}

	// Suggest solutions for common errors
	errStr := err.Error()
	for _, s := range errorSuggestions {
		if strings.Contains(errStr, s.keyword) {
			fmt.Fprintf(os.Stderr, "Solution: %s\n", s.solution)
			break
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Full error: %+v\n", err)
	}
}

// errorSuggestions maps a substring of an error to a suggested fix.
// Ordered, so that when several keywords match the hint shown is the same
// every run.
var errorSuggestions = []struct {
	keyword  string
	solution string
}{
	{"Unauthorized", "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here"},
	{"API key", "Set ABUSECH_API_KEY environment variable\n          export ABUSECH_API_KEY=your_key_here"},
	{"timeout", "The request timed out. Try again or check your network connection"},
	{"deadline exceeded", "The request timed out. Try again or check your network connection"},
	{"connection refused", "Cannot reach API. Check your internet connection"},
}

// printVerbose prints a verbose message
func printVerbose(message string) {
	fmt.Printf("[VERBOSE] %s\n", message)
}

// printSuccess prints a success message
func printSuccess(message string) {
	fmt.Println(message)
}

// printJSON prints data as indented JSON
func printJSON(data interface{}) {
	b, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		// Fallback to standard JSON if coloring fails
		fmt.Printf("%+v\n", data)
		return
	}
	fmt.Println(string(b))
}

// SetTimeout sets the per-request timeout
func SetTimeout(d time.Duration) {
	requestTimeout = d
}

// Timeout returns the per-request timeout
func Timeout() time.Duration {
	return requestTimeout
}

// SetVerbose sets the verbose flag (for testing)
func SetVerbose(v bool) {
	verbose = v
	// InitLogger(v)
}

// IsVerbose returns the verbose flag value
func IsVerbose() bool {
	return verbose
}
