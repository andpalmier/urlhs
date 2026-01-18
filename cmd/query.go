package cmd

import (
	"flag"
	"fmt"

	"github.com/andpalmier/urlhs/api"
)

// executeRecent handles the 'recent' subcommand
func executeRecent(args []string) error {
	recentCmd := flag.NewFlagSet("recent", flag.ExitOnError)
	urls := recentCmd.Bool("urls", false, "Query recent URLs")
	payloads := recentCmd.Bool("payloads", false, "Query recent payloads")
	limit := recentCmd.Int("limit", 0, "Limit the number of results (max 1000)")

	recentCmd.Usage = func() {
		printUsageHeader("recent", "Query recent URLs or payloads from URLhaus.")
		fmt.Println("\nFlags:")
		fmt.Println("  -urls              Query recent URLs (recent additions)")
		fmt.Println("  -payloads          Query recent payloads")
		fmt.Println("  -limit <number>    Limit the number of results (max 1000)")
		fmt.Println("\nExamples:")
		fmt.Println("  urlh recent -urls -limit 10")
		fmt.Println("  urlh recent -payloads -limit 50")
	}

	if len(args) < 1 {
		printError("expected -urls or -payloads flag")
		recentCmd.Usage()
		return fmt.Errorf("expected -urls or -payloads flag")
	}

	if err := recentCmd.Parse(args); err != nil {
		return err
	}

	if !*urls && !*payloads {
		printError("you must specify either -urls or -payloads")
		recentCmd.Usage()
		fmt.Println()
		return fmt.Errorf("you must specify either -urls or -payloads")
	}

	if *urls && *payloads {
		printError("you can only specify one of -urls or -payloads")
		recentCmd.Usage()
		fmt.Println()
		return fmt.Errorf("you can only specify one of -urls or -payloads")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	if *urls {
		results, err := client.QueryRecentURLs(ctx, *limit)
		if err != nil {
			printDetailedError(err, "Failed to query recent URLs")
			return err
		}
		printJSON(results)
	} else if *payloads {
		results, err := client.QueryRecentPayloads(ctx, *limit)
		if err != nil {
			printDetailedError(err, "Failed to query recent payloads")
			return err
		}
		printJSON(results)
	}

	return nil
}

// executeQuery handles the 'query' subcommand
func executeQuery(args []string) error {
	queryCmd := flag.NewFlagSet("query", flag.ExitOnError)
	url := queryCmd.String("url", "", "Query by URL")
	urlid := queryCmd.String("urlid", "", "Query by URL ID")
	host := queryCmd.String("host", "", "Query by host (domain or IP)")
	hash := queryCmd.String("hash", "", "Query payload by hash (MD5 or SHA256)")
	tag := queryCmd.String("tag", "", "Query by tag")
	signature := queryCmd.String("signature", "", "Query by malware signature")

	queryCmd.Usage = func() {
		printUsageHeader("query", "Query URLhaus for URL, host, payload, tag, or signature information.")
		fmt.Println("\nFlags:")
		fmt.Println("  -url <url>          Query information about a specific URL")
		fmt.Println("  -urlid <id>         Query information about a URL by its ID")
		fmt.Println("  -host <host>        Query information about a host (domain or IP)")
		fmt.Println("  -hash <hash>        Query payload information by MD5 or SHA256 hash")
		fmt.Println("  -tag <tag>          Query URLs associated with a tag")
		fmt.Println("  -signature <sig>    Query URLs associated with a malware signature")
		fmt.Println("\nExamples:")
		fmt.Println("  urlh query -tag Emotet")
		fmt.Println("  urlh query -host example.com")
		fmt.Println("  urlh query -signature Gozi")
		fmt.Println("  urlh query -hash 12c8aec5766ac3e6f26f2505e2f4a8f2")
	}

	if len(args) < 1 {
		printError("expected query arguments")
		queryCmd.Usage()
		return fmt.Errorf("expected query arguments")
	}

	if err := queryCmd.Parse(args); err != nil {
		return err
	}

	// Map flags to their values
	queryParams := map[string]*string{
		"url":       url,
		"urlid":     urlid,
		"host":      host,
		"hash":      hash,
		"tag":       tag,
		"signature": signature,
	}

	var selectedQuery string
	for key, val := range queryParams {
		if *val != "" {
			selectedQuery = key
			break
		}
	}

	if selectedQuery == "" {
		printError("please provide a query parameter (e.g., -url, -host, -tag)")
		queryCmd.Usage()
		fmt.Println()
		return fmt.Errorf("please provide a query parameter")
	}

	client, err := getAPIClient()
	if err != nil {
		// API key is optional for some queries, so we create a client without it
		client = api.NewClient("")
	}

	ctx, cancel := getContext()
	defer cancel()

	switch selectedQuery {
	case "url":
		result, err := client.QueryURL(ctx, *url)
		if err != nil {
			printDetailedError(err, "Failed to query URL")
			return err
		}
		printJSON(result)

	case "urlid":
		result, err := client.QueryURLID(ctx, *urlid)
		if err != nil {
			printDetailedError(err, "Failed to query URL ID")
			return err
		}
		printJSON(result)

	case "host":
		result, err := client.QueryHost(ctx, *host)
		if err != nil {
			printDetailedError(err, "Failed to query host")
			return err
		}
		printJSON(result)

	case "hash":
		result, err := client.QueryPayload(ctx, *hash)
		if err != nil {
			printDetailedError(err, "Failed to query payload")
			return err
		}
		printJSON(result)

	case "tag":
		result, err := client.QueryTag(ctx, *tag)
		if err != nil {
			printDetailedError(err, "Failed to query tag")
			return err
		}
		printJSON(result)

	case "signature":
		result, err := client.QuerySignature(ctx, *signature)
		if err != nil {
			printDetailedError(err, "Failed to query signature")
			return err
		}
		printJSON(result)

	default:
		return fmt.Errorf("unknown query type: %s", selectedQuery)
	}

	return nil
}
