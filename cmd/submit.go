package cmd

import (
	"flag"
	"fmt"
	"strings"

	"github.com/andpalmier/urlhs/api"
)

// repeatableFlag collects a flag that may be given more than once.
type repeatableFlag []string

func (r *repeatableFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatableFlag) Set(v string) error {
	if v == "" {
		return fmt.Errorf("value cannot be empty")
	}
	*r = append(*r, v)
	return nil
}

// executeSubmit handles the 'submit' subcommand
func executeSubmit(args []string) error {
	submitCmd := flag.NewFlagSet("submit", flag.ExitOnError)
	tags := submitCmd.String("tags", "", "Comma separated list of tags")
	anonymous := submitCmd.Bool("anonymous", false, "Hide your abuse.ch handle on the submission")
	var urls repeatableFlag
	submitCmd.Var(&urls, "url", "A malware URL to submit. Repeatable.")

	submitCmd.Usage = func() {
		printUsageHeader("submit", "Reports malware distribution URLs to URLhaus.")
		fmt.Println("\nFlags:")
		fmt.Println("  -url <url>               A malware URL to submit (required, repeatable)")
		fmt.Println("  -tags <tag1,tag2>        Comma separated tags, applied to every URL")
		fmt.Println("  -anonymous               Hide your abuse.ch handle on the submission")
		fmt.Println("\nExample:")
		fmt.Println("  urlhs submit -url http://evil.example/payload.exe -tags exe,AgentTesla")
		fmt.Println("\nOnly submit URLs that are online and serving a malware payload right now.")
		fmt.Println("No phishing, adware or URL shorteners. Read the submission policy first:")
		fmt.Println("  https://urlhaus.abuse.ch/api/#submit")
	}

	if err := submitCmd.Parse(args); err != nil {
		return err
	}

	if len(urls) == 0 {
		printError("you must specify at least one URL using -url")
		submitCmd.Usage()
		fmt.Println()
		return fmt.Errorf("missing URL")
	}

	var tagList []string
	if *tags != "" {
		tagList = strings.Split(*tags, ",")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return err
	}

	ctx, cancel := getContext()
	defer cancel()

	answer, err := client.SubmitURLs(ctx, api.SubmitOptions{
		URLs:      urls,
		Tags:      tagList,
		Anonymous: *anonymous,
	})
	if err != nil {
		printDetailedError(err, "Failed to submit URLs")
		return err
	}

	printSuccess(fmt.Sprintf("Submitted %d URL(s). URLhaus answered: %s", len(urls), answer))
	return nil
}
