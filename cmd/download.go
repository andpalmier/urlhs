package cmd

import (
	"flag"
	"fmt"
)

// executeDownload handles the 'download' subcommand
func executeDownload(args []string) error {
	downloadCmd := flag.NewFlagSet("download", flag.ExitOnError)
	sha256 := downloadCmd.String("sha256", "", "SHA256 hash of the file to download")

	downloadCmd.Usage = func() {
		printUsageHeader("download", "Downloads a malware sample by its SHA256 hash from URLhaus.")
		fmt.Println("\nFlags:")
		fmt.Println("  -sha256 <sha256_hash>    SHA256 hash of the file to download")
		fmt.Println("\nNote:")
		fmt.Println("  The downloaded file is saved as <sha256>.zip")
		fmt.Println("  The ZIP archive is NOT password protected and may trigger antivirus alerts!")
	}

	if err := downloadCmd.Parse(args); err != nil {
		return err
	}

	if *sha256 == "" {
		printError("you must specify a SHA256 hash using -sha256")
		downloadCmd.Usage()
		fmt.Println()
		return fmt.Errorf("missing SHA256 hash")
	}

	client, err := getAPIClient()
	if err != nil {
		printDetailedError(err, "Failed to create API client")
		return fmt.Errorf("URLHAUS_API_KEY environment variable is required for downloading samples")
	}

	ctx, cancel := getContext()
	defer cancel()

	err = client.DownloadSample(ctx, *sha256)
	if err != nil {
		printDetailedError(err, fmt.Sprintf("Failed to download sample: %s", *sha256))
		return err
	}

	printSuccess(fmt.Sprintf("File downloaded successfully: %s.zip", *sha256))
	return nil
}
