# urlhs - URLhaus CLI client

A command-line client for the [URLhaus API](https://urlhaus-api.abuse.ch/). It looks up malware URLs, hosts, payloads, tags and signatures, and downloads the samples URLhaus has collected.

> Part of the abuse.ch CLI toolkit, a set of clients for [abuse.ch](https://abuse.ch) services:
> - [urlhs](https://github.com/andpalmier/urlhs) for URLhaus, the malware URL database
> - [tfox](https://github.com/andpalmier/tfox) for ThreatFox, the IOC database
> - [yrfy](https://github.com/andpalmier/yrfy) for YARAify, YARA scanning
> - [mbzr](https://github.com/andpalmier/mbzr) for MalwareBazaar, malware samples

[![CI](https://github.com/andpalmier/urlhs/actions/workflows/ci.yml/badge.svg)](https://github.com/andpalmier/urlhs/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

- Built on the Go standard library, with no third party dependencies
- Prints JSON, so you can pipe it into jq or anything else
- Rate limits itself to 10 requests per second
- Runs under Docker, Podman, and Apple container

## Installation

### Homebrew

```bash
brew install --cask andpalmier/tap/urlhs
```

Homebrew casks are macOS only. On Linux, use `go install` or a pre-built binary.

### Go

```bash
go install github.com/andpalmier/urlhs@latest
```

### Container

```bash
# Pull the pre-built image
docker pull ghcr.io/andpalmier/urlhs:latest

# Or build it yourself
docker build -t urlhs .
```

### From source

```bash
git clone https://github.com/andpalmier/urlhs.git
cd urlhs
make build
```

## Quick start

Get an API key from the [abuse.ch Authentication Portal](https://auth.abuse.ch/), export it, then query something:

```bash
export ABUSECH_API_KEY="your_api_key_here"
urlhs recent -urls -limit 10
```

Every command reads the key from `ABUSECH_API_KEY`. When the API refuses a request, urlhs prints the reason it gave rather than a bare status code. A query that simply matched nothing says so on stderr and still exits 0.

## Usage

### Global flags

These go before the command name.

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Print what the client is doing |
| `-t`, `--timeout` | Timeout per request, as a duration such as `45s` or `2m` (default `30s`) |
| `-V`, `--version` | Print version information |
| `-h`, `--help` | Print help |

### Commands

| Command | Description |
|---------|-------------|
| `recent` | List recently added URLs or payloads |
| `query` | Look up a URL, host, payload, tag or signature |
| `download` | Fetch a payload by SHA256 hash |
| `version` | Print version information |

### Recent additions

URLhaus keeps the last three days, and returns at most 1000 entries.

```bash
# Recent malware URLs
urlhs recent -urls -limit 50

# Recent payloads collected from those URLs
urlhs recent -payloads -limit 50
```

### Looking things up

```bash
# By URL
urlhs query -url "http://example.com/malware.exe"

# By the URLhaus database ID, when you have one
urlhs query -urlid 233833

# By host, which can be a domain, hostname or IPv4 address
urlhs query -host example.com

# By payload hash, MD5 or SHA256
urlhs query -hash 12c8aec5766ac3e6f26f2505e2f4a8f2

# By tag
urlhs query -tag Emotet

# By malware signature, which the reporter cannot influence
urlhs query -signature Gozi
```

A payload carries its hashes under `md5_hash` and `sha256_hash`, and its size under `file_size`. URLhaus spells these two different ways depending on the endpoint, so urlhs normalises them onto the documented names.

### Downloading payloads

```bash
urlhs download -sha256 <sha256_hash>

# Choose where it lands
urlhs download -sha256 <hash> -out /tmp/sample.zip
```

Without `-out` the file is written to `<sha256>.zip` in the current directory, and urlhs will not overwrite a file that already exists.

Unlike MalwareBazaar, URLhaus does not password protect these archives. Your antivirus will most likely quarantine the file the moment it lands, so download somewhere you have excluded from scanning.

### Running in a container

```bash
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10

podman run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10

container run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10
```

Downloads need a mounted volume, otherwise the sample disappears with the container:

```bash
docker run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/urlhs download -sha256 <hash> -out /data/sample.zip
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `ABUSECH_API_KEY` | Your abuse.ch API key. Required. |

## License

Licensed under the AGPLv3. See [LICENSE](LICENSE) for the full text.

## Acknowledgments

- [URLhaus](https://urlhaus.abuse.ch) by abuse.ch
- [abuse.ch](https://abuse.ch) for their work against malware
