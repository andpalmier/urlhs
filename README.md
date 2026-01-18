# urlhs - URLhaus CLI Client

A command-line tool for interacting with the [URLhaus API](https://urlhaus-api.abuse.ch/).

> **Part of the abuse.ch CLI toolkit** - This project is part of a collection of CLI tools for interacting with [abuse.ch](https://abuse.ch) services:
> - [urlhs](https://github.com/andpalmier/urlhs) - URLhaus (malware URL database)
> - [tfox](https://github.com/andpalmier/tfox) - ThreatFox (IOC database)
> - [yrfy](https://github.com/andpalmier/yrfy) - YARAify (YARA scanning)
> - [mbzr](https://github.com/andpalmier/mbzr) - MalwareBazaar (malware samples)

[![Go Report Card](https://goreportcard.com/badge/github.com/andpalmier/urlhs)](https://goreportcard.com/report/github.com/andpalmier/urlhs)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Features

- ✅ Uses only Go standard libraries
- 📝 JSON output for easy parsing
- ⚡️ Built-in rate limiting (10 req/s)
- 🐳 Docker, Podman, and Apple container support

## Installation

### Using Homebrew

```bash
brew install andpalmier/tap/urlhs
```

### Using Go

```bash
go install github.com/andpalmier/urlhs@latest
```

### Using Container (Docker/Podman)

```bash
# Pull pre-built image
docker pull ghcr.io/andpalmier/urlhs:latest

# Or build locally
docker build -t urlhs .
```

### From Source

```bash
git clone https://github.com/andpalmier/urlhs.git
cd urlhs
make build
```

## Quick Start

1. **Get your API key** from [abuse.ch Authentication Portal](https://auth.abuse.ch/)

2. **Set your API key**:

```bash
export ABUSECH_API_KEY="your_api_key_here"
```

3. **Query recent URLs**:

```bash
urlhs recent -urls -limit 10
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `recent` | Query recent URLs or payloads |
| `query` | Query by URL, host, payload, tag, or signature |
| `download` | Download malware sample by SHA256 |
| `version` | Show version information |

### Query Recent Data

```bash
# Recent URLs
urlhs recent -urls -limit 50

# Recent payloads
urlhs recent -payloads -limit 50
```

### Query Information

```bash
# By URL
urlhs query -url "http://example.com/malware.exe"

# By host
urlhs query -host example.com

# By payload hash
urlhs query -hash 12c8aec5766ac3e6f26f2505e2f4a8f2

# By tag
urlhs query -tag Emotet

# By malware signature
urlhs query -signature Gozi
```

### Download Samples

```bash
urlhs download -sha256 <sha256_hash>
```

> **Warning**: Downloaded files are NOT password protected and may trigger antivirus alerts.

### Container Usage

```bash
# Run with Docker
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10

# Run with Podman
podman run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10

# Run with Apple container
container run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10

# Mount volume for downloads
docker run --rm -e ABUSECH_API_KEY="your_key" -v $(pwd):/data ghcr.io/andpalmier/urlhs download -sha256 <hash>
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ABUSECH_API_KEY` | Your abuse.ch API key (required) |

## License

This project is licensed under the AGPLv3 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [URLhaus](https://urlhaus.abuse.ch) by abuse.ch
- [abuse.ch](https://abuse.ch) for their work in fighting malware
