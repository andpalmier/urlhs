# urlhs

CLI for the [URLhaus API](https://urlhaus-api.abuse.ch/). Look up malware URLs, hosts, and payloads, submit new URLs, and download bulk exports.

[![CI](https://github.com/andpalmier/urlhs/actions/workflows/ci.yml/badge.svg)](https://github.com/andpalmier/urlhs/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## Install

```bash
brew install --cask andpalmier/tap/urlhs
go install github.com/andpalmier/urlhs@latest
docker pull ghcr.io/andpalmier/urlhs:latest
```

Homebrew works on macOS only. On Linux, use Go or a release binary.

## Quick start

```bash
export ABUSECH_API_KEY="your_api_key_here"
urlhs recent -urls -limit 10
```

`query` can work without an API key for public lookups. Other commands need `ABUSECH_API_KEY`.

## Commands

- `recent`: list recently added URLs or payloads.
- `query`: look up a URL, host, payload, tag, or signature.
- `download`: fetch a payload by SHA256 hash.
- `export`: download a bulk export.
- `submit`: report malware distribution URLs.
- `version`: print version information.

## Examples

```bash
urlhs recent -urls -limit 50
urlhs recent -payloads -limit 50
urlhs query -url "http://example.com/malware.exe"
urlhs query -host example.com
urlhs query -tag Emotet
urlhs download -sha256 <hash> -out /tmp/sample.zip
urlhs submit -url http://evil.example/payload.exe -tags exe,AgentTesla
urlhs -t 10m export -file full.csv.zip -out /tmp/urlhaus.csv.zip
```

## Notes

- URLhaus keeps three days of data and returns at most 1000 entries.
- Downloads are ZIP files without password protection. Antivirus may quarantine them.
- Read the [submission policy](https://urlhaus.abuse.ch/api/#submit) before submitting.
- Exports rebuild every five minutes. `payload.csv.zip` is about 800 MB.
- Large exports need a longer `-t` timeout.

## Container

```bash
docker run --rm -e ABUSECH_API_KEY="your_key" ghcr.io/andpalmier/urlhs recent -urls -limit 10
docker run --rm -e ABUSECH_API_KEY="your_key" -v "$PWD":/data ghcr.io/andpalmier/urlhs download -sha256 <hash> -out /data/sample.zip
```

## License

AGPLv3. See [LICENSE](LICENSE).
