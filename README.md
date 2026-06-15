# Snitch v2 — Modern OSINT Dork Scanner

Snitch automates information gathering for specified domains using Google Dork queries. It searches across multiple search engines to find sensitive files, exposed configurations, error pages, and other security-relevant content.

**Rewritten from scratch for Python 3.12+ (2026).** Original: [github.com/Smaash](https://github.com/Smaash) (v0.3.2, Python 2).

## Features

- **4 Search Engines**: DuckDuckGo, Bing, Google, SearXNG (with fallback)
- **Async Engine**: `asyncio` + `aiohttp` concurrent scraping
- **120+ Dork Signatures**: Updated for 2026 — cloud keys, K8s APIs, modern CMS, API gateways
- **Multiple Output Formats**: Plain text, JSON, CSV
- **Proxy Support**: SOCKS5 / HTTP
- **Anti-Detection**: UA rotation, rate limiting, CAPTCHA handling

## Installation

```bash
pip install -r requirements.txt
```

### Requirements

```
aiohttp>=3.11.0
```

Optional: `PySocks>=1.7.1` (for SOCKS proxy)

## Usage

```bash
# Basic scan — all dork types against a domain
python snitch.py -U example.com -D all

# Multiple targets with specific types, JSON output
python snitch.py -U gov,edu -D ext,info -P 20 --json

# Custom dork query with proxy
python snitch.py -C "site:target.com ext:bak" --proxy socks5://127.0.0.1:9050

# Use self-hosted SearXNG instance
python snitch.py -U target.com -D soft --searxng https://my-searx.example.com

# CSV output to file
python snitch.py -U example.com -D files,ext --csv -O results.csv

# Verbose mode with custom engines
python snitch.py -U example.com -D info -v --engines duckduckgo,bing
```

### Options

| Option | Description |
|--------|-------------|
| `-U URL` | Target domain(s) or TLD(s), comma-separated |
| `-C DORK` | Custom dork query (bypasses predefined categories) |
| `-D TYPE` | Dork type: `info`, `ext`, `docs`, `files`, `soft`, `all` (default: `all`) |
| `-O FILE` | Output file path |
| `-S URL` | Proxy (`socks5://ip:port` or `http://ip:port`) |
| `-I SEC` | Request interval in seconds (default: 1.5) |
| `-P N` | Max pages per dork (default: 10) |
| `--timeout SEC` | HTTP timeout (default: 15) |
| `-v` | Verbose output |
| `--json` | Output in JSON format |
| `--csv` | Output in CSV format |
| `--engines LIST` | Comma-separated engines: `duckduckgo`, `bing`, `google`, `searxng` |
| `--searxng URL` | Custom SearXNG instance URL |

### Dork Types

| Type | Description |
|------|-------------|
| `info` | SQL errors, app stack traces, framework exceptions |
| `ext` | Sensitive extensions (`.bak`, `.env`, `.key`, SSH keys) |
| `docs` | Documents & messages (PDF, XLS, email files) |
| `files` | Admin panels, config backups, directory listings, DevOps endpoints |
| `soft` | Web software detection (CMS, frameworks, monitoring tools, K8s/Docker) |
| `all` | All of the above |

## Example Output

```
$ python snitch.py -D ext -U gov -P5

╔══════════════════════════════════════════════════════════════════════════╗
║  Snitch v2.0.0  —  OSINT Dork Scanner for the 2020s                    ║
╚══════════════════════════════════════════════════════════════════════════╝

[*] Targets: gov
[*] Engines: duckduckgo, bing, google
[*] Dorks: 15 queries x 1 targets x 3 engines
[*] Max pages/dork: 5

  [duckduckgo] http://www.seismic.ca.gov/pub/CSSC_1998-01_COG.pdf.OLD
  [duckduckgo] http://greengenes.lbl.gov/Download/Sequence_Data/Fasta_data_files/CoreSet_2010/formatdb.log
  [bing] https://software.sandia.gov/trac/canary/attachment/ticket/3917/Pike_Hach%26SCAN_Oracle.edsx_convert.log
  [google] http://web.epa.ohio.gov/phpMyAdmin.2.11.5/scripts/create_tables_mysql_4_1_2+.sql
  ...

============================================================
[+] Done! Found 42 unique URLs in 23.1s
============================================================

Engine           Req     OK   Fail  URLs Status
────────────────────────────────────────────────────────────
duckduckgo         15    12      3    18 OK
bing               15    10      5    14 OK
google             15     8      7    10 BLOCKED

Category       URLs
───────────────────
ext              28
custom            0

[+] Text saved: results.txt (42 URLs)
```

## Architecture

```
snitch.py (CLI)
  └── SnitchScanner (orchestrator)
        ├── DuckDuckGoEngine  (HTML scraper)
        ├── BingEngine        (HTML scraper)
        ├── GoogleEngine      (HTML scraper + anti-bot)
        └── SearXNGEngine     (meta-search, self-hostable)
              ↓
        SearchResult → Dedup → Output (Text/JSON/CSV)
```

## Changelog

### v2.0.0 (2026)
- Complete rewrite from Python 2 to Python 3.12+
- Replaced all 5 dead search engines with 4 working ones (DDG/Bing/Google/SearXNG)
- Added async concurrency with `asyncio` + `aiohttp`
- Expanded dork database from ~60 to ~120+ signatures
- Added modern fingerprints: AWS keys, Terraform state, Docker/K8s APIs, Swagger/OpenAPI, Grafana/Prometheus/Jaeger
- Added JSON and CSV output formats
- Added SOCKS5/HTTP proxy support
- Added engine-level statistics and blocking detection
- Type-safe codebase with dataclasses and enums

### v0.3.2 (Original)
- Fixed socks import, logo printing on Windows, loop using 'all' dork types
- More search engines (now defunct)
- Custom dorks / multiple targets support

## License

Original project: [github.com/Smaash/snitch](https://github.com/Smaash/snitch)

This rewrite maintains the same spirit — an OSINT tool for authorized security testing only.
