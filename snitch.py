#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Snitch v2.0 — Modern OSINT Dork Scanner
Rewritten from scratch for Python 3.12+ (2026)

Original: github.com/Smaash (v0.3.2, Python 2)
Rewrite:  Async engine | Modern search engines | Type-safe | Rich output

Usage:
    python snitch.py -U example.com -D all -O results.txt
    python snitch.py -U gov,edu -D ext,info -P 20 --json
    python snitch.py -C "site:target.com ext:bak" --proxy socks5://127.0.0.1:9050
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import signal
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import AsyncIterator, Optional

import aiohttp

# ─── Constants ───────────────────────────────────────────────────────────────

VERSION = "2.0.0"
BANNER = f"""\
\u256d\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256e
\u2502  Snitch v{VERSION}  —  OSINT Dork Scanner for the 2020s                \u2502
\u2570\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u256f\
"""

DEFAULT_INTERVAL = 1.5          # seconds between requests per engine
DEFAULT_PAGES = 10              # max pages per dork per engine
DEFAULT_TIMEOUT = 15            # HTTP timeout in seconds
MAX_CONCURRENT = 5              # max parallel search tasks

# URL patterns to filter out (noise / non-target)
NOISE_PATTERNS = [
    r"facebook\.com",
    r"stackoverflow\.com",
    r"php\.net",
    r"drupal\.org",
    r"wordpress\.org",
    r"youtube\.(com|be)",
    r"github\.com",
    r"wikipedia\.org",
    r"trendmicro\.com",
    r"sophos\.com",
]

# ─── User-Agent Rotation (2026-current) ──────────────────────────────────────

USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]


# ─── Dork Database (2026-updated) ────────────────────────────────────────────

class DorkCategory(Enum):
    """Predefined dork categories."""
    INFO = "info"
    EXT = "ext"
    DOCS = "docs"
    FILES = "files"
    SOFT = "soft"
    ALL = "all"


DORK_DB: dict[DorkCategory, tuple[str, ...]] = {
    DorkCategory.INFO: (
        # ── SQL Error Leaks ──
        '"supplied argument is not a valid MySQL result resource"',
        '"You have an error in your SQL syntax"',
        '"Unable to jump to row" "on MySQL result index"',
        'intext:"mysql_fetch_assoc()" OR intext:"mysql_fetch_object()"',
        'intext:"Warning: mysql_connect(): Access denied for user"',
        # ── DB2 / MSSQL / Oracle / PostgreSQL ──
        'intext:"detected an internal error [IBM][CLI Driver][DB2]"',
        'intext:"MSSQL_OLEdb : Microsoft OLE DB Provider for SQL Server"',
        'intext:"ORA-00936: missing expression"',
        'intext:"PostgreSQL query failed: ERROR: parser:"',
        # ── Generic App Errors ──
        'intext:"Server Error in \'/\' Application"',
        'intitle:"Apache Tomcat" "Error Report"',
        'intext:"ADODB.Field" OR intext:"ADODB.Command"',
        'intext:"Input string was not in a correct format"',
        'intext:"Warning: Cannot modify header information - headers already sent"',
        'intext:"Fatal error: Class \'" not found in"',
        'intext:"[function.getimagesize]: failed to open stream"',
        # ── Framework-specific (2026 additions) ──
        'intext:"SyntaxError" "Unexpected token" inurl:".js" site:',   # JS stack traces
        'intext:"Traceback (most recent call last)" site:',            # Python errors exposed
        'intext:"Exception" "at " inurl:".aspx" site:',               # .NET stack traces
        'intext:"java.lang.Exception" site:',                          # Java errors
        'intext:"TypeError: Cannot read properties" site:',             # Node.js errors
        'inurl:"/api/" intext:"error" intext:"message" intext:"status"',  # REST API errors
        'inurl:"/graphql" intext:"errors"',                             # GraphQL errors
    ),

    DorkCategory.EXT: (
        # ── Sensitive File Extensions ──
        "ext:bak OR ext:old OR ext:tmp OR ext:log OR ext:sql",
        "ext:inc OR ext:conf OR ext:cfg OR ext:ini OR ext:reg OR ext:env",
        "ext:swp OR ext:swo",                                          # Vim swap files
        "ext:DS_Store",                                                 # macOS metadata
        "ext:gitignore OR ext:htpasswd OR ext:htaccess",
        # ── Cloud/CI Configs (2026 additions) ──
        'filetype:yml "aws_access_key_id" OR "secret_key"',
        'filetype:env "DB_PASSWORD" OR "API_KEY" OR "SECRET"',
        'filetype:json "api_key" OR "apikey" OR "token"',
        'filetype:pem "PRIVATE KEY"',
        'filetype:key "BEGIN RSA PRIVATE KEY"',
        'inurl:".terraform" ext:tfstate',
        'filetype:ppk "PuTTY-User-Key-File"',                           # SSH keys
        'inurl:"id_rsa" OR inurl:"id_dsa" -github',                    # Exposed SSH keys
        'filetype:credentials "password"',
    ),

    DorkCategory.DOCS: (
        "ext:cvs OR ext:xls OR ext:xlsx OR ext:ppt OR ext:pptx",
        "ext:pdf OR ext:docx OR ext:doc OR ext:rtf OR ext:odt",
        "ext:msg OR ext:eml",                                          # Email files
        # ── Sensitive Document Patterns (2026 additions) ──
        'filetype:pdf "confidential" OR "internal use only"',
        'filetype:xls "salary" OR "payroll" OR "compensation"',
        'filetype:csv "password" OR "email" OR "username"',
        'filetype:sql "INSERT INTO" "users" -github',
        'filetype:xml "database" OR "connectionString"',
    ),

    DorkCategory.FILES: (
        # ── Directory Listings ──
        'intitle:"index of" OR "Index of /backup"',
        'intitle:"index of" inurl:.mysql_history OR inurl:.bash_history',
        'intitle:"index of" ws_ftp.ini',
        # ── Admin Panels ──
        "inurl:admin OR inurl:administrator intitle:login",
        'inurl:admin.php OR inurl:administrator.php OR inurl:cms.php',
        'inurl:"wp-login.php" OR inurl:"wp-admin"',
        'inurl:"phpMyAdmin" OR inurl:"phpPgAdmin" OR inurl:"myadmin"',
        'inurl:"jenkins/login" OR inurl:"jmx-console"',
        'inurl:"solr/admin"',
        'inurl:kibana/app',
        'inurl:"grafana/login"',
        # ── Config & Backup Files ──
        'inurl:configuration.php-dist OR inurl:config.php.bak',
        'inurl:web.config.bak OR inurl:web.config.old',
        'allinurl:install.php OR upgrade.php OR setup.php',
        'inurl:server-status intext:"Apache"',
        'intitle:phpinfo "PHP Version"',
        "# phpMyAdmin MySQL-Dump ext:sql",
        # ── Cloud Storage / CI / DevOps (2026 additions) ──
        'inurl:".well-known/" OR inurl:"security.txt" OR inurl:"humans.txt"',
        'inurl:"/.git/config" OR inurl:"/.svn/entries"',
        'inurl:"/env" OR inurl:"/.env" ext:',
        'inurl:"/actuator" OR inurl:"/actuator/env"',                   # Spring Boot
        'inurl:"/swagger-ui.html" OR inurl:"/swagger-resources"',
        'inurl:"/console" intitle:"RabbitMQ"',                         # RabbitMQ
        'inurl:"/_cluster/health"',                                     # Elasticsearch
        'inurl:"/metrics"',                                             # Prometheus-style
        # ── Archive Files ──
        "ext:zip OR ext:rar OR ext:gz OR ext:tar.gz OR ext:tar OR ext:7z",
        # ── Misc Info ──
        "file:robots.txt",
        "file:crossdomain.xml",
        "file:sitemap.xml",
    ),

    DorkCategory.SOFT: (
        # ── CMS / Framework Detection ──
        'intext:"Powered by WordPress" OR inurl:"wp-content"',
        'intext:"Powered by Drupal" OR inurl:"sites/default"',
        'intext:"Powered by Joomla"',
        'intext:"Powered by Laravel" inurl:"laravel"',
        'intext:"Powered by Django" inurl:"admin"',
        'intext:"Express" inurl:"package.json" -github',
        'intext:"Next.js" inurl:"_next/static"',
        'intext:"Nuxt.js" OR intext:"nuxt"',
        'intext:"Vue.js" intitle:"devtools"',
        'intext:"React" inurl:"static/js/"',
        # ── Editors / Uploaders ──
        '"index of" intext:fckeditor inurl:fckeditor',
        'inurl:/tiny_mce/ OR inurl:/tinymce/',
        'inurl:/kindeditor/ OR inurl:/ckeditor/',
        'inurl:/elfinder/ OR inurl:/filemanager/',
        # ── Web Servers ──
        'intitle:"Apache Status" "Apache Server Status for"',
        'intitle:"Apache Tomcat" "Error Report"',
        '"Microsoft-IIS" intitle:index.of',
        'intitle:"Welcome to nginx!"',
        'intitle:"cPanel" OR intitle:"WHM"',
        'intitle:"Plesk"',
        # ── E-commerce ──
        'intext:"Powered by Shopify"',
        'intext:"Powered by PrestaShop"',
        'intext:"Powered by Magento" OR inurl:magento',
        'intext:"WooCommerce" inurl:"wp-content/plugins/woocommerce"',
        # ── Forums / Wiki ──
        'intext:"Powered by vBulletin"',
        'intext:"Powered by XenForo"',
        'intext:"Powered by Discourse" OR inurl:discourse',
        'intext:"Powered by MediaWiki"',
        # ── Mail / Collaboration ──
        'intitle:"Zimbra Web Client"',
        'intitle:"RoundCube Webmail" OR intitle:"Horde" OR intitle:"SquirrelMail"',
        'intitle:"Microsoft Outlook Web Access" OR intitle:"OWA"',
        'intitle:"Nextcloud" OR intitle:"ownCloud"',
        # ── Analytics / Monitoring (2026 additions) ──
        'intitle:"Grafana" OR intitle:"Grafana Login"',
        'intitle:"Prometheus" "Time Series Collection"',
        'intitle:"Jaeger UI" OR intitle:"Jaeger tracing"',
        'intitle:"Kibana" OR inurl:"app/kibana"',
        'intitle:"Elasticsearch" "cluster_health"',
        # ── Container / K8s ──
        'inurl:"/v1.24/version" OR inurl:"/version" intext:"kubelet"',  # Kubernetes
        'inurl:"/containers/json"',                                       # Docker API
        'inurl:"/api/v1/namespaces"',                                     # K8s API
        # ── API Gateways ──
        'inurl:"/swagger-ui/index.html" OR inurl:"/api-docs"',
        'inurl:"/redoc" OR inurl:"/openapi"',
        'inurl:"/graphiql" OR inurl:"/playground"',                      # GraphQL IDEs
        # ── Database Admin ──
        'inurl:"phpmyadmin" OR inurl:"pma"',
        'inurl:"adminer.php"',
        'inurl:"/pgadmin"',
        'inurl:"/mongo-express"',
        'inurl:"/redis-commander"',
    ),
}


# ─── Search Engine Adapters ─────────────────────────────────────────────────


class SearchEngine(Enum):
    """Supported search engines with working scraping methods."""
    DUCKDUCKGO = "duckduckgo"
    BING = "bing"
    GOOGLE = "google"
    SEARXNG = "searxng"      # Self-hosted or public instances


@dataclass
class SearchResult:
    """A single search result URL with metadata."""
    url: str
    engine: SearchEngine
    dork: str
    title: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class EngineStats:
    """Per-engine statistics."""
    engine: SearchEngine
    requested: int = 0
    succeeded: int = 0
    failed: int = 0
    urls_found: int = 0
    blocked: bool = False
    last_error: str = ""


class BaseSearchEngine:
    """Abstract base class for search engine adapters."""

    name: SearchEngine
    base_url: str
    rate_limit_delay: float = DEFAULT_INTERVAL

    def __init__(self, session: aiohttp.ClientSession, proxy: str | None = None,
                 timeout: int = DEFAULT_TIMEOUT, verbose: bool = False):
        self._session = session
        self._proxy = proxy
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._verbose = verbose
        self._stats = EngineStats(engine=self.name)
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT // len(SearchEngine))

    @property
    def stats(self) -> EngineStats:
        return self._stats

    async def _fetch(self, url: str, **kwargs) -> str | None:
        """Fetch a URL with proper headers and error handling."""
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        kwargs.setdefault("headers", headers)
        kwargs.setdefault("timeout", self._timeout)
        if self._proxy:
            kwargs.setdefault("proxy", self._proxy)

        self._stats.requested += 1
        try:
            async with self._semaphore:
                await asyncio.sleep(random.uniform(0.5, self.rate_limit_delay))
                async with self._session.get(url, **kwargs) as resp:
                    if resp.status == 200:
                        self._stats.succeeded += 1
                        return await resp.text()
                    elif resp.status == 429:
                        self._stats.blocked = True
                        self._stats.last_error = f"Rate limited (429)"
                        if self._verbose:
                            print(f"  [\u26a0] {self.name.value}: Rate limited, backing off...")
                        await asyncio.sleep(10)
                        return None
                    elif resp.status == 403:
                        self._stats.blocked = True
                        self._stats.last_error = f"Forbidden (403)"
                        return None
                    else:
                        self._stats.failed += 1
                        return None
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError) as e:
            self._stats.failed += 1
            self._stats.last_error = str(e)[:80]
            if self._verbose:
                print(f"  [!] {self.name.value}: {e}")
            return None

    async def search(self, dork: str, target: str,
                     page: int = 0) -> list[SearchResult]:
        """Execute a single search query. Must be overridden."""
        raise NotImplementedError

    async def search_all_pages(self, dork: str, target: str,
                                max_pages: int = DEFAULT_PAGES
                                ) -> AsyncIterator[SearchResult]:
        """Yield results across multiple pages."""
        for page_num in range(max_pages):
            if self._stats.blocked and self._stats.succeeded > 0:
                break
            try:
                results = await self.search(dork, target, page=page_num)
                if not results:
                    break
                for r in results:
                    self._stats.urls_found += 1
                    yield r
                await asyncio.sleep(self.rate_limit_delay)
            except Exception as e:
                if self._verbose:
                    print(f"  [!] {self.name.value} page {page_num}: {e}")
                break


class DuckDuckGoEngine(BaseSearchEngine):
    """DuckDuckGo HTML (lite) scraper — no API key needed."""

    name = SearchEngine.DUCKDUCKGO
    base_url = "https://html.duckduckgo.com/html/"

    async def search(self, dork: str, target: str,
                     page: int = 0) -> list[SearchResult]:
        query = f"{dork} site:{target}" if target else dork
        params = {"q": query, "s": page * 30, "dc": page * 30 + 1}
        url = f"{self.base_url}?{urllib.parse.urlencode(params)}"

        html = await self._fetch(url)
        if not html:
            return []

        results: list[SearchResult] = []
        # DDG wraps results in <a class="result__a"> with href containing the actual URL
        for match in re.finditer(
            r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]*)</a>',
            html,
            re.IGNORECASE,
        ):
            raw_url = match.group(1)
            title = match.group(2).strip()
            # DDG redirects through their own URL; extract the actual target
            actual_url = self._extract_ddg_url(raw_url)
            if actual_url and not self._is_noise(actual_url):
                results.append(SearchResult(
                    url=actual_url, engine=self.name, dork=dork, title=title
                ))
        return results

    @staticmethod
    def _extract_ddg_url(raw: str) -> str | None:
        """Extract real URL from DDG redirect link."""
        # DDG uses UDDG= parameter or direct links
        uddg_match = re.search(r'uddg=([^&]+)', raw)
        if uddg_match:
            return urllib.parse.unquote(uddg_match.group(1))
        # Sometimes it's a direct link
        if raw.startswith("http"):
            return raw
        return None

    @staticmethod
    def _is_noise(url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in NOISE_PATTERNS)


class BingEngine(BaseSearchEngine):
    """Bing HTML scraper."""

    name = SearchEngine.BING
    base_url = "https://www.bing.com/search"

    async def search(self, dork: str, target: str,
                     page: int = 0) -> list[SearchResult]:
        query = f"{dork} site:{target}" if target else dork
        params = {"q": query, "first": page * 10 + 1}
        url = f"{self.base_url}?{urllib.parse.urlencode(params)}"

        html = await self._fetch(url)
        if not html:
            return []

        results: list[SearchResult] = []
        # Bing results in <li class="b_algo"> with <h2><a href="...">
        for match in re.finditer(
            r'<li[^>]*class="b_algo"[^>]*>.*?<h2[^>]*>.*?<a[^>]*href="([^"]+)"[^>]*>([^<]*)</a>',
            html,
            re.DOTALL | re.IGNORECASE,
        ):
            url = match.group(1)
            title = match.group(2).strip()
            if url and not self._is_noise(url):
                results.append(SearchResult(
                    url=url, engine=self.name, dork=dork, title=title
                ))
        return results

    @staticmethod
    def _is_noise(url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in NOISE_PATTERNS)


class GoogleEngine(BaseSearchEngine):
    """Google HTML scraper (with anti-bot evasion)."""

    name = SearchEngine.GOOGLE
    base_url = "https://www.google.com/search"
    rate_limit_delay = 3.0  # Google is stricter

    async def search(self, dork: str, target: str,
                     page: int = 0) -> list[SearchResult]:
        query = f"{dork} site:{target}" if target else dork
        params = {
            "q": query,
            "start": page * 10,
            "num": 10,
            "hl": "en",
        }
        url = f"{self.base_url}?{urllib.parse.urlencode(params)}"
        # Add extra headers to look more human
        extra_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        }

        html = await self._fetch(url, headers=extra_headers)
        if not html:
            return []

        # Check for CAPTCHA/blocking
        if re.search(r'unusual traffic from your computer|captcha|sorry.*interrupt', html, re.IGNORECASE):
            self._stats.blocked = True
            self._stats.last_error = "Google CAPTCHA/blocked"
            if self._verbose:
                print(f"  [\u26a0] Google: Blocked (CAPTCHA or unusual traffic)")
            return []

        results: list[SearchResult] = []
        # Google results in <div class="g"> with <a href="/url?q=..."> or direct <a>
        for match in re.finditer(
            r'<a[^>]+href="(?:/url\?q=)?([^&"]+)"[^>]*>(?:<[^>]+>)*?([^<]*(?:</[^>]+>[^<]*)*?)</a>',
            html,
            re.IGNORECASE,
        ):
            raw_url = match.group(1)
            # Skip Google's own URLs
            if raw_url.startswith(("google.", "/search", "/url", "#")):
                continue
            decoded = urllib.parse.unquote(raw_url)
            if decoded and not self._is_noise(decoded):
                results.append(SearchResult(
                    url=decoded, engine=self.name, dork=dork
                ))
        return results

    @staticmethod
    def _is_noise(url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in NOISE_PATTERNS)


class SearXNGEngine(BaseSearchEngine):
    """SearXNG meta-search engine (supports self-hosted instances)."""

    name = SearchEngine.SEARXNG
    base_url = "https://searx.be"  # Default public instance; configurable

    def __init__(self, *args, instance_url: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        if instance_url:
            self.base_url = instance_url.rstrip("/")

    async def search(self, dork: str, target: str,
                     page: int = 0) -> list[SearchResult]:
        query = f"{dork} site:{target}" if target else dork
        params = {
            "q": query,
            "format": "html",
            "categories": "general",
            "pageno": page + 1,
        }
        url = f"{self.base_url}/search?{urllib.parse.urlencode(params)}"

        html = await self._fetch(url)
        if not html:
            return []

        results: list[SearchResult] = []
        # SearXNG results in <article class="result"> with <a class="url_wrapper">
        for match in re.finditer(
            r'<article[^>]*class="result"[^>]*>.*?<a[^>]*class="[^"]*url_wrapper[^"]*"[^>]*href="([^"]+)"',
            html,
            re.DOTALL | re.IGNORECASE,
        ):
            url = match.group(1)
            if url and not self._is_noise(url):
                results.append(SearchResult(
                    url=url, engine=self.name, dork=dork
                ))
        return results

    @staticmethod
    def _is_noise(url: str) -> bool:
        return any(re.search(p, url, re.IGNORECASE) for p in NOISE_PATTERNS)


# ─── Core Scanner ────────────────────────────────────────────────────────────


@dataclass
class ScanConfig:
    """Configuration for a scan run."""
    targets: list[str]
    dork_types: list[DorkCategory]
    custom_dorks: list[str] = field(default_factory=list)
    max_pages: int = DEFAULT_PAGES
    interval: float = DEFAULT_INTERVAL
    output_file: Path | None = None
    proxy: str | None = None
    verbose: bool = False
    json_output: bool = False
    csv_output: bool = False
    searxng_instance: str | None = None
    engines: list[SearchEngine] = field(default_factory=lambda: [
        SearchEngine.DUCKDUCKGO, SearchEngine.BING, SearchEngine.GOOGLE
    ])


class SnitchScanner:
    """
    Main scanner orchestrator.

    Manages engine lifecycle, deduplication, progress reporting, and output.
    """

    def __init__(self, config: ScanConfig):
        self._config = config
        self._results: dict[str, SearchResult] = {}  # Dedup by URL
        self._engine_stats: dict[SearchEngine, EngineStats] = {}
        self._session: aiohttp.ClientSession | None = None
        self._engines: list[BaseSearchEngine] = []
        self._start_time: float = 0
        self._total_dorks: int = 0
        self._completed_dorks: int = 0
        self._lock = asyncio.Lock()

    async def _init_engines(self) -> None:
        """Initialize search engine adapters based on config."""
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT,
            limit_per_host=3,
            ssl=False,  # Some engines have cert issues
        )
        self._session = aiohttp.ClientSession(connector=connector)

        engine_classes: dict[SearchEngine, type[BaseSearchEngine]] = {
            SearchEngine.DUCKDUCKGO: DuckDuckGoEngine,
            SearchEngine.BING: BingEngine,
            SearchEngine.GOOGLE: GoogleEngine,
            SearchEngine.SEARXNG: SearXNGEngine,
        }

        for eng_name in self._config.engines:
            cls = engine_classes.get(eng_name)
            if cls is None:
                continue
            kwargs = dict(
                session=self._session,
                proxy=self._config.proxy,
                verbose=self._config.verbose,
            )
            if eng_name == SearchEngine.SEARXNG and self._config.searxng_instance:
                kwargs["instance_url"] = self._config.searxng_instance
            try:
                engine = cls(**kwargs)
                engine.rate_limit_delay = self._config.interval
                self._engines.append(engine)
            except Exception as e:
                print(f"  [!] Failed to init {eng_name.value}: {e}")

        if not self._engines:
            raise RuntimeError("No search engines available.")

    def _build_dork_list(self) -> list[tuple[str, str]]:
        """Build (dork_query, category_name) list from config."""
        dork_list: list[tuple[str, str]] = []

        for dtype in self._config.dork_types:
            if dtype == DorkCategory.ALL:
                for cat, dorks in DORK_DB.items():
                    if cat != DorkCategory.ALL:
                        for d in dorks:
                            dork_list.append((d, cat.value))
            else:
                dorks = DORK_DB.get(dtype, ())
                for d in dorks:
                    dork_list.append((d, dtype.value))

        for cdork in self._config.custom_dorks:
            dork_list.append((cdork, "custom"))

        return dork_list

    async def _run_single_search(self, engine: BaseSearchEngine,
                                  dork: str, target: str) -> None:
        """Run one engine+dork combination and collect results."""
        async for result in engine.search_all_pages(dork, target, self._config.max_pages):
            url_key = result.url.lower().rstrip("/")
            if url_key not in self._results:
                async with self._lock:
                    self._results[url_key] = result
                if not self._config.json_output and not self._config.csv_output:
                    print(f"  [{engine.name.value:>12}] {result.url}")

        async with self._lock:
            self._completed_dorks += 1
            if self._config.verbose and self._total_dorks > 0:
                pct = self._completed_dorks / self._total_dorks * 100
                print(f"\r  Progress: {self._completed_dorks}/{self._total_dorks} ({pct:.0f}%)",
                      end="", flush=True)

    async def run(self) -> None:
        """Execute the full scan."""
        self._start_time = time.time()
        dork_list = self._build_dork_list()
        self._total_dorks = len(dork_list) * len(self._engines) * len(self._config.targets)

        print(f"\n[*] Targets: {', '.join(self._config.targets)}")
        print(f"[*] Engines: {', '.join(e.value for e in self._config.engines)}")
        print(f"[*] Dorks: {len(dork_list)} queries x {len(self._config.targets)} targets x {len(self._engines)} engines")
        print(f"[*] Max pages/dork: {self._config.max_pages}")
        if self._config.proxy:
            print(f"[*] Proxy: {self._config.proxy}")
        print()

        await self._init_engines()

        tasks: list[asyncio.Task[None]] = []
        for target in self._config.targets:
            for dork, _category in dork_list:
                for engine in self._engines:
                    tasks.append(asyncio.create_task(
                        self._run_single_search(engine, dork, target)
                    ))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Collect stats
        for engine in self._engines:
            self._engine_stats[engine.name] = engine.stats

        elapsed = time.time() - self._start_time
        self._print_summary(elapsed)
        self._save_results()

        await self._session.close()

    def _print_summary(self, elapsed: float) -> None:
        """Print final statistics."""
        unique_urls = len(self._results)
        print(f"\n{'='*60}")
        print(f"[+] Done! Found {unique_urls} unique URLs in {elapsed:.1f}s")
        print(f"{'='*60}\n")

        # Per-engine breakdown
        print(f"{'Engine':<14} {'Req':>6} {'OK':>6} {'Fail':>6} {'URLs':>6} {'Status'}")
        print("-" * 56)
        for name, stat in sorted(self._engine_stats.items(),
                                   key=lambda x: x[1].urls_found, reverse=True):
            status = "BLOCKED" if stat.blocked else "OK"
            print(f"{name.value:<14} {stat.requested:>6} {stat.succeeded:>6} "
                  f"{stat.failed:>6} {stat.urls_found:>6} {status}")
        print()

        # Per-category breakdown
        category_counts: dict[str, int] = {}
        for r in self._results.values():
            # Extract category from dork string
            cat = "custom"
            for dc in DorkCategory:
                if dc != DorkCategory.ALL:
                    if r.dork in DORK_DB.get(dc, ()):
                        cat = dc.value
                        break
            category_counts[cat] = category_counts.get(cat, 0) + 1

        if category_counts:
            print(f"{'Category':<14} {'URLs':>6}")
            print("-" * 22)
            for cat, count in sorted(category_counts.items(),
                                      key=lambda x: x[1], reverse=True):
                print(f"{cat:<14} {count:>6}")
            print()

    def _save_results(self) -> None:
        """Save results to configured output file(s)."""
        if not self._results:
            return

        sorted_results = sorted(self._results.values(), key=lambda r: r.url)

        if self._config.json_output:
            path = self._output_file or Path(f"snitch_{int(time.time())}.json")
            data = [{
                "url": r.url,
                "engine": r.engine.value,
                "dork": r.dork,
                "title": r.title,
                "timestamp": r.timestamp,
            } for r in sorted_results]
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"[+] JSON saved: {path}")

        elif self._config.csv_output:
            path = self._output_file or Path(f"snitch_{int(time.time())}.csv")
            lines = ["url,engine,dork,title"]
            for r in sorted_results:
                safe_url = r.url.replace(",", "%2C")
                safe_dork = r.dork.replace(",", "%2C").replace('"', '""')
                safe_title = r.title.replace(",", "%2C").replace('"', '""')
                lines.append(f'{safe_url},{r.engine.value},"{safe_dork}","{safe_title}"')
            path.write_text("\n".join(lines), encoding="utf-8")
            print(f"[+] CSV saved: {path}")

        elif self._config.output_file:
            lines = [r.url for r in sorted_results]
            self._config.output_file.write_text("\n".join(lines), encoding="utf-8")
            print(f"[+] Text saved: {self._config.output_file} ({len(lines)} URLs)")


# ─── CLI Interface ───────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> ScanConfig:
    """Parse command-line arguments."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="snitch",
        description="Snitch v2 — Modern OSINT Dork Scanner (Python 3 rewrite)",
        epilog=(
            "Examples:\n"
            "  %(prog)s -U example.com -D all\n"
            "  %(prog)s -U gov,edu -D ext,info -P 20 --json\n"
            "  %(prog)s -C 'site:target.com ext:bak' --proxy socks5://127.0.0.1:9050\n"
            "  %(prog)s -U target.com -D soft --searxng https://my-searx.example.com\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required
    g_req = parser.add_argument_group("Required (one of)")
    g_req.add_argument(
        "-U", "--url", metavar="DOMAIN",
        help="Target domain(s) or domain extension(s), comma-separated (e.g., gov, edu, example.com)"
    )
    g_req.add_argument(
        "-C", "--custom", metavar="DORK",
        help="Custom Google dork query (bypasses predefined categories)"
    )

    # Dork type
    parser.add_argument(
        "-D", "--dork", metavar="TYPE",
        default="all",
        help=f"Dork type(s), comma-separated: "
             f"{', '.join(e.value for e in DorkCategory if e != DorkCategory.ALL)}, all (default: all)"
    )

    # Options
    parser.add_argument("-O", "--output", metavar="FILE", help="Output file path")
    parser.add_argument("-S", "--proxy", metavar="URL",
                        help="Proxy URL (socks5://ip:port or http://ip:port)")
    parser.add_argument("-I", "--interval", type=float, default=DEFAULT_INTERVAL,
                        metavar="SEC", help=f"Request interval seconds (default: {DEFAULT_INTERVAL})")
    parser.add_argument("-P", "--pages", type=int, default=DEFAULT_PAGES,
                        metavar="N", help=f"Max pages per dork (default: {DEFAULT_PAGES})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        metavar="SEC", help=f"HTTP timeout (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="Output in JSON format")
    parser.add_argument("--csv", action="store_true", dest="csv_output",
                        help="Output in CSV format")
    parser.add_argument("--engines", metavar="LIST",
                        help=f"Comma-separated engines: "
                             f"{', '.join(e.value for e in SearchEngine)} "
                             f"(default: duckduckgo,bing,google)")
    parser.add_argument("--searxng", metavar="URL",
                        help="Custom SearXNG instance URL (for searxng engine)")

    args = parser.parse_args(argv)

    # Validate
    if not args.url and not args.custom:
        parser.error("Either -U/--url or -C/--custom is required.")

    # Parse targets
    targets: list[str] = []
    if args.url:
        targets = [t.strip() for t in args.url.split(",") if t.strip()]

    # Parse dork types
    dork_types: list[DorkCategory] = []
    for dt in args.dork.split(","):
        dt_clean = dt.strip()
        try:
            dork_types.append(DorkCategory(dt_clean))
        except ValueError:
            valid = ", ".join(e.value for e in DorkCategory)
            parser.error(f"Unknown dork type: '{dt_clean}'. Valid: {valid}")

    # Parse engines
    engines: list[SearchEngine] = []
    if args.engines:
        for ename in args.engines.split(","):
            try:
                engines.append(SearchEngine(ename.strip()))
            except ValueError:
                valid = ", ".join(e.value for e in SearchEngine)
                parser.error(f"Unknown engine: '{ename.strip()}'. Valid: {valid}")
    else:
        engines = [SearchEngine.DUCKDUCKGO, SearchEngine.BING, SearchEngine.GOOGLE]

    # Output file
    output_path: Path | None = None
    if args.output:
        output_path = Path(args.output)

    return ScanConfig(
        targets=targets,
        dork_types=dork_types,
        custom_dorks=[args.custom] if args.custom else [],
        max_pages=args.pages,
        interval=args.interval,
        output_file=output_path,
        proxy=args.proxy,
        verbose=args.verbose,
        json_output=args.json_output,
        csv_output=args.csv_output,
        searxng_instance=args.searxng,
        engines=engines,
    )


def main() -> int:
    """Entry point."""
    if len(sys.argv) == 1:
        print(BANNER)
        parse_args(["--help"])
        return 0

    print(BANNER)

    config = parse_args()

    # Handle Ctrl+C gracefully
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    cancelled = False

    def _sigint_handler(sig, frame):
        nonlocal cancelled
        cancelled = True
        print("\n[!] Interrupted by user. Saving partial results...")
        # Don't exit immediately; let the scanner save what it has

    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        scanner = SnitchScanner(config)
        loop.run_until_complete(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}", file=sys.stderr)
        if config.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        loop.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
