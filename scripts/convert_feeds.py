#!/usr/bin/env python3
"""
Threat Feed to AdGuard Home Converter

Fetches domain-based threat intelligence feeds defined in config/feeds.yml,
converts entries to AdGuard Home compatible adblock-style syntax (||domain^),
and writes deduplicated output files.

NOTE: This tool intentionally excludes IP-based feeds. AdGuard Home operates
at the DNS query level - it matches hostnames/FQDNs, not resolved IPs.
IP-based blocking belongs at your firewall or IDS/IPS layer.
"""

import csv
import io
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "config" / "feeds.yml"
OUTPUT_DIR = REPO_ROOT / "output"

# -- Regex patterns ----------------------------------------------------

DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
HOSTS_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(.+)$"
)
ADGUARD_RULE_RE = re.compile(
    r"^\|\|.+\^"
)


def is_valid_domain(domain: str) -> bool:
    """Validate a domain name (reject IPs, too-long names, etc.)."""
    if not domain or len(domain) > 253:
        return False
    # Quick reject: if it looks like an IP address, skip it
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return False
    return bool(DOMAIN_RE.match(domain))


def fetch_feed(url: str, timeout: int = 90) -> str | None:
    """Download a feed URL and return its text content."""
    try:
        log.info(f"  Fetching: {url}")
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "AdGuard-ThreatFeed-Converter/2.0"
        })
        resp.raise_for_status()
        log.info(f"  Downloaded {len(resp.text):,} bytes")
        return resp.text
    except requests.RequestException as e:
        log.error(f"  Failed to fetch {url}: {e}")
        return None


# -- Feed Parsers ------------------------------------------------------

def parse_domain_feed(raw: str) -> set[str]:
    """Parse a plain domain list (one domain per line)."""
    rules: set[str] = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("!") or line.startswith(";"):
            continue
        if is_valid_domain(line):
            rules.add(f"||{line}^")
    return rules


def parse_hosts_feed(raw: str) -> set[str]:
    """Parse /etc/hosts format (0.0.0.0 domain or 127.0.0.1 domain)."""
    rules: set[str] = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        match = HOSTS_RE.match(line)
        if match:
            domain = match.group(1).strip()
            domain = domain.split("#")[0].strip()  # strip inline comments
            if is_valid_domain(domain):
                rules.add(f"||{domain}^")
    return rules


def parse_url_feed(raw: str) -> set[str]:
    """Parse a URL list - extract and deduplicate hostnames."""
    rules: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        try:
            parsed = urlparse(line if "://" in line else f"http://{line}")
            hostname = parsed.hostname
            if hostname and is_valid_domain(hostname.lower()):
                rules.add(f"||{hostname.lower()}^")
        except Exception:
            continue
    return rules


def parse_adguard_feed(raw: str) -> set[str]:
    """Parse a feed already in AdGuard adblock-style syntax (passthrough).

    Extracts existing ||domain^ rules, strips headers/comments, deduplicates.
    """
    rules: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if ADGUARD_RULE_RE.match(line):
            rules.add(line)
    return rules


def parse_phishtank_csv(raw: str) -> set[str]:
    """Parse PhishTank CSV and extract domains from the 'url' column."""
    rules: set[str] = set()
    try:
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            url = row.get("url", "")
            if url:
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname and is_valid_domain(hostname.lower()):
                        rules.add(f"||{hostname.lower()}^")
                except Exception:
                    continue
    except Exception as e:
        log.error(f"  Failed to parse PhishTank CSV: {e}")
    return rules


PARSERS = {
    "domain": parse_domain_feed,
    "hosts": parse_hosts_feed,
    "url": parse_url_feed,
    "adguard": parse_adguard_feed,
    "phishtank_csv": parse_phishtank_csv,
}


# -- Output helpers ----------------------------------------------------

def generate_header(feed_name: str, feed_desc: str, rule_count: int) -> str:
    """Generate an AdGuard-compatible metadata header for the output file."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"! Title: {feed_name}\n"
        f"! Description: {feed_desc}\n"
        f"! Homepage: https://github.com/YOUR_USERNAME/adguard-threat-feeds\n"
        f"! License: MIT\n"
        f"! Last modified: {now}\n"
        f"! Total rules: {rule_count}\n"
        f"!\n"
        f"! Auto-generated - do not edit manually.\n"
        f"! Converted to AdGuard Home adblock-style syntax.\n"
        f"!\n"
    )


def write_output(filepath: Path, header: str, rules: set[str]) -> None:
    """Write sorted rules with header to an output file."""
    sorted_rules = sorted(rules)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(sorted_rules))
        f.write("\n")
    log.info(f"  Wrote {len(sorted_rules):,} rules -> {filepath.name}")


# -- Main --------------------------------------------------------------

def main() -> int:
    log.info("=" * 60)
    log.info("AdGuard Threat Feed Converter  (domain-only)")
    log.info("=" * 60)

    if not CONFIG_PATH.exists():
        log.error(f"Config not found: {CONFIG_PATH}")
        return 1

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    feeds = config.get("feeds", [])
    if not feeds:
        log.warning("No feeds defined in config.")
        return 0

    log.info(f"Processing {len(feeds)} feed(s)...\n")

    total_rules = 0
    errors = 0

    for feed in feeds:
        name = feed["name"]
        url = feed["url"]
        feed_type = feed["type"]
        output_file = feed["output"]
        description = feed.get("description", name)

        log.info(f"[{name}]")

        if feed_type not in PARSERS:
            log.error(f"  Unknown feed type: '{feed_type}'")
            errors += 1
            continue

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        parser = PARSERS[feed_type]
        rules = parser(raw)

        if not rules:
            log.warning(f"  No valid rules extracted from {name}")
            errors += 1
            continue

        header = generate_header(name, description, len(rules))
        output_path = OUTPUT_DIR / output_file
        write_output(output_path, header, rules)
        total_rules += len(rules)
        log.info("")

    # -- Generate combined / merged list -------------------------------
    log.info("[Combined Blocklist]")
    all_rules: set[str] = set()
    for out_file in OUTPUT_DIR.glob("*.txt"):
        if out_file.name == "combined.txt":
            continue
        with open(out_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("!"):
                    all_rules.add(line)

    if all_rules:
        combined_header = generate_header(
            "Combined Threat Feed",
            "All threat feeds merged and deduplicated",
            len(all_rules),
        )
        write_output(OUTPUT_DIR / "combined.txt", combined_header, all_rules)
        log.info("")

    log.info("=" * 60)
    log.info(f"Done.  Total unique rules: {total_rules:,}  |  Errors: {errors}")
    log.info("=" * 60)

    return 1 if errors == len(feeds) else 0


if __name__ == "__main__":
    sys.exit(main())
