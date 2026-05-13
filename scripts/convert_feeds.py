#!/usr/bin/env python3
"""
Threat Feed Converter -- AdGuard Home + FortiGate

Fetches threat intelligence feeds defined in config/feeds.yml and converts
them into formats compatible with:

  - AdGuard Home   (adblock-style: ||domain^)     -- domain feeds only
  - FortiGate      (plain text, one entry/line)    -- domain, IP, AND hash feeds

IP and hash feeds are output for FortiGate only.
"""

import csv
import io
import ipaddress
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
OUTPUT_ADGUARD = REPO_ROOT / "output" / "adguard"
OUTPUT_FG_DOMAINS = REPO_ROOT / "output" / "fortigate" / "domains"
OUTPUT_FG_IP = REPO_ROOT / "output" / "fortigate" / "ip"
OUTPUT_FG_HASH = REPO_ROOT / "output" / "fortigate" / "hash"

HOMEPAGE = "https://github.com/weightlessit/dns-threat-feeds"

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
IP_LINE_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)$"
)
HASH_RE = re.compile(
    r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})(?:\s.*)?$"
)

# Private / bogon ranges to exclude from IP feeds
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


# -- Validation --------------------------------------------------------

def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        return False
    return bool(DOMAIN_RE.match(domain))


def is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_private_network(cidr_str: str) -> bool:
    try:
        net = ipaddress.ip_network(cidr_str, strict=False)
        return any(net.overlaps(priv) for priv in PRIVATE_NETWORKS)
    except ValueError:
        return False


# -- HTTP fetch --------------------------------------------------------

def fetch_feed(url: str, timeout: int = 120) -> str | None:
    try:
        log.info(f"  Fetching: {url}")
        resp = requests.get(url, timeout=timeout, headers={
            "User-Agent": "ThreatFeed-Converter/3.0"
        })
        resp.raise_for_status()
        log.info(f"  Downloaded {len(resp.text):,} bytes")
        return resp.text
    except requests.RequestException as e:
        log.error(f"  Failed to fetch {url}: {e}")
        return None


# -- Domain Feed Parsers -----------------------------------------------

def parse_domain_feed(raw: str) -> set[str]:
    domains: set[str] = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("!") or line.startswith(";"):
            continue
        if is_valid_domain(line):
            domains.add(line)
    return domains


def parse_hosts_feed(raw: str) -> set[str]:
    domains: set[str] = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        match = HOSTS_RE.match(line)
        if match:
            domain = match.group(1).strip().split("#")[0].strip()
            if is_valid_domain(domain):
                domains.add(domain)
    return domains


def parse_url_feed(raw: str) -> set[str]:
    domains: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        try:
            parsed = urlparse(line if "://" in line else f"http://{line}")
            hostname = parsed.hostname
            if hostname and is_valid_domain(hostname.lower()):
                domains.add(hostname.lower())
        except Exception:
            continue
    return domains


def parse_adguard_feed(raw: str) -> set[str]:
    domains: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("!") or line.startswith("#"):
            continue
        if ADGUARD_RULE_RE.match(line):
            domain = line.lstrip("|").rstrip("^").lower()
            if is_valid_domain(domain):
                domains.add(domain)
    return domains


def parse_phishtank_csv(raw: str) -> set[str]:
    domains: set[str] = set()
    try:
        reader = csv.DictReader(io.StringIO(raw))
        for row in reader:
            url = row.get("url", "")
            if url:
                try:
                    parsed = urlparse(url)
                    hostname = parsed.hostname
                    if hostname and is_valid_domain(hostname.lower()):
                        domains.add(hostname.lower())
                except Exception:
                    continue
    except Exception as e:
        log.error(f"  Failed to parse PhishTank CSV: {e}")
    return domains


DOMAIN_PARSERS = {
    "domain": parse_domain_feed,
    "hosts": parse_hosts_feed,
    "url": parse_url_feed,
    "adguard": parse_adguard_feed,
    "phishtank_csv": parse_phishtank_csv,
}


# -- IP Feed Parser ----------------------------------------------------

def parse_ip_feed(raw: str) -> set[str]:
    """Parse plain IP/CIDR list. Returns clean IPs/CIDRs (not expanded)."""
    entries: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        line = line.split(";")[0].strip()
        line = line.split("#")[0].strip()
        if not line:
            continue

        ip_match = IP_LINE_RE.match(line)
        if ip_match:
            entry = ip_match.group(1)
            if "/" in entry:
                if not is_private_network(entry):
                    try:
                        net = ipaddress.ip_network(entry, strict=False)
                        entries.add(str(net))
                    except ValueError:
                        continue
            else:
                try:
                    addr = ipaddress.ip_address(entry)
                    if not is_private_ip(str(addr)):
                        entries.add(str(addr))
                except ValueError:
                    continue
    return entries


# -- Hash Feed Parser --------------------------------------------------

def parse_hash_feed(raw: str) -> set[str]:
    """Parse malware hash list. Returns hex hashes (lowercase)."""
    hashes: set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        match = HASH_RE.match(line)
        if match:
            hashes.add(match.group(1).lower())
    return hashes


# -- Output helpers ----------------------------------------------------

def adguard_header(name: str, desc: str, count: int) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"! Title: {name}\n"
        f"! Description: {desc}\n"
        f"! Homepage: {HOMEPAGE}\n"
        f"! License: MIT\n"
        f"! Last modified: {now}\n"
        f"! Total rules: {count}\n"
        f"!\n"
        f"! Auto-generated -- do not edit manually.\n"
        f"!\n"
    )


def fortigate_header(name: str, desc: str, count: int, feed_type: str = "entry") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"# Title: {name}\n"
        f"# Description: {desc}\n"
        f"# Homepage: {HOMEPAGE}\n"
        f"# License: MIT\n"
        f"# Last modified: {now}\n"
        f"# Total {feed_type}s: {count}\n"
        f"#\n"
        f"# Auto-generated -- do not edit manually.\n"
        f"# FortiGate external threat feed format (one {feed_type} per line).\n"
        f"#\n"
    )


def write_list(filepath: Path, header: str, entries: set[str]) -> None:
    sorted_entries = sorted(entries)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(sorted_entries))
        f.write("\n")
    log.info(f"  Wrote {len(sorted_entries):,} entries -> {filepath}")


# -- Main --------------------------------------------------------------

def main() -> int:
    log.info("=" * 60)
    log.info("Threat Feed Converter  (AdGuard Home + FortiGate)")
    log.info("=" * 60)

    if not CONFIG_PATH.exists():
        log.error(f"Config not found: {CONFIG_PATH}")
        return 1

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    errors = 0

    # ==================================================================
    # DOMAIN FEEDS  (AdGuard + FortiGate)
    # ==================================================================
    domain_feeds = config.get("domain_feeds", [])
    all_domains: set[str] = set()

    log.info(f"\nProcessing {len(domain_feeds)} domain feed(s)...\n")

    for feed in domain_feeds:
        name = feed["name"]
        url = feed["url"]
        feed_type = feed["type"]
        output_name = feed["output"]
        description = feed.get("description", name)

        log.info(f"[{name}]")

        if feed_type not in DOMAIN_PARSERS:
            log.error(f"  Unknown feed type: '{feed_type}'")
            errors += 1
            continue

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        domains = DOMAIN_PARSERS[feed_type](raw)
        if not domains:
            log.warning(f"  No valid domains extracted from {name}")
            errors += 1
            continue

        all_domains.update(domains)

        ag_rules = {f"||{d}^" for d in domains}
        ag_hdr = adguard_header(name, description, len(ag_rules))
        write_list(OUTPUT_ADGUARD / f"{output_name}.txt", ag_hdr, ag_rules)

        fg_hdr = fortigate_header(name, description, len(domains))
        write_list(OUTPUT_FG_DOMAINS / f"{output_name}.txt", fg_hdr, domains)
        log.info("")

    if all_domains:
        log.info("[Combined Domain Blocklist]")
        ag_combined = {f"||{d}^" for d in all_domains}
        write_list(
            OUTPUT_ADGUARD / "combined.txt",
            adguard_header("Combined Threat Feed", "All domain feeds merged and deduplicated", len(ag_combined)),
            ag_combined,
        )
        write_list(
            OUTPUT_FG_DOMAINS / "combined.txt",
            fortigate_header("Combined Threat Feed", "All domain feeds merged and deduplicated", len(all_domains)),
            all_domains,
        )
        log.info("")

    # ==================================================================
    # IP FEEDS  (FortiGate only)
    # ==================================================================
    ip_feeds = config.get("ip_feeds", [])
    all_ips: set[str] = set()

    log.info(f"Processing {len(ip_feeds)} IP feed(s)...\n")

    for feed in ip_feeds:
        name = feed["name"]
        url = feed["url"]
        output_name = feed["output"]
        description = feed.get("description", name)

        log.info(f"[{name}]")

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        ips = parse_ip_feed(raw)
        if not ips:
            log.warning(f"  No valid IPs extracted from {name}")
            errors += 1
            continue

        all_ips.update(ips)

        fg_hdr = fortigate_header(name, description, len(ips))
        write_list(OUTPUT_FG_IP / f"{output_name}.txt", fg_hdr, ips)
        log.info("")

    if all_ips:
        log.info("[Combined IP Blocklist]")
        write_list(
            OUTPUT_FG_IP / "combined.txt",
            fortigate_header("Combined IP Threat Feed", "All IP feeds merged and deduplicated", len(all_ips)),
            all_ips,
        )
        log.info("")

    # ==================================================================
    # HASH FEEDS  (FortiGate only)
    # ==================================================================
    hash_feeds = config.get("hash_feeds", [])
    all_hashes: set[str] = set()

    log.info(f"Processing {len(hash_feeds)} hash feed(s)...\n")

    for feed in hash_feeds:
        name = feed["name"]
        url = feed["url"]
        output_name = feed["output"]
        description = feed.get("description", name)

        log.info(f"[{name}]")

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        hashes = parse_hash_feed(raw)
        if not hashes:
            log.warning(f"  No valid hashes extracted from {name}")
            errors += 1
            continue

        all_hashes.update(hashes)

        fg_hdr = fortigate_header(name, description, len(hashes), "hash")
        write_list(OUTPUT_FG_HASH / f"{output_name}.txt", fg_hdr, hashes)
        log.info("")

    if all_hashes:
        log.info("[Combined Hash Blocklist]")
        write_list(
            OUTPUT_FG_HASH / "combined.txt",
            fortigate_header("Combined Hash Threat Feed", "All hash feeds merged and deduplicated", len(all_hashes), "hash"),
            all_hashes,
        )
        log.info("")

    total_feeds = len(domain_feeds) + len(ip_feeds) + len(hash_feeds)
    log.info("=" * 60)
    log.info(f"Done.  Domains: {len(all_domains):,}  |  IPs: {len(all_ips):,}  |  Hashes: {len(all_hashes):,}  |  Errors: {errors}")
    log.info("=" * 60)

    return 1 if errors == total_feeds else 0


if __name__ == "__main__":
    sys.exit(main())
