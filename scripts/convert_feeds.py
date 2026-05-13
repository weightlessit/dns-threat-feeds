#!/usr/bin/env python3
"""Threat Feed Converter -- AdGuard Home + FortiGate (with whitelist)."""

import csv
import io
import ipaddress
import logging
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "config" / "feeds.yml"
WHITELIST_PATH = REPO_ROOT / "config" / "whitelist.yml"
OUTPUT_ADGUARD = REPO_ROOT / "output" / "adguard"
OUTPUT_FG_DOMAINS = REPO_ROOT / "output" / "fortigate" / "domains"
OUTPUT_FG_IP = REPO_ROOT / "output" / "fortigate" / "ip"
OUTPUT_FG_HASH = REPO_ROOT / "output" / "fortigate" / "hash"
HOMEPAGE = "https://github.com/weightlessit/dns-threat-feeds"

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(.+)$")
ADGUARD_RULE_RE = re.compile(r"^\|\|.+\^")
IP_LINE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)$")
IP_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$")
HASH_RE = re.compile(r"^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})(?:\s.*)?$")

PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32"]]


# -- Validation ----------------------------------------------------------------

def is_valid_domain(d):
    if not d or len(d) > 253:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", d):
        return False
    return bool(DOMAIN_RE.match(d))


def is_private_ip(s):
    try:
        return any(ipaddress.ip_address(s) in n for n in PRIVATE_NETWORKS)
    except ValueError:
        return False


def is_private_network(s):
    try:
        return any(ipaddress.ip_network(s, strict=False).overlaps(n) for n in PRIVATE_NETWORKS)
    except ValueError:
        return False


# -- HTTP fetch ----------------------------------------------------------------

def fetch_feed(url, timeout=120):
    try:
        log.info(f"  Fetching: {url}")
        r = requests.get(url, timeout=timeout, headers={"User-Agent": "ThreatFeed-Converter/3.0"})
        r.raise_for_status()
        log.info(f"  Downloaded {len(r.text):,} bytes")
        return r.text
    except requests.RequestException as e:
        log.error(f"  Failed to fetch {url}: {e}")
        return None


# -- Domain parsers ------------------------------------------------------------

def parse_domain_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line[0] in "#!;":
            continue
        if is_valid_domain(line):
            out.add(line)
    return out


def parse_hosts_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if not line or line[0] in "#!":
            continue
        m = HOSTS_RE.match(line)
        if m:
            d = m.group(1).strip().split("#")[0].strip()
            if is_valid_domain(d):
                out.add(d)
    return out


def parse_url_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        try:
            h = urlparse(line if "://" in line else f"http://{line}").hostname
            if h and is_valid_domain(h.lower()):
                out.add(h.lower())
        except Exception:
            pass
    return out


def parse_adguard_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] in "!#":
            continue
        if ADGUARD_RULE_RE.match(line):
            d = line.lstrip("|").rstrip("^").lower()
            if is_valid_domain(d):
                out.add(d)
    return out


DOMAIN_PARSERS = {
    "domain": parse_domain_feed,
    "hosts": parse_hosts_feed,
    "url": parse_url_feed,
    "adguard": parse_adguard_feed,
}


# -- IP parsers ----------------------------------------------------------------

def parse_ip_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        rm = IP_RANGE_RE.match(line)
        if rm:
            try:
                ipaddress.ip_address(rm.group(1))
                ipaddress.ip_address(rm.group(2))
                if not is_private_ip(rm.group(1)):
                    out.add(f"{rm.group(1)}-{rm.group(2)}")
            except ValueError:
                pass
            continue
        im = IP_LINE_RE.match(line)
        if im:
            e = im.group(1)
            if "/" in e:
                if not is_private_network(e):
                    try:
                        out.add(str(ipaddress.ip_network(e, strict=False)))
                    except ValueError:
                        pass
            else:
                try:
                    a = ipaddress.ip_address(e)
                    if not is_private_ip(str(a)):
                        out.add(str(a))
                except ValueError:
                    pass
    return out


def parse_alienvault_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        ip_str = line.split("#")[0].strip()
        if not ip_str:
            continue
        try:
            a = ipaddress.ip_address(ip_str)
            if not is_private_ip(str(a)):
                out.add(str(a))
        except ValueError:
            pass
    return out


IP_PARSERS = {
    "ip": parse_ip_feed,
    "alienvault": parse_alienvault_feed,
}


# -- Hash parser ---------------------------------------------------------------

def parse_hash_feed(raw):
    out = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        m = HASH_RE.match(line)
        if m:
            out.add(m.group(1).lower())
    return out


# -- Whitelist -----------------------------------------------------------------

def load_whitelist():
    """Load whitelist from config/whitelist.yml (Tranco top N + manual entries)."""
    wl = set()
    if not WHITELIST_PATH.exists():
        log.warning(f"Whitelist config not found: {WHITELIST_PATH}")
        return wl
    with open(WHITELIST_PATH, "r") as f:
        cfg = yaml.safe_load(f) or {}
    tranco = cfg.get("tranco", {})
    if tranco.get("enabled", False):
        url = tranco.get("url", "")
        count = tranco.get("count", 10000)
        log.info(f"Loading Tranco top {count:,} whitelist domains...")
        try:
            resp = requests.get(url, timeout=60,
                                headers={"User-Agent": "ThreatFeed-Converter/3.0"})
            resp.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                csv_name = zf.namelist()[0]
                with zf.open(csv_name) as csv_file:
                    reader = csv.reader(io.TextIOWrapper(csv_file, "utf-8"))
                    for i, row in enumerate(reader):
                        if i >= count:
                            break
                        if len(row) >= 2:
                            d = row[1].strip().lower()
                            if d:
                                wl.add(d)
            log.info(f"  Loaded {len(wl):,} Tranco domains")
        except Exception as e:
            log.warning(f"  Failed to load Tranco list: {e}")
            log.warning("  Continuing without Tranco whitelist")
    for d in (cfg.get("manual") or []):
        if d:
            wl.add(d.strip().lower())
    log.info(f"  Total whitelist: {len(wl):,} domains")
    return wl


def apply_whitelist(domains, whitelist):
    """Remove whitelisted domains. Walks up domain hierarchy so
    whitelisting google.com also covers drive.google.com, etc."""
    if not whitelist:
        return domains, 0
    filtered, removed = set(), 0
    for domain in domains:
        parts = domain.split(".")
        hit = False
        for i in range(len(parts) - 1):  # stop before bare TLD
            if ".".join(parts[i:]) in whitelist:
                hit = True
                break
        if hit:
            removed += 1
        else:
            filtered.add(domain)
    return filtered, removed


# -- Output helpers ------------------------------------------------------------

def adguard_header(name, desc, count):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (f"! Title: {name}\n! Description: {desc}\n! Homepage: {HOMEPAGE}\n"
            f"! License: MIT\n! Last modified: {now}\n! Total rules: {count}\n!\n"
            f"! Auto-generated -- do not edit manually.\n!\n")


def fortigate_header(name, desc, count, ft="entry"):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (f"# Title: {name}\n# Description: {desc}\n# Homepage: {HOMEPAGE}\n"
            f"# License: MIT\n# Last modified: {now}\n# Total {ft}s: {count}\n#\n"
            f"# Auto-generated -- do not edit manually.\n"
            f"# FortiGate external threat feed format (one {ft} per line).\n#\n")


def write_list(filepath, header, entries):
    s = sorted(entries)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(header)
        f.write("\n".join(s))
        f.write("\n")
    log.info(f"  Wrote {len(s):,} entries -> {filepath}")


# -- Main ----------------------------------------------------------------------

def main():
    log.info("=" * 60)
    log.info("Threat Feed Converter  (AdGuard Home + FortiGate)")
    log.info("=" * 60)

    if not CONFIG_PATH.exists():
        log.error(f"Config not found: {CONFIG_PATH}")
        return 1

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    errors = 0
    whitelist = load_whitelist()
    total_wl_removed = 0

    # ---- DOMAIN FEEDS ----
    domain_feeds = config.get("domain_feeds", [])
    all_domains, entry_domains = set(), set()

    log.info(f"\nProcessing {len(domain_feeds)} domain feed(s)...\n")

    for feed in domain_feeds:
        name = feed["name"]
        url = feed["url"]
        ft = feed["type"]
        out_name = feed["output"]
        desc = feed.get("description", name)
        is_entry = feed.get("entry_combined", False)

        log.info(f"[{name}]{'  (entry-model)' if is_entry else ''}")

        if ft not in DOMAIN_PARSERS:
            log.error(f"  Unknown type: '{ft}'")
            errors += 1
            continue

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        domains = DOMAIN_PARSERS[ft](raw)
        if not domains:
            log.warning(f"  No valid domains from {name}")
            errors += 1
            continue

        # Apply whitelist
        domains, wl_removed = apply_whitelist(domains, whitelist)
        if wl_removed:
            log.info(f"  Whitelist removed {wl_removed:,} domains")
            total_wl_removed += wl_removed

        all_domains.update(domains)
        if is_entry:
            entry_domains.update(domains)

        ag_rules = {f"||{d}^" for d in domains}
        write_list(OUTPUT_ADGUARD / f"{out_name}.txt",
                   adguard_header(name, desc, len(ag_rules)), ag_rules)
        write_list(OUTPUT_FG_DOMAINS / f"{out_name}.txt",
                   fortigate_header(name, desc, len(domains)), domains)
        log.info("")

    if all_domains:
        log.info("[Combined Domain Blocklist]")
        ag_all = {f"||{d}^" for d in all_domains}
        write_list(OUTPUT_ADGUARD / "combined.txt",
                   adguard_header("Combined Threat Feed",
                                  "All domain feeds merged and deduplicated",
                                  len(ag_all)), ag_all)
        write_list(OUTPUT_FG_DOMAINS / "combined.txt",
                   fortigate_header("Combined Threat Feed",
                                    "All domain feeds merged and deduplicated",
                                    len(all_domains)), all_domains)
        log.info("")

    if entry_domains:
        log.info("[Entry-Model Combined Domain Blocklist]")
        write_list(
            OUTPUT_FG_DOMAINS / "entry-model-combined.txt",
            fortigate_header(
                "Entry-Model Combined Domain Feed",
                "Curated domain feed for entry-level FortiGates (80E, 60F, 40F). "
                "Targets ~750K within 1M global domain limit (FortiOS 7.4.4+).",
                len(entry_domains)),
            entry_domains)
        log.info("")

    # ---- IP FEEDS ----
    ip_feeds = config.get("ip_feeds", [])
    all_ips, entry_ips = set(), set()

    log.info(f"Processing {len(ip_feeds)} IP feed(s)...\n")

    for feed in ip_feeds:
        name = feed["name"]
        url = feed["url"]
        ft = feed.get("type", "ip")
        out_name = feed["output"]
        desc = feed.get("description", name)
        is_entry = feed.get("entry_combined", False)

        log.info(f"[{name}]{'  (entry-model)' if is_entry else ''}")

        if ft not in IP_PARSERS:
            log.error(f"  Unknown IP type: '{ft}'")
            errors += 1
            continue

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        ips = IP_PARSERS[ft](raw)
        if not ips:
            log.warning(f"  No valid IPs from {name}")
            errors += 1
            continue

        all_ips.update(ips)
        if is_entry:
            entry_ips.update(ips)

        write_list(OUTPUT_FG_IP / f"{out_name}.txt",
                   fortigate_header(name, desc, len(ips)), ips)
        log.info("")

    if all_ips:
        log.info("[Combined IP Blocklist]")
        write_list(OUTPUT_FG_IP / "combined.txt",
                   fortigate_header("Combined IP Threat Feed",
                                    "All IP feeds merged and deduplicated",
                                    len(all_ips)), all_ips)
        log.info("")

    if entry_ips:
        log.info("[Entry-Model Combined IP Blocklist]")
        write_list(
            OUTPUT_FG_IP / "entry-model-combined.txt",
            fortigate_header(
                "Entry-Model Combined IP Feed",
                "Curated IP feed for entry-level FortiGates (80E, 60F, 40F). "
                "Targets ~200K within 300K global IP limit (FortiOS 7.4.4+).",
                len(entry_ips)),
            entry_ips)
        log.info("")

    # ---- HASH FEEDS ----
    hash_feeds = config.get("hash_feeds", [])
    all_hashes = set()

    log.info(f"Processing {len(hash_feeds)} hash feed(s)...\n")

    for feed in hash_feeds:
        name = feed["name"]
        url = feed["url"]
        out_name = feed["output"]
        desc = feed.get("description", name)

        log.info(f"[{name}]")

        raw = fetch_feed(url)
        if raw is None:
            errors += 1
            continue

        hashes = parse_hash_feed(raw)
        if not hashes:
            log.warning(f"  No valid hashes from {name}")
            errors += 1
            continue

        all_hashes.update(hashes)
        write_list(OUTPUT_FG_HASH / f"{out_name}.txt",
                   fortigate_header(name, desc, len(hashes), "hash"), hashes)
        log.info("")

    if all_hashes:
        log.info("[Combined Hash Blocklist]")
        write_list(OUTPUT_FG_HASH / "combined.txt",
                   fortigate_header("Combined Hash Threat Feed",
                                    "All hash feeds merged and deduplicated",
                                    len(all_hashes), "hash"), all_hashes)
        log.info("")

    total = len(domain_feeds) + len(ip_feeds) + len(hash_feeds)
    log.info("=" * 60)
    log.info(
        f"Done.  Domains: {len(all_domains):,} (entry: {len(entry_domains):,})  |  "
        f"IPs: {len(all_ips):,} (entry: {len(entry_ips):,})  |  "
        f"Hashes: {len(all_hashes):,}  |  WL removed: {total_wl_removed:,}  |  Errors: {errors}")
    log.info("=" * 60)

    return 1 if errors == total else 0


if __name__ == "__main__":
    sys.exit(main())
