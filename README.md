# AdGuard Threat Feeds

Automated pipeline that fetches **domain-based** threat intelligence feeds and
converts them to [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome)
compatible blocklists using adblock-style syntax (`||domain^`).

A GitHub Action runs every 6 hours, pulls the latest feeds, converts them, and
commits the updated lists to this repo. Point your AdGuard Home instance at the
raw GitHub URLs and you're done.

---

## Why does this exist?

Many high-quality threat intel feeds publish data in formats AdGuard Home can't
directly consume -- plain domain lists, `/etc/hosts` files, full URLs, or CSVs.
This project normalises them all into the `||domain^` syntax that AdGuard Home
expects, and keeps them current automatically.

## Why no IP-based feeds?

AdGuard Home is a **DNS sinkhole**. It intercepts DNS *queries* and matches
against **hostnames / FQDNs**. It does **not** inspect what IP address a domain
resolves to, and it cannot act as a network firewall.

A rule like `||185.x.x.x^` would only trigger if someone literally typed that
IP into their browser address bar (which essentially never happens for
compromised-IP threat data). **IP-based threat feeds are useless in AdGuard
Home.**

**Where IP feeds belong instead:**

| Tool | Example |
|------|---------|
| Firewall rules | pfSense, OPNsense, iptables/nftables |
| IDS / IPS | Suricata, Snort, CrowdSec |
| Cloud DNS gateway | Cloudflare Gateway, Cisco Umbrella |
| Proxy / NGFW | Squid, Palo Alto, Fortinet |

---

## Quick Start -- Add to AdGuard Home

1. Open **AdGuard Home > Filters > DNS Blocklists > Add blocklist > Add a custom list**
2. Paste a raw URL from the table below
3. Repeat for each feed you want (or just use **Combined**)

| Feed | Raw URL |
|------|---------|
| URLhaus Malware Domains | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/urlhaus-hostfile-domains.txt` |
| URLhaus Recent URLs | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/urlhaus-recent-domains.txt` |
| ThreatFox IOC Domains | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/threatfox-domains.txt` |
| Phishing Army Extended | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/phishing-army-domains.txt` |
| OpenPhish Community | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/openphish-domains.txt` |
| PhishTank Verified | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/phishtank-domains.txt` |
| CERT Polska | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/cert-polska-domains.txt` |
| DigitalSide.it | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/digitalside-domains.txt` |
| Rescure Domains | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/rescure-domains.txt` |
| Maltrail Malware | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/maltrail-malware-domains.txt` |
| Block List Project -- Malware | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/blp-malware.txt` |
| Block List Project -- Phishing | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/blp-phishing.txt` |
| Block List Project -- Ransomware | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/blp-ransomware.txt` |
| HaGeZi Threat Intel Feeds | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/hagezi-tif.txt` |
| **Combined (all feeds)** | `https://raw.githubusercontent.com/YOUR_USERNAME/adguard-threat-feeds/main/output/combined.txt` |

---

## Included Feeds

| Source | Type | Description |
|--------|------|-------------|
| [URLhaus](https://urlhaus.abuse.ch/) | Hosts | Malware distribution domains |
| [URLhaus Recent](https://urlhaus.abuse.ch/) | URL | Recently reported malicious URLs (domains extracted) |
| [ThreatFox](https://threatfox.abuse.ch/) | Hosts | IOC domains (C2, payload delivery, etc.) |
| [Phishing Army](https://phishing.army/) | Domain | Aggregated phishing domains (extended) |
| [OpenPhish](https://openphish.com/) | URL | Community phishing URLs (domains extracted) |
| [PhishTank](https://phishtank.org/) | CSV | Verified active phishing domains |
| [CERT Polska](https://hole.cert.pl/) | Domain | Malicious domains from Polish national CERT |
| [DigitalSide.it](https://osint.digitalside.it/) | Domain | OSINT malware domains |
| [Rescure](https://rescure.me/) | Domain | Cyber threat intel malicious domains |
| [Maltrail](https://github.com/stamparm/maltrail) | Domain | Static malware-associated domains |
| [Block List Project](https://blocklistproject.github.io/Lists/) | AdGuard | Malware, phishing, and ransomware lists |
| [HaGeZi](https://github.com/hagezi/dns-blocklists) | AdGuard | Curated threat intelligence feeds |

---

## Adding a New Feed

Edit `config/feeds.yml` and add an entry:

```yaml
  - name: My New Feed
    url: https://example.com/threat-feed.txt
    type: domain        # domain | hosts | url | adguard | phishtank_csv
    output: my-new-feed.txt
    description: What this feed blocks
```

Supported input types:

| Type | Input Format |
|------|-------------|
| `domain` | Plain domain list, one per line |
| `hosts` | `/etc/hosts` style (`0.0.0.0 domain.com`) |
| `url` | Full URLs -- domains are extracted |
| `adguard` | Already in `||domain^` format (passthrough, deduped) |
| `phishtank_csv` | PhishTank CSV with a `url` column |

---

## How It Works

```
config/feeds.yml              <-  single source of truth
        |
   scripts/convert_feeds.py   <-  fetches, parses, converts, deduplicates
        |
   output/*.txt               <-  clean AdGuard-format blocklists
        |
   output/combined.txt        <-  all feeds merged + deduped
```

1. GitHub Action triggers every 6 hours (or manually)
2. `convert_feeds.py` reads `feeds.yml` and downloads each feed
3. Each feed is parsed according to its type and converted to `||domain^` rules
4. A combined/merged list is generated
5. Changes are committed and pushed automatically

---

## Local Development

```bash
pip install requests pyyaml
python scripts/convert_feeds.py
```

Output files are written to the `output/` directory.

---

## License

MIT -- see [LICENSE](LICENSE) for details.
