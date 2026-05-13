# DNS Threat Feeds -- AdGuard Home + FortiGate

Automated pipeline that fetches threat intelligence feeds and converts them
into formats compatible with **AdGuard Home** and **Fortinet FortiGate**.

A GitHub Action runs every 6 hours, pulls the latest feeds, normalises them,
and commits the updated lists. Point your devices at the raw GitHub URLs.

---

## Why does this exist?

Threat intelligence feeds come in a dozen different formats -- hosts files,
CSV dumps, URL lists, AdGuard syntax, plain IPs, CIDR blocks. Neither
AdGuard Home nor FortiGate can consume them all natively. This project
normalises everything into the exact format each platform expects and keeps
it current automatically.

---

## Dual Output Formats

Every feed is converted into the correct format for each target platform:

| Platform | Domain format | IP format | Output directory |
|----------|---------------|-----------|------------------|
| AdGuard Home | `||domain^` (adblock-style) | *not generated* | `output/adguard/` |
| FortiGate | plain domain, one per line | plain IP/CIDR, one per line | `output/fortigate/domains/` and `output/fortigate/ip/` |

---

## Why are IP feeds only in FortiGate output?

AdGuard Home is a **DNS sinkhole**. It intercepts DNS queries and matches
against hostnames/FQDNs. It does not inspect what IP address a domain
resolves to, and it cannot act as a network firewall. A rule like
`||185.x.x.x^` is effectively useless.

FortiGate, on the other hand, can use IP-based external threat feeds
directly in firewall policies (source/destination address objects) to deny
traffic at the network layer. That is exactly where IP feeds belong.

---

## Quick Start -- AdGuard Home

1. Open **AdGuard Home > Filters > DNS Blocklists > Add blocklist > Add a custom list**
2. Paste a raw URL from the table below
3. Repeat for each feed (or just use **Combined**)

### AdGuard Domain Feed URLs

| Feed | Raw URL |
|------|---------|
| URLhaus Malware Domains | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/urlhaus-hostfile-domains.txt` |
| URLhaus Recent URLs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/urlhaus-recent-domains.txt` |
| ThreatFox IOC Domains | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/threatfox-domains.txt` |
| Phishing Army Extended | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/phishing-army-domains.txt` |
| OpenPhish Community | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/openphish-domains.txt` |
| PhishTank Verified | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/phishtank-domains.txt` |
| CERT Polska | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/cert-polska-domains.txt` |
| DigitalSide.it | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/digitalside-domains.txt` |
| Rescure Domains | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/rescure-domains.txt` |
| Maltrail Malware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/maltrail-malware-domains.txt` |
| Block List Project - Malware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-malware.txt` |
| Block List Project - Phishing | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-phishing.txt` |
| Block List Project - Ransomware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-ransomware.txt` |
| HaGeZi Threat Intel | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/hagezi-tif.txt` |
| **Combined (all domains)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/combined.txt` |

---

## Quick Start -- FortiGate

FortiGate imports external threat feeds as plain text files via
**Security Fabric > External Connectors > Threat Feeds**.

Important: FortiGate requires **separate feeds for domains and IPs**.
Do not mix them. This project keeps them in separate directories.

### FortiGate Domain Feeds

Use type **Domain Name** when creating the connector.

| Feed | Raw URL |
|------|---------|
| **Combined Domains** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/combined.txt` |

Individual feeds use the same path pattern -- replace `combined` with the
output name from `config/feeds.yml` (e.g. `urlhaus-hostfile-domains`).

### FortiGate IP Feeds

Use type **IP Address** when creating the connector.

| Feed | Raw URL |
|------|---------|
| ET Compromised IPs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/et-compromised-ips.txt` |
| Feodo Tracker C2 | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/feodo-tracker-ips.txt` |
| Spamhaus DROP | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/spamhaus-drop.txt` |
| Spamhaus EDROP | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/spamhaus-edrop.txt` |
| Blocklist.de All | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/blocklist-de-all.txt` |
| CINSscore Bad IPs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/cinsscore-badguys.txt` |
| DigitalSide.it IPs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/digitalside-ips.txt` |
| Binary Defense | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/binarydefense-banlist.txt` |
| **Combined (all IPs)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/combined.txt` |

### FortiGate CLI Configuration Example

```
# Domain threat feed (DNS Filter / Web Filter)
config system external-resource
    edit "ThreatFeed-Domains"
        set type domain
        set category 192
        set resource "https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/combined.txt"
        set refresh-rate 360
    next
end

# IP threat feed (Firewall policy address object)
config system external-resource
    edit "ThreatFeed-IPs"
        set type address
        set resource "https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/combined.txt"
        set refresh-rate 360
    next
end

# Example deny policy using the IP feed
config firewall policy
    edit 0
        set name "Block-Threat-IPs"
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "ThreatFeed-IPs"
        set action deny
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
```

---

## Included Feeds

### Domain Feeds (AdGuard + FortiGate)

| Source | Type | Description |
|--------|------|-------------|
| [URLhaus](https://urlhaus.abuse.ch/) | Hosts | Malware distribution domains |
| [URLhaus Recent](https://urlhaus.abuse.ch/) | URL | Recently reported malicious URLs |
| [ThreatFox](https://threatfox.abuse.ch/) | Hosts | IOC domains (C2, payload delivery) |
| [Phishing Army](https://phishing.army/) | Domain | Aggregated phishing domains (extended) |
| [OpenPhish](https://openphish.com/) | URL | Community phishing URLs |
| [PhishTank](https://phishtank.org/) | CSV | Verified active phishing domains |
| [CERT Polska](https://hole.cert.pl/) | Domain | Malicious domains from Polish national CERT |
| [DigitalSide.it](https://osint.digitalside.it/) | Domain | OSINT malware domains |
| [Rescure](https://rescure.me/) | Domain | Cyber threat intel domains |
| [Maltrail](https://github.com/stamparm/maltrail) | Domain | Static malware-associated domains |
| [Block List Project](https://blocklistproject.github.io/Lists/) | AdGuard | Malware, phishing, ransomware |
| [HaGeZi](https://github.com/hagezi/dns-blocklists) | AdGuard | Curated threat intelligence feeds |

### IP Feeds (FortiGate only)

| Source | Description |
|--------|-------------|
| [Emerging Threats](https://rules.emergingthreats.net/) | Compromised IPs (Proofpoint) |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | Botnet C2 server IPs |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Hijacked IP ranges |
| [Spamhaus EDROP](https://www.spamhaus.org/drop/) | Extended hijacked ranges |
| [Blocklist.de](https://www.blocklist.de/) | IPs attacking services (SSH, mail, web) |
| [CINSscore](https://cinsscore.com/) | Collective intelligence threat IPs |
| [DigitalSide.it](https://osint.digitalside.it/) | OSINT malicious IPs |
| [Binary Defense](https://www.binarydefense.com/) | Honeypot ban list |

---

## Adding a New Feed

Edit `config/feeds.yml` and add an entry to the appropriate section:

```yaml
# Domain feed (generates AdGuard + FortiGate output)
domain_feeds:
  - name: My New Domain Feed
    url: https://example.com/domains.txt
    type: domain        # domain | hosts | url | adguard | phishtank_csv
    output: my-new-feed
    description: What this feed blocks

# IP feed (generates FortiGate output only)
ip_feeds:
  - name: My New IP Feed
    url: https://example.com/ips.txt
    type: ip
    output: my-new-ip-feed
    description: What this feed blocks
```

---

## How It Works

```
config/feeds.yml
    |
    v
scripts/convert_feeds.py
    |
    +---> output/adguard/*.txt           (||domain^ format)
    +---> output/fortigate/domains/*.txt  (plain domain)
    +---> output/fortigate/ip/*.txt       (plain IP/CIDR)
```

1. GitHub Action triggers every 6 hours (or manually)
2. Script reads feeds.yml and downloads each feed
3. Domain feeds are parsed and output in both AdGuard and FortiGate formats
4. IP feeds are parsed and output in FortiGate format only
5. Combined/merged lists are generated for each output type
6. Changes are committed and pushed automatically

---

## Local Development

```bash
pip install requests pyyaml
python scripts/convert_feeds.py
```

Output directories:
- `output/adguard/`            -- AdGuard Home blocklists
- `output/fortigate/domains/`  -- FortiGate domain threat feeds
- `output/fortigate/ip/`       -- FortiGate IP threat feeds

---

## License

MIT -- see [LICENSE](LICENSE) for details.
