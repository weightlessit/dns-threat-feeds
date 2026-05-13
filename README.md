# DNS Threat Feeds -- AdGuard Home + FortiGate

Automated pipeline that fetches threat intelligence feeds and converts them
into formats compatible with **AdGuard Home** and **Fortinet FortiGate**.

A GitHub Action runs every 6 hours, pulls the latest feeds, normalises them,
and commits the updated lists. Point your devices at the raw GitHub URLs.

---

## Why does this exist?

Threat intelligence feeds come in a dozen different formats -- hosts files,
CSV dumps, URL lists, AdGuard syntax, plain IPs, CIDR blocks, IP ranges,
hash lists. Neither AdGuard Home nor FortiGate can consume them all natively.
This project normalises everything into the exact format each platform
expects and keeps it current automatically.

---

## Output Formats

| Platform | Domain format | IP format | Hash format | Output directory |
|----------|---------------|-----------|-------------|------------------|
| AdGuard Home | `||domain^` | *n/a* | *n/a* | `output/adguard/` |
| FortiGate | plain domain | plain IP/CIDR/range | plain hex hash | `output/fortigate/domains/` `ip/` `hash/` |

**Why no IP or hash feeds for AdGuard?** AdGuard Home is a DNS sinkhole that
matches hostnames. It cannot act on raw IPs or file hashes. FortiGate uses
all three as firewall address objects, DNS filter entries, and AV profile
hash blocklists respectively.

---

## Quick Start -- AdGuard Home

1. Open **AdGuard Home > Filters > DNS Blocklists > Add blocklist > Add a custom list**
2. Paste a raw URL from the table below
3. Repeat for each feed (or just use **Combined**)

### AdGuard Domain Feed URLs

| Feed | Raw URL |
|------|---------|| URLhaus Malware Domains | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/urlhaus-hostfile-domains.txt` |
| URLhaus Recent URLs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/urlhaus-recent-domains.txt` |
| ThreatFox IOC Domains | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/threatfox-domains.txt` |
| Phishing Army Extended | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/phishing-army-domains.txt` |
| OpenPhish Community | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/openphish-domains.txt` |
| PhishTank Verified | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/phishtank-domains.txt` |
| CERT Polska | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/cert-polska-domains.txt` |
| CyberHost Malware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/cyberhost-malware-domains.txt` |
| Disconnect Malvertising | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/disconnect-malvertising.txt` |
| StopForumSpam Toxic | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/stopforumspam-toxic.txt` |
| BLP - Malware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-malware.txt` |
| BLP - Phishing | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-phishing.txt` |
| BLP - Ransomware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-ransomware.txt` |
| HaGeZi Threat Intel | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/hagezi-tif.txt` |
| **Combined (all domains)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/combined.txt` |

---

## Quick Start -- FortiGate

FortiGate imports external threat feeds as plain text files via
**Security Fabric > External Connectors > Threat Feeds**.

Important: FortiGate requires **separate feeds for domains, IPs, and hashes**.
Do not mix them. This project keeps them in separate directories.

### FortiGate Domain Feeds

Use type **Domain Name** when creating the connector.

| Feed | Raw URL |
|------|---------|| **Combined Domains** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/combined.txt` |

Individual feeds use the same path -- replace `combined` with the output
name from `config/feeds.yml` (e.g. `urlhaus-hostfile-domains`).

### FortiGate IP Feeds

Use type **IP Address** when creating the connector.

FortiGate supports single IPs, CIDR notation, and IP ranges (x.x.x.x-y.y.y.y).
All three formats are used in these feeds depending on the upstream source.

| Feed | Raw URL |
|------|---------|| ET Compromised IPs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/et-compromised-ips.txt` |
| Feodo Tracker C2 | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/feodo-tracker-ips.txt` |
| Spamhaus DROP | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/spamhaus-drop.txt` |
| Blocklist.de All | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/blocklist-de-all.txt` |
| CINSscore Bad IPs | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/cinsscore-badguys.txt` |
| Binary Defense | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/binarydefense-banlist.txt` |
| ThreatHive | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/threathive.txt` |
| IPSum Level 3 | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/ipsum-level3.txt` |
| OpenDBL ET Known | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/opendbl-etknown.txt` |
| OpenDBL Bruteforce | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/opendbl-bruteforce.txt` |
| OpenDBL DShield | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/opendbl-dshield.txt` |
| Bitwire Outbound | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/bitwire-outbound.txt` |
| Bitwire Inbound | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/bitwire-inbound.txt` |
| **Combined (all IPs)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/combined.txt` |

### FortiGate Malware Hash Feeds

Use type **Malware Hash** when creating the connector.

To use hash feeds, you must also enable **"Use external malware block list"**
in your Antivirus profile (Security Profiles > AntiVirus > edit profile).

Fortinet recommends using only ONE hash type per feed (do not mix MD5/SHA1/
SHA256 in the same file). All feeds in this project use SHA256 exclusively.

| Feed | Raw URL |
|------|---------|| romainmarcoux SHA256 | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/hash/romainmarcoux-sha256.txt` |
| **Combined (all hashes)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/hash/combined.txt` |

Note: MalwareBazaar SHA256 export is included in feeds.yml as a commented-out
option -- it requires a free auth key from https://auth.abuse.ch.

### FortiGate CLI Configuration Examples

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

# Malware hash threat feed (Antivirus external block list)
config system external-resource
    edit "ThreatFeed-Hashes"
        set type malware
        set resource "https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/hash/combined.txt"
        set refresh-rate 360
    next
end

# Enable external hash blocklist in AV profile
config antivirus profile
    edit "default"
        set external-blocklist enable
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

### Domain Feeds (AdGuard + FortiGate) -- 14 feeds

| Source | Type | Description |
|--------|------|-------------|
| [URLhaus](https://urlhaus.abuse.ch/) | Hosts | Malware distribution domains |
| [URLhaus Recent](https://urlhaus.abuse.ch/) | URL | Recently reported malicious URLs |
| [ThreatFox](https://threatfox.abuse.ch/) | Hosts | IOC domains (C2, payload delivery) |
| [Phishing Army](https://phishing.army/) | Domain | Aggregated phishing domains (extended) |
| [OpenPhish](https://openphish.com/) | URL | Community phishing URLs |
| [PhishTank](https://phishtank.org/) | CSV | Verified active phishing domains |
| [CERT Polska](https://hole.cert.pl/) | Domain | Malicious domains from Polish CERT |
| [CyberHost](https://cyberhost.uk/malware-blocklist/) | Domain | Verified malware and phishing domains |
| [Disconnect](https://disconnect.me/) | Domain | Malvertising distribution domains |
| [StopForumSpam](https://www.stopforumspam.com/) | Domain | Spam/scam toxic domains |
| [Block List Project](https://blocklistproject.github.io/Lists/) | AdGuard | Malware, phishing, ransomware |
| [HaGeZi](https://github.com/hagezi/dns-blocklists) | AdGuard | Curated threat intelligence feeds |

### IP Feeds (FortiGate only) -- 13 feeds

| Source | Format | Description |
|--------|--------|-------------|
| [Emerging Threats](https://rules.emergingthreats.net/) | IP | Compromised IPs (Proofpoint) |
| [Feodo Tracker](https://feodotracker.abuse.ch/) | IP | Botnet C2 server IPs |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | CIDR | Hijacked IP ranges (EDROP merged in) |
| [Blocklist.de](https://www.blocklist.de/) | IP | IPs attacking services (SSH, mail, web) |
| [CINSscore](https://cinsscore.com/) | IP | Collective intelligence threat IPs |
| [Binary Defense](https://www.binarydefense.com/) | IP | Honeypot ban list |
| [ThreatHive](https://threathive.net/) | IP | 140K IPs from honeypot + OSINT (15 min) |
| [IPSum L3](https://github.com/stamparm/ipsum) | IP | IPs on 3+ blacklists (high confidence) |
| [OpenDBL ET Known](https://opendbl.net/) | IP | ET compromised hosts (firewall-ready) |
| [OpenDBL Bruteforce](https://opendbl.net/) | IP | SSH/service brute-force attackers |
| [OpenDBL DShield](https://opendbl.net/) | Range | SANS DShield top attackers |
| [Bitwire Outbound](https://github.com/bitwire-it/ipblocklist) | IP | C2, malware drops, phishing (outbound) |
| [Bitwire Inbound](https://github.com/bitwire-it/ipblocklist) | IP | Scanners, brute-force, spam (inbound) |

### Malware Hash Feeds (FortiGate only) -- 1 feed

| Source | Hash Type | Description |
|--------|-----------|-------------|
| [romainmarcoux](https://github.com/romainmarcoux/malicious-hash) | SHA256 | 71K aggregated malware hashes, updated daily |

---

## Adding a New Feed

Edit `config/feeds.yml` and add an entry to the appropriate section:

```yaml
domain_feeds:
  - name: My New Domain Feed
    url: https://example.com/domains.txt
    type: domain        # domain | hosts | url | adguard | phishtank_csv
    output: my-new-feed
    description: What this feed blocks

ip_feeds:
  - name: My New IP Feed
    url: https://example.com/ips.txt
    type: ip            # supports plain IP, CIDR, and x.x.x.x-y.y.y.y ranges
    output: my-new-ip-feed
    description: What this feed blocks

hash_feeds:
  - name: My New Hash Feed
    url: https://example.com/hashes.txt
    type: hash
    output: my-new-hash-feed
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
    +---> output/adguard/*.txt              (||domain^ format)
    +---> output/fortigate/domains/*.txt    (plain domain)
    +---> output/fortigate/ip/*.txt         (plain IP/CIDR/range)
    +---> output/fortigate/hash/*.txt       (plain hex hash)
```

1. GitHub Action triggers every 6 hours (or manually)
2. Script reads feeds.yml and downloads each feed
3. Domain feeds output in both AdGuard and FortiGate formats
4. IP feeds output in FortiGate format only (supports IP, CIDR, and ranges)
5. Hash feeds output in FortiGate format only
6. Combined/merged lists are generated for each output type
7. Changes are committed and pushed automatically

---

## Local Development

```bash
pip install requests pyyaml
python scripts/convert_feeds.py
```

---

## License

MIT -- see [LICENSE](LICENSE) for details.
