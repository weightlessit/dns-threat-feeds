# DNS Threat Feeds -- AdGuard Home + FortiGate

Automated pipeline that fetches threat intelligence feeds and converts them
into formats compatible with **AdGuard Home** and **Fortinet FortiGate**.

A GitHub Action runs every 6 hours, pulls the latest feeds, normalises them,
and commits the updated lists. Point your devices at the raw GitHub URLs.

---

## Why does this exist?

Threat intelligence feeds come in a dozen different formats -- hosts files,
CSV dumps, URL lists, AdGuard syntax, plain IPs, CIDR blocks, IP ranges,
hash lists, and custom delimited formats (like AlienVault). Neither AdGuard
Home nor FortiGate can consume them all natively. This project normalises
everything into the exact format each platform expects and keeps it current
automatically.

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

## FortiGate Model-Tier Limits (FortiOS 7.4.4+)

Starting with FortiOS 7.4.4, external threat feed entry limits are applied
**globally** (across all feeds of the same type combined) and vary by model
tier. If you exceed these limits, entries are silently truncated.

| Resource Type | Entry-Level (Branch) | Mid-Range (Campus) | High-End (Data Center) |
|---------------|---------------------|--------------------|-----------------------|
| Category (URL) | 150,000 | 300,000 | 2,000,000 |
| **IP Address** | **300,000** | 300,000 (1M on 7.4.9+/7.6.3+) | 300,000 (5M on 7.4.9+/7.6.3+) |
| **Domain** | **1,000,000** | 3,000,000 | 5,000,000 |
| MAC Address | 1,000,000 | 1,000,000 | 1,000,000 |
| File size limit | 32 MB | 64 MB | 128 MB |

**Entry-level models** include: FortiGate 40F, 60E/F, 70F, 80E/F, 90E, etc.
**Mid-range models** include: FortiGate 100F, 200F, 400E/F, 600E, etc.
**High-end models** include: FortiGate 1000F, 2000E, 3000F, 6000F, etc.

> **Before FortiOS 7.4.4**, the limit was **131,072 entries per feed** and
> **10 MB file size** regardless of model. If you are running an older
> firmware, use the individual feed files rather than combined lists.

### Checking for Truncation

Run this command on the FortiGate CLI to see per-feed statistics:

```
diagnose sys external-resource stats
```

Example output:

```
name: ThreatFeed-Domains; uuid_idx: 606; type: domain;
  update_method: feed;
  truncated total lines: 2262179;
  valid lines: 2262179;
  error lines: 0;
  used: yes;
  buildable: 261969;
  total in count file: 2262179;
```

Key fields:
- **valid lines** -- entries with correct syntax (parsed successfully)
- **buildable** -- entries actually accepted and enforced
- **If `buildable` < `valid lines`, entries are being truncated!**

In the example above, 2M domains were valid but only ~262K were accepted --
the FortiGate hit its global domain limit and dropped the rest.

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
| CERT Polska | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/cert-polska-domains.txt` |
| CyberHost Malware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/cyberhost-malware-domains.txt` |
| Disconnect Malvertising | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/disconnect-malvertising.txt` |
| StopForumSpam Toxic | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/stopforumspam-toxic.txt` |
| BLP - Malware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-malware.txt` |
| BLP - Phishing | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-phishing.txt` |
| BLP - Ransomware | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/blp-ransomware.txt` |
| HaGeZi Threat Intel | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/hagezi-tif.txt` |
| **Combined (all domains)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/adguard/combined.txt` |

AdGuard Home has no entry limit like FortiGate -- use combined.txt freely.

---

## Quick Start -- FortiGate

FortiGate imports external threat feeds as plain text files via
**Security Fabric > External Connectors > Threat Feeds**.

Important: FortiGate requires **separate feeds for domains, IPs, and hashes**.
Do not mix them. This project keeps them in separate directories.

> **Entry-level models (80E, 60F, 40F, etc.):** Use the
> `entry-model-combined.txt` files instead of `combined.txt`.
> See [Entry-Model Combined Lists](#entry-model-combined-lists) below.

### FortiGate Domain Feeds

Use type **Domain Name** when creating the connector.

| Feed | Raw URL |
|------|---------|
| **Entry-Model Combined (recommended for 80E, 60F, etc.)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/entry-model-combined.txt` |
| **Full Combined (mid-range/high-end only)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/combined.txt` |

### FortiGate IP Feeds

Use type **IP Address** when creating the connector.

| Feed | Raw URL |
|------|---------|
| **Entry-Model Combined (recommended for 80E, 60F, etc.)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/entry-model-combined.txt` |
| **Full Combined (mid-range/high-end only)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/combined.txt` |

### FortiGate Malware Hash Feeds

Use type **Malware Hash** when creating the connector.

| Feed | Raw URL |
|------|---------|
| romainmarcoux SHA256 | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/hash/romainmarcoux-sha256.txt` |
| MalwareBazaar Recent SHA256 | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/hash/malwarebazaar-sha256.txt` |
| **Combined (all hashes)** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/hash/combined.txt` |

### FortiGate CLI Configuration Examples

```
# Domain threat feed -- use entry-model-combined for entry-level hardware
# Switch to combined.txt for mid-range/high-end models
config system external-resource
    edit "ThreatFeed-Domains"
        set type domain
        set category 192
        set resource "https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/entry-model-combined.txt"
        set refresh-rate 360
    next
end

# IP threat feed -- use entry-model-combined for entry-level hardware
config system external-resource
    edit "ThreatFeed-IPs"
        set type address
        set resource "https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/entry-model-combined.txt"
        set refresh-rate 360
    next
end

# Malware hash threat feed
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

After applying, verify with: `diagnose sys external-resource stats`

---

## Entry-Model Combined Lists

These curated combined lists are designed to fit within the global entry
limits of **FortiGate entry-level models** (80E, 60F, 40F, 90E, etc.)
running **FortiOS 7.4.4 or later**.

| File | Target | Limit | Headroom |
|------|--------|-------|----------|
| `entry-model-combined.txt` (domains) | ~750,000 | 1,000,000 | ~250,000 |
| `entry-model-combined.txt` (IPs) | ~200,000 | 300,000 | ~100,000 |

### Domain feeds included (7 of 13)

| Feed | Est. Entries | Why included |
|------|-------------|--------------|
| HaGeZi TIF | ~500K | Most comprehensive single source |
| Phishing Army Extended | ~80K | Broad phishing coverage |
| URLhaus Malware Domains | ~50K | Active malware distribution |
| CyberHost Malware/Phishing | ~37K | Verified malware and phishing |
| ThreatFox IOC Domains | ~30K | C2 and payload delivery |
| CERT Polska | ~20K | National CERT malware domains |
| OpenPhish Community | ~5K | Active phishing URLs |

### Domain feeds excluded (6 of 13)

| Feed | Reason |
|------|--------|
| URLhaus Recent URLs | Heavily overlaps with URLhaus hostfile |
| Disconnect Malvertising | Lower priority (ad-related, not malware) |
| StopForumSpam Toxic | Lower priority (spam, not malware/phishing) |
| BLP Malware | ~200K entries, heavy overlap with HaGeZi TIF |
| BLP Phishing | ~200K entries, heavy overlap with HaGeZi TIF |
| BLP Ransomware | Small but overlaps with HaGeZi TIF |

### IP feeds included (12 of 15)

| Feed | Est. Entries | Why included |
|------|-------------|--------------|
| Blocklist.de All | ~30K | SSH/mail/web attack detection |
| IPSum Level 3 | ~18K | High confidence (3+ blacklists) |
| CINSscore Bad IPs | ~15K | Collective intelligence |
| Binary Defense | ~3K | Honeypot ban list |
| Spamhaus DROP | ~1K CIDRs | Hijacked IP ranges (critical) |
| ET Compromised IPs | ~500 | Proofpoint compromised hosts |
| ET Firewall Block IPs | varies | Broader ET block list |
| OpenDBL ET Known | ~400 | ET hosts (firewall-ready) |
| OpenDBL Bruteforce | ~400 | Brute-force attackers |
| Feodo Tracker C2 | ~200 | Botnet C2 (critical) |
| OpenDBL DShield | ~20 ranges | SANS DShield top attackers |
| Bitwire Outbound | varies | C2/malware drops (outbound) |

### IP feeds excluded (3 of 15)

| Feed | Reason |
|------|--------|
| ThreatHive | ~140K alone eats half the 300K budget; heavy overlap |
| Bitwire Inbound | Save headroom; outbound is higher priority for C2 blocking |
| AlienVault Reputation | Very large; significant overlap with other feeds |

### Entry-Model Combined URLs

| Type | Raw URL |
|------|---------|
| **Domains** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/domains/entry-model-combined.txt` |
| **IPs** | `https://raw.githubusercontent.com/weightlessit/dns-threat-feeds/main/output/fortigate/ip/entry-model-combined.txt` |

> **Recommendation:** On entry-level FortiGates, use ONLY the
> entry-model-combined files as your single domain and IP threat feed.
> Do not add additional individual feeds on top -- the entry counts are
> global and will cause truncation. If you need specific individual feeds
> instead, manually select feeds that fit within your model's budget.

---

## Included Feeds

### Domain Feeds (AdGuard + FortiGate) -- 13 feeds

| Source | Type | Description |
|--------|------|-------------|
| [URLhaus](https://urlhaus.abuse.ch/) | Hosts | Malware distribution domains |
| [URLhaus Recent](https://urlhaus.abuse.ch/) | URL | Recently reported malicious URLs |
| [ThreatFox](https://threatfox.abuse.ch/) | Hosts | IOC domains (C2, payload delivery) |
| [Phishing Army](https://phishing.army/) | Domain | Aggregated phishing domains (extended) |
| [OpenPhish](https://openphish.com/) | URL | Community phishing URLs |
| [CERT Polska](https://hole.cert.pl/) | Domain | Malicious domains from Polish CERT |
| [CyberHost](https://cyberhost.uk/malware-blocklist/) | Domain | Verified malware and phishing domains |
| [Disconnect](https://disconnect.me/) | Domain | Malvertising distribution domains |
| [StopForumSpam](https://www.stopforumspam.com/) | Domain | Spam/scam toxic domains |
| [Block List Project](https://blocklistproject.github.io/Lists/) | AdGuard | Malware, phishing, ransomware |
| [HaGeZi](https://github.com/hagezi/dns-blocklists) | AdGuard | Curated threat intelligence feeds |

### IP Feeds (FortiGate only) -- 15 feeds

| Source | Format | Description |
|--------|--------|-------------|
| [Emerging Threats](https://rules.emergingthreats.net/) | IP | Compromised IPs (Proofpoint) |
| [Emerging Threats FW](https://rules.emergingthreats.net/) | IP | Firewall block IPs (broader coverage) |
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
| [AlienVault](https://reputation.alienvault.com/) | Custom | IP reputation (scanning, malware, C2) |

### Malware Hash Feeds (FortiGate only) -- 2 feeds

| Source | Hash Type | Description |
|--------|-----------|-------------|
| [romainmarcoux](https://github.com/romainmarcoux/malicious-hash) | SHA256 | 71K aggregated malware hashes, updated daily |
| [MalwareBazaar](https://bazaar.abuse.ch/) | SHA256 | Recent malware submissions (last 48h, continuous) |

---

## Adding a New Feed

Edit `config/feeds.yml` and add an entry to the appropriate section:

```yaml
domain_feeds:
  - name: My New Domain Feed
    url: https://example.com/domains.txt
    type: domain        # domain | hosts | url | adguard
    output: my-new-feed
    entry_combined: true # include in entry-model-combined.txt (optional)
    description: What this feed blocks

ip_feeds:
  - name: My New IP Feed
    url: https://example.com/ips.txt
    type: ip            # ip (plain/CIDR/range) | alienvault (custom format)
    output: my-new-ip-feed
    entry_combined: true # include in entry-model-combined.txt (optional)
    description: What this feed blocks
```

> **Important:** When adding feeds with `entry_combined: true`, verify
> the total entry count stays within your model's limits using:
> `diagnose sys external-resource stats`

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
4. IP feeds output in FortiGate format only (supports IP, CIDR, ranges, AlienVault)
5. Hash feeds output in FortiGate format only
6. Three combined variants are generated:
   - `combined.txt` -- all feeds merged (for mid-range/high-end FortiGates and AdGuard)
   - `entry-model-combined.txt` -- curated subset (for entry-level FortiGates)
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
