# CyberSec Tools v2.0.0

Collection of 26 cybersecurity CLI tools for penetration testing, security auditing, and OSINT reconnaissance.

## Installation

```bash
git clone https://github.com/habiutomo/tools-cyber-security.git
cd tools-cyber-security
pip install -r requirements.txt
```

## Usage

```bash
python cybersec.py <module> [options]
```

## Modules

### Network Recon

| Module | Description | Example |
|--------|-------------|---------|
| `portscan` | Port scanner with banner grabbing | `python cybersec.py portscan -t target.com --top 20` |
| `hostdisco` | Discover live hosts in network | `python cybersec.py hostdisco -t 192.168.1.0/24` |
| `pingsweep` | ICMP ping sweep network range | `python cybersec.py pingsweep -t 192.168.1.1-50` |
| `traceroute` | Trace network path to target | `python cybersec.py traceroute -t 8.8.8.8` |

### Reconnaissance

| Module | Description | Example |
|--------|-------------|---------|
| `subdomain` | Subdomain enumeration via DNS brute-force | `python cybersec.py subdomain -d target.com` |
| `revip` | Reverse IP lookup + Shodan data | `python cybersec.py revip -t target.com --shodan` |
| `dnslookup` | Query DNS records (A, MX, NS, TXT, etc.) | `python cybersec.py dnslookup -d target.com --all` |
| `whois` | WHOIS domain registration info | `python cybersec.py whois -t target.com` |

### Web Security

| Module | Description | Example |
|--------|-------------|---------|
| `headers` | HTTP security header analysis | `python cybersec.py headers -u https://target.com` |
| `httpmethods` | Test for dangerous HTTP methods | `python cybersec.py httpmethods -u https://target.com` |
| `cors` | Detect CORS misconfigurations | `python cybersec.py cors -u https://target.com` |
| `redirect` | Detect open redirect vulnerabilities | `python cybersec.py redirect -u "https://target.com?next=x"` |
| `dirbust` | Directory & file brute-force | `python cybersec.py dirbust -u https://target.com` |
| `sensfiles` | Find sensitive files (.env, .git, backups) | `python cybersec.py sensfiles -u https://target.com` |

### Security Analysis

| Module | Description | Example |
|--------|-------------|---------|
| `sslcheck` | SSL/TLS certificate & protocol analysis | `python cybersec.py sslcheck -t target.com --check-protocols` |
| `wafdetect` | Detect Web Application Firewalls | `python cybersec.py wafdetect -u https://target.com` |
| `techdetect` | Detect technologies on website | `python cybersec.py techdetect -u https://target.com` |
| `takeover` | Subdomain takeover vulnerability check | `python cybersec.py takeover -s sub1.target.com sub2.target.com` |

### Cryptography & Passwords

| Module | Description | Example |
|--------|-------------|---------|
| `pwdgen` | Generate secure passwords | `python cybersec.py pwdgen -l 24 -n 5` |
| `pwdcheck` | Check password strength | `python cybersec.py pwdcheck "MyP@ssw0rd!"` |
| `hashgen` | Generate hashes (MD5, SHA1, SHA256, etc.) | `python cybersec.py hashgen "text" -a sha256` |
| `hashcrack` | Crack hashes with wordlist | `python cybersec.py hashcrack -H <hash> -a md5` |

### OSINT

| Module | Description | Example |
|--------|-------------|---------|
| `emailosint` | Email OSINT (Gravatar, breach check) | `python cybersec.py emailosint -e target@email.com --breach` |
| `userosint` | Username lookup across 31 platforms | `python cybersec.py userosint -u username` |

### Wireless & URL

| Module | Description | Example |
|--------|-------------|---------|
| `wifi` | Scan nearby WiFi networks | `python cybersec.py wifi` |
| `urlcheck` | Check URL for phishing/malware | `python cybersec.py urlcheck "https://suspicious-site.com"` |

## Module Details

### Port Scanner (`portscan`)

```bash
python cybersec.py portscan -t 192.168.1.1 -p 1-1000
python cybersec.py portscan -t target.com --top 20 -b
```

Options:
- `-t, --target` : Target IP or hostname
- `-p, --ports` : Port range (e.g. 1-1024, 80,443)
- `--top` : Scan top N common ports
- `-T, --timeout` : Connection timeout
- `-b, --banner` : Grab banners from open ports
- `-o, --output` : Save results to file

### Subdomain Enumeration (`subdomain`)

```bash
python cybersec.py subdomain -d example.com
python cybersec.py subdomain -d example.com -w wordlists/subdomains.txt -t 30
```

Options:
- `-d, --domain` : Target domain
- `-w, --wordlist` : Custom wordlist file
- `-t, --threads` : Number of threads
- `-o, --output` : Save results to file

### SSL/TLS Checker (`sslcheck`)

```bash
python cybersec.py sslcheck -t target.com
python cybersec.py sslcheck -t target.com --check-protocols
```

Analyzes:
- Certificate subject, issuer, validity
- TLS version & cipher suite
- Protocol support (SSLv2, SSLv3, TLSv1.0-1.3)
- Weak cipher detection

### HTTP Header Analyzer (`headers`)

```bash
python cybersec.py headers -u https://target.com
python cybersec.py headers -u https://target.com --all-headers
```

Checks for:
- Strict-Transport-Security
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- And more...

### URL Phishing Checker (`urlcheck`)

```bash
python cybersec.py urlcheck "https://suspicious-site.com"
python cybersec.py urlcheck "https://google.com" "http://phishing.tk"
```

Detects:
- Missing HTTPS
- Suspicious TLDs (.tk, .xyz, etc.)
- URL shorteners
- Phishing keywords
- IP address usage
- Excessive subdomains
- Redirect parameters

### Username OSINT (`userosint`)

```bash
python cybersec.py userosint -u john_doe
```

Searches across 31 platforms:
GitHub, GitLab, Twitter/X, Instagram, Reddit, LinkedIn, YouTube, TikTok, Pinterest, Medium, DeviantArt, Twitch, Steam, Keybase, HackerRank, LeetCode, StackOverflow, npm, PyPI, DockerHub, Gravatar, About.me, Patreon, Flickr, Spotify, SoundCloud, Dev.to, Replit, CodePen, Behance, Dribbble

### Hash Generator (`hashgen`)

```bash
python cybersec.py hashgen "password123"
python cybersec.py hashgen "text" -a md5 sha256 sha512
python cybersec.py hashgen "text" --all-algos
python cybersec.py hashgen -f sensitive_file.txt
```

Supported algorithms: MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s

### Password Generator (`pwdgen`)

```bash
python cybersec.py pwdgen
python cybersec.py pwdgen -l 32 -n 10
python cybersec.py pwdgen --no-special --no-digits
```

Options:
- `-l, --length` : Password length (default: 16)
- `-n, --count` : Number of passwords
- `--no-upper` : Exclude uppercase
- `--no-lower` : Exclude lowercase
- `--no-digits` : Exclude digits
- `--no-special` : Exclude special characters

## Wordlists

Custom wordlists included in `wordlists/`:
- `common.txt` - Common directories for brute-force
- `subdomains.txt` - Subdomain enumeration wordlist

## Requirements

- Python 3.8+
- Dependencies listed in `requirements.txt`

## Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any target systems.

## License

MIT License
