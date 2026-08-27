# Termux-Tool

Offensive framework for **reconnaissance, OSINT, scanning and security analysis**,
written **100% in Python from the standard library**. No `pip` dependencies, no
root and **no external binaries**: protocols (DNS, WHOIS, TCP, TLS, HTTP) are
implemented from scratch using `socket`, `ssl` and `urllib`.

Designed to run **100% on Termux (Android)** and also on **Kali/Debian**.

```
              ░▒░                       ░▒░
        ░▓▓▓▓▓█▒       ▒      ▒      ░█▓▓▓▓▓░
      ▒█████████▒     ██▓    ▒██    ▒█████████▒
    ▒████████████▓    ▓█████████   ▓████████████▒
   ████████████████▓░░████████░░▓████████████████
 ░████████████████████████████████████████████████░
 ▒   ▒████████████████████████████████████████▒   ▒
      ▒█▒░▒▓████████████████████████████▓▒░▒█▒
             ▓█████████████████████████░
              ▓▒░▒▓██████████████▓▒░▒█
                     ▓██████████▓
                       ▓█████████
                          ████░
                          ▓▓█▓░
                           ░█

    ████████╗███████╗██████╗ ███╗   ███╗██╗   ██╗██╗  ██╗
    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██║   ██║╚██╗██╔╝
       ██║   █████╗  ██████╔╝██╔████╔██║██║   ██║ ╚███╔╝
       ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║   ██║ ██╔██╗
       ██║   ███████╗██║  ██║██║ ╚═╝ ██║╚██████╔╝██╔╝ ██╗
       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝
              ▓▒░  T · O · O · L  ░▒▓
```

---

## Features

- **47 tools** distributed across 5 categories.
- **Central script** (`termux-tool.py`) that orchestrates modules, which live separately in `modules/`.
- **Orange/red** color theme with ANSI 256 and bat ASCII art (real silhouette converted to Unicode blocks).
- **Zero external dependencies** → no conflicts with Termux package manager.
- **No root**: scanning uses TCP `connect()` (not raw SYN), DNS is UDP client.
- Multithreading (`concurrent.futures`) for fast scanning.

---

## Installation

### Termux (Android)
```bash
pkg install python git -y
git clone https://github.com/nostraxiten/Termux-Tool
cd Termux-Tool
python termux-tool.py
```

### Kali / Debian
```bash
sudo apt install python3 -y
cd Termux-Tool
python3 termux-tool.py
```

Or simply:
```bash
bash install.sh
```

---

## Usage

Launch the main menu:
```bash
python termux-tool.py
```

Each module can also be run standalone:
```bash
python modules/osint.py
python modules/active.py
```

Navigate using numbers; `0` goes back or exits. `Ctrl+C` stops the current tool
without closing the framework.

---

## Structure

```
Termux-Tool/
├── termux-tool.py        # central launcher
├── core/
│   ├── banner.py         # color palette + ASCII art
│   ├── ui.py             # menus and output
│   └── net.py            # HTTP, custom DNS (UDP), WHOIS, sockets
├── modules/
│   ├── osint.py          # OSINT & recon
│   ├── passive.py        # passive scanning
│   ├── active.py         # active / aggressive scanning
│   ├── analysis.py       # security & network analysis
│   └── basictools.py     # basic utilities
├── data/
│   ├── subdomains.txt    # subdomains wordlist
│   └── dirs.txt          # web paths wordlist
├── install.sh
├── requirements.txt      # (empty: all stdlib)
└── README.md
```

---

## Tools Catalog

**OSINT & Reconnaissance**
1. IP / Host Info (geolocation, ISP, ASN)
2. WHOIS (recursive via IANA, socket port 43)
3. DNS Records (custom resolver: A, AAAA, MX, NS, TXT, SOA, CNAME)
4. Reverse DNS (PTR)
5. SSL/TLS Certificate (issuer, validity, SANs, version/cipher)
6. GitHub OSINT (profile + repos + languages)
7. Wayback Machine (archived URLs)
8. HTTP Fingerprint / technology detection
9. Phone Info offline (E.164, country code)
10. Username OSINT (presence on ~18 networks)

**Passive Scanning**
1. DNS Enum (records + common hostnames)
2. Subdomains via crt.sh (Certificate Transparency)
3. robots.txt & sitemap.xml
4. security.txt
5. Security headers audit (with A–F grade)
6. Cookie analysis (Secure/HttpOnly/SameSite)
7. Email harvester
8. CMS detection by paths
9. HTML meta info (generator, comments)

**Active / Aggressive Scanning**
1. Quick scan (top ~50 ports)
2. Port range scanning
3. Banner grabbing
4. Network sweep / host sweep (TCP ping)
5. Directory bruteforce
6. Subdomain bruteforce
7. HTTP methods
8. Web crawler
9. VHost scan
10. Service detection

**Security & Network Analysis**
1. Local network info (exit IP, gateway, public IP)
2. Public IP + geo
3. Password strength (entropy)
4. Password generator (secrets)
5. Hash generator (md5→blake2b)
6. Hash identifier
7. Encoder/Decoder (base64/hex/url/rot13)
8. TCP connectivity test
9. HTTP status / uptime
10. TCP latency (TCP ping)

**Basic Security Toolkit**
1. Random MAC
2. Tokens / UUID
3. File hash
4. Text entropy (Shannon)
5. Classic ciphers (Caesar/XOR/ROT13)
6. Wordlist generator
7. User-Agents generator
8. Subnet calculator (CIDR)

---

## Legal Notice

This tool is for **auditing your own systems or with explicit authorization**,
and for educational purposes. Scanning third-party infrastructure without permission may be illegal.
Your use is your responsibility.

---

*by [@nostraxiten](https://github.com/nostraxiten)*
