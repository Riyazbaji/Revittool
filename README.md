# Revittool – Java-based Domain Reconnaissance Toolkit

Revittool is a **Java command-line tool** that performs **real-time reconnaissance** on a domain:

- DNS lookups (forward & reverse)
- Full DNS enumeration (A, AAAA, MX, NS, TXT, CNAME)
- WHOIS ownership summary (no external API)
- TLS/SSL certificate inspection
- Email security checks (MX, SPF, DMARC)
- DNSSEC status (via Google Public DNS)
- Basic port reachability (80, 443, 21, 22)
- ATCE – Attack Surface Temporal Correlation Engine  
  (subdomains from Certificate Transparency logs + risk tagging + snapshots)

Originally, Revittool started as a simple forward/reverse DNS tool.  
It has now evolved into a **full attack surface mapper** for cybersecurity learning and analysis.

---

## 🚀 Features

### 1. Basic DNS – Forward & Reverse

- Resolve domain → IP addresses (A/AAAA)
- Reverse DNS (PTR) for each IP
- Helpful to see which hostnames and providers are behind an IP.

### 2. DNS Enumeration

Queries multiple DNS record types:

- **A / AAAA** – IPv4 / IPv6 addresses  
- **MX** – Mail exchangers (who handles email)  
- **NS** – Name servers (who controls DNS)  
- **TXT** – Security-related TXT (SPF, DMARC, verification)  
- **CNAME** – Aliases

### 3. WHOIS Summary (No API)

Connects directly to the **WHOIS server** (port 43) and extracts:

- Domain Name  
- Registrar  
- Created On  
- Updated On  
- Expires On  
- Name Servers  

No paid WHOIS API is used – this is **raw protocol-level WHOIS parsing**.

### 4. TLS / SSL Certificate Analysis

Connects to the domain on port 443 and shows:

- Certificate Subject (CN)  
- SANs (Subject Alternative Names)  
- Expiry date & remaining days  

Useful to check if HTTPS is correctly configured and if the cert is expiring soon.

### 5. Email Security – MX / SPF / DMARC

- Lists **MX** records → which provider hosts mail (e.g., Google Workspace, Microsoft 365)  
- Checks if **SPF** is present (TXT record with `v=spf1`)  
- Checks if **DMARC** is present (`_dmarc.domain` TXT with `v=DMARC1`)

> If SPF/DMARC are missing, the domain is **more vulnerable to email spoofing / phishing.**

### 6. DNSSEC Status

Queries Google Public DNS over HTTPS to check if the domain has **DS records**:

- `DNSSEC: ENABLED` → zone signed, better protection against DNS tampering  
- `DNSSEC: NOT ENABLED` → no DS records found  

### 7. Port Reachability

For each resolved IP, checks:

- HTTP (port 80)  
- HTTPS (port 443)  
- SSH (port 22)  
- FTP (port 21)

Outputs whether each port is:

- `REACHABLE`  
- `closed/unreachable`

This gives a quick view of **publicly exposed services**.

### 8. ATCE – Attack Surface Temporal Correlation Engine

ATCE uses **Certificate Transparency (CT) logs** via `crt.sh` to:

- Find subdomains for the target domain
- Classify each subdomain into:
  - **HIGH** – admin/login/portal/secure-style subdomains  
  - **MEDIUM** – dev/test/staging/beta/demo  
  - **LOW** – main/infra/standard assets  

For selected subdomains, it also:

- Takes an **HTTP snapshot** and saves HTML to `snapshots/`  
- Tries to fetch `/favicon.ico` and computes an **MD5 hash**  
  (can be used to fingerprint technologies / providers)

If `crt.sh` is slow or unreachable, ATCE prints a **clean message** instead of a stack trace.

---

## 🧪 Original (Basic) Version – Forward / Reverse / Batch

The first version of Revittool supported:

- Forward DNS lookup for a domain:  
  `java Revittool -forward example.com`
- Reverse DNS lookup for an IP:  
  `java Revittool -reverse 8.8.8.8`
- Batch mode (TXT input → CSV output):  
  `java Revittool -batch input.txt output.csv`

The new full-scan engine (`RevittoolFull`) is an **upgrade**, but you can still keep/use the basic version as a lightweight tool.

---

## ⚙️ Requirements

- Java **17+** (or compatible JDK)
- Internet connection (for DNS, WHOIS, TLS, CT, DNSSEC)
- Windows, Linux, or macOS terminal

---

## 🔧 Build & Run

### 1. Compile

```bash
javac RevittoolFull.java
