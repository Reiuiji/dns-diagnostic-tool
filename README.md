# 🌐 Global DNS Diagnostic & Propagation Tool

A lightweight, self-contained DNS propagation testing and diagnostic suite built entirely in **pure Python**. This tool features a modern, responsive web dashboard and several command-line utility scripts with **zero external dependencies** (no `pip` installs required).

---

## ✨ Features

- **Sleek Web Dashboard**: A premium, glassmorphic dark-mode interface showing real-time query status.
- **Global & European Resolvers**: Resolves domains concurrently across 18 public and independent/ISP DNS resolvers (including Google, Cloudflare, Quad9, OpenDNS, and independent privacy/ISP resolvers in Germany, France, the UK, Denmark, and more).
- **Custom DNS Target**: Query any custom DNS server IP address directly.
- **Detailed Modal Inspector**: Click any resolver card to view raw DNS packet details, including Answer, Authority, and Additional record sections.
- **Zero-Dependency Core**: Built using Python's standard `socket`, `struct`, and `http.server` modules.

---

## 🚀 Quick Start

### 1. Launch the Web Interface

Start the local server (defaults to port `8000` if not specified):
```bash
python3 server.py [port]
```

**Example (custom port):**
```bash
python3 server.py 8080
```
Then, open your web browser and navigate to: **`http://localhost:8080`**

---

## 🛠️ CLI Utilities

The repository contains standalone command-line scripts for direct debugging:

### `query_dns.py` (CLI DNS Client)
Query a domain's records against all configured public/European servers, or specify a target DNS server directly:
```bash
python3 query_dns.py <domain> [record_type] [target_dns_ip]
```
- **Supported Record Types**: `A`, `AAAA`, `NS`, `MX`, `TXT`, `CNAME`, `SOA`
- **Example**:
  ```bash
  python3 query_dns.py vh4bh.equestria.horse AAAA 8.8.8.8
  ```

### `query_ecs.py` (EDNS Client Subnet Tester)
Simulate DNS lookups from different geographical subnets (US, UK, Germany, France, Japan, etc.) directly on the authoritative nameserver to diagnose GeoDNS routing, parental filtering, or regional blocks:
```bash
python3 query_ecs.py
```

### `check_tld_ns.py` (TLD Delegation Auditor)
Query the root registry nameservers directly to audit delegation consistency and detect lame delegation or caching mismatches:
```bash
python3 check_tld_ns.py
```

---

## 📂 Project Structure

```
├── README.md               # Project documentation
├── .gitignore              # Git ignore file
├── index.html              # Dashboard frontend (HTML/CSS/JS)
├── server.py               # HTTP web server & JSON API handler
├── query_dns.py            # Standalone CLI DNS client
├── query_ecs.py            # EDNS Client Subnet diagnostic script
└── check_tld_ns.py         # Registry delegation verification script
```
