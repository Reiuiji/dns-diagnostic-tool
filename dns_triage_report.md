# DNS Triage Report: vh4bh.equestria.horse

This report documents the global resolution diagnostics for the domain `vh4bh.equestria.horse`, with a focus on resolving issues reported in European regions.

---

## 1. Diagnostic Summary

- **Resolution Status**: The domain resolves successfully to **`88.216.208.106`** (Cherry Servers, Lithuania) on all standard public and ISP-provided DNS servers globally.
- **Authoritative DNS**: Hosted on Cloudflare (`nile.ns.cloudflare.com` and `millie.ns.cloudflare.com`).
- **DNSSEC**: Disabled. There is no DS record configured at the `.horse` registry level, meaning DNSSEC validation is not enforced and cannot cause validation failures (e.g., `SERVFAIL`).
- **Core Triage Finding**: 
  - **No IPv6 (AAAA) Record**: The subdomain `vh4bh.equestria.horse` has no IPv6 record configured. In Europe, many mobile and broadband ISPs run on IPv6-only or DS-Lite configurations, relying on DNS64/NAT64 translation to reach IPv4-only hosts. If an ISP's DNS64 gateway fails or misbehaves, the lookup fails.

---

## 2. Authoritative Delegation Consistency

To check for any regional registry mismatches, we queried all 6 authoritative `.horse` TLD nameservers (managed by GoDaddy Registry) directly for the delegation of `equestria.horse`:

| TLD Nameserver | IP Address | Status | Delegated Nameservers |
| :--- | :--- | :--- | :--- |
| `a.nic.horse` | `37.209.192.10` | `NOERROR` | `nile.ns.cloudflare.com`, `millie.ns.cloudflare.com` |
| `b.nic.horse` | `37.209.194.10` | `NOERROR` | `nile.ns.cloudflare.com`, `millie.ns.cloudflare.com` |
| `c.nic.horse` | `37.209.196.10` | `NOERROR` | `nile.ns.cloudflare.com`, `millie.ns.cloudflare.com` |
| `x.nic.horse` | `156.154.172.82` | `NOERROR` | `nile.ns.cloudflare.com`, `millie.ns.cloudflare.com` |
| `y.nic.horse` | `156.154.173.82` | `NOERROR` | `nile.ns.cloudflare.com`, `millie.ns.cloudflare.com` |
| `z.nic.horse` | `156.154.174.82` | `NOERROR` | `nile.ns.cloudflare.com`, `millie.ns.cloudflare.com` |

*Delegation is fully consistent globally. There are no lame delegation or zone synchronization issues at the TLD level.*

---

## 3. Global & European DNS Resolver Status

We verified the resolution of the `A` record for `vh4bh.equestria.horse` across major public DNS networks and country-specific ISP DNS servers throughout Europe:

| DNS Provider / ISP Region | DNS Server IP | Result | Resolved IP Address |
| :--- | :--- | :--- | :--- |
| **Google Public DNS** | `8.8.8.8` / `8.8.4.4` | `NOERROR` | `88.216.208.106` |
| **Cloudflare Public DNS** | `1.1.1.1` / `1.0.0.1` | `NOERROR` | `88.216.208.106` |
| **Quad9 DNS** | `9.9.9.9` | `NOERROR` | `88.216.208.106` |
| **OpenDNS** | `208.67.222.222` | `NOERROR` | `88.216.208.106` |
| **Yandex DNS (Eastern Europe)** | `77.88.8.8` | `NOERROR` | `88.216.208.106` |
| **Censurfridns (Denmark)** | `91.239.100.100` | `NOERROR` | `88.216.208.106` |
| **Digitalcourage (Germany)** | `46.38.225.230` | `NOERROR` | `88.216.208.106` |
| **FDN (France)** | `80.67.169.12` | `NOERROR` | `88.216.208.106` |
| **XS4ALL (Netherlands)** | `194.109.6.66` | `NOERROR` | `88.216.208.106` |
| **CZ.NIC (Czech Republic)** | `217.31.204.130` | `NOERROR` | `88.216.208.106` |
| **NASK (Poland)** | `195.187.244.194` | `NOERROR` | `88.216.208.106` |
| **GreenNet (United Kingdom)** | `81.187.96.109` | `NOERROR` | `88.216.208.106` |
| **Sunet (Sweden)** | `192.36.125.150` | `NOERROR` | `88.216.208.106` |
| **Funkfeuer (Austria)** | `193.238.164.8` | `NOERROR` | `88.216.208.106` |
| **TIM (Italy)** | `85.37.17.15` | `NOERROR` | `88.216.208.106` |
| **Telefonica (Spain)** | `80.58.61.250` | `NOERROR` | `88.216.208.106` |

---

## 4. EDNS Client Subnet (ECS) Routing Consistency

To check if Cloudflare's servers return different IPs or fail depending on where the DNS queries originate, we queried the authoritative server `172.64.34.181` directly using simulated subnets from different regions:

```
Subnet: Default (No ECS)          -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: US East (Virginia)        -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: UK (London)               -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: Germany (Frankfurt)       -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: France (Paris)            -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: Lithuania (Vilnius)       -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: Netherlands (Amsterdam)   -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: Japan (Tokyo)             -> RCODE: NOERROR  | Answers: 88.216.208.106
Subnet: Australia (Sydney)        -> RCODE: NOERROR  | Answers: 88.216.208.106
```

---

## 5. Potential Causes of Regional Resolve Errors

For European users experiencing issues, these are the two primary technical causes:

1. **IPv6-Only and DS-Lite Compatibility (Missing AAAA)**:
   - Many major European mobile networks (such as EE, Vodafone, Deutsche Telekom) and broadband providers prioritize IPv6 and operate IPv6-only links with NAT64/DNS64 translation mechanisms to route traffic to IPv4-only legacy hosts.
   - If an ISP's local DNS64 translation proxy experiences congestion or failures, it will fail to synthesize an IPv6 address for `vh4bh.equestria.horse` (which only has an IPv4 A record).
   - **Recommendation**: Add a corresponding native IPv6 (`AAAA`) record for the subdomain in the Cloudflare control panel. (Note: The apex domain `equestria.horse` already has AAAA records pointing to GitHub Pages, but the subdomain does not).
2. **ISP Parental and Content Filters**:
   - Several UK and European ISPs default-enable parental/clean-broadband filters. These automated systems sometimes block less common TLDs (like `.horse`) or obscure subdomains.
   - **Recommendation**: Affected users should test access via a mobile hotspot, a VPN, or temporarily disable ISP-level filtering profiles.
