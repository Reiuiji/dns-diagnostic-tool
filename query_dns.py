import socket
import struct
import time
import sys

def build_query(domain, qtype=1): # default qtype=1 (A)
    # Header: Transaction ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
    # Transaction ID: 0x1234
    # Flags: 0x0100 (Standard Query, Recursion Desired)
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    
    # Question
    question = b''
    for part in domain.split('.'):
        if not part:
            continue
        question += bytes([len(part)]) + part.encode('utf-8')
    question += b'\x00' # end of string
    
    # QTYPE, QCLASS (IN = 1)
    question += struct.pack('!HH', qtype, 1)
    return header + question

def parse_name(data, offset):
    parts = []
    initial_offset = offset
    jumped = False
    data_len = len(data)
    
    while offset < data_len:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Compression pointer
            if offset + 1 >= data_len:
                offset += 1
                break
            pointer = struct.unpack('!H', data[offset:offset+2])[0]
            pointer &= 0x3FFF
            if not jumped:
                initial_offset = offset + 2
                jumped = True
            offset = pointer
        else:
            offset += 1
            if offset + length > data_len:
                break
            parts.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
            offset += length
            
    return '.'.join(parts), (initial_offset if jumped else offset)

def parse_response(data):
    if len(data) < 12:
        return {"error": "Packet too short"}
        
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    rcode = flags & 0x000F
    
    rcode_names = {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
        4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
        8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"
    }
    rcode_name = rcode_names.get(rcode, f"UNKNOWN({rcode})")
    
    offset = 12
    # Parse questions to advance offset
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4 # skip type and class
        
    def parse_records(count):
        nonlocal offset
        records = []
        for _ in range(count):
            if offset >= len(data):
                break
            name, offset = parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset+10])
            offset += 10
            rdata_raw = data[offset:offset+rdlen]
            
            rdata_str = ""
            try:
                if rtype == 1: # A
                    rdata_str = socket.inet_ntop(socket.AF_INET, rdata_raw) if len(rdata_raw) == 4 else rdata_raw.hex()
                elif rtype == 28: # AAAA
                    rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_raw) if len(rdata_raw) == 16 else rdata_raw.hex()
                elif rtype in (2, 5): # NS, CNAME
                    ns_name, _ = parse_name(data, offset)
                    rdata_str = ns_name
                elif rtype == 16: # TXT
                    txt_offset = offset
                    txt_parts = []
                    while txt_offset < offset + rdlen:
                        txt_len = data[txt_offset]
                        txt_parts.append(data[txt_offset+1:txt_offset+1+txt_len].decode('utf-8', errors='ignore'))
                        txt_offset += 1 + txt_len
                    rdata_str = "".join(txt_parts)
                elif rtype == 6: # SOA
                    soa_offset = offset
                    mname, soa_offset = parse_name(data, soa_offset)
                    rname, soa_offset = parse_name(data, soa_offset)
                    serial, refresh, retry, expire, minimum = struct.unpack('!IIIII', data[soa_offset:soa_offset+20])
                    rdata_str = f"MNAME: {mname}, RNAME: {rname}, Serial: {serial}, Refresh: {refresh}, Retry: {retry}, Expire: {expire}, MinTTL: {minimum}"
                elif rtype == 43: # DS
                    if len(rdata_raw) >= 4:
                        key_tag, algo, digest_type = struct.unpack('!HBB', rdata_raw[:4])
                        digest = rdata_raw[4:].hex()
                        rdata_str = f"KeyTag: {key_tag}, Algo: {algo}, DigestType: {digest_type}, Digest: {digest}"
                    else:
                        rdata_str = rdata_raw.hex()
                elif rtype == 48: # DNSKEY
                    if len(rdata_raw) >= 4:
                        flags, protocol, algo = struct.unpack('!HBB', rdata_raw[:4])
                        pubkey = rdata_raw[4:].hex()
                        rdata_str = f"Flags: {flags}, Protocol: {protocol}, Algo: {algo}, PublicKey: {pubkey}"
                    else:
                        rdata_str = rdata_raw.hex()
                else:
                    rdata_str = rdata_raw.hex()
            except Exception as e:
                rdata_str = f"Parsing Error ({str(e)}) - Hex: {rdata_raw.hex()}"
                
            records.append({
                "name": name,
                "type": rtype,
                "class": rclass,
                "ttl": ttl,
                "data": rdata_str
            })
            offset += rdlen
        return records

    answers = parse_records(ancount)
    authorities = parse_records(nscount)
    additionals = parse_records(arcount)
    
    return {
        "tx_id": tx_id,
        "flags": flags,
        "rcode": rcode,
        "rcode_name": rcode_name,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals
    }

def query_server(server_ip, domain, qtype=1, timeout=3.0):
    query_packet = build_query(domain, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    start_time = time.time()
    try:
        sock.sendto(query_packet, (server_ip, 53))
        response, _ = sock.recvfrom(512)
        elapsed = time.time() - start_time
        parsed = parse_response(response)
        parsed["time_ms"] = round(elapsed * 1000, 2)
        parsed["server"] = server_ip
        return parsed
    except socket.timeout:
        return {"server": server_ip, "error": "Timeout", "time_ms": round((time.time() - start_time) * 1000, 2)}
    except Exception as e:
        return {"server": server_ip, "error": str(e), "time_ms": round((time.time() - start_time) * 1000, 2)}

# List of public DNS servers
PUBLIC_DNS = {
    "Google (8.8.8.8)": "8.8.8.8",
    "Google (8.8.4.4)": "8.8.4.4",
    "Cloudflare (1.1.1.1)": "1.1.1.1",
    "Cloudflare (1.0.0.1)": "1.0.0.1",
    "Quad9 (9.9.9.9)": "9.9.9.9",
    "Quad9 (149.112.112.112)": "149.112.112.112",
    "OpenDNS (208.67.222.222)": "208.67.222.222",
    "OpenDNS (208.67.220.220)": "208.67.220.220",
    "AdGuard (94.140.14.14)": "94.140.14.14",
    "Alternate DNS (76.76.19.19)": "76.76.19.19",
    "Lumen/Level3 (4.2.2.1)": "4.2.2.1",
    "DNS.WATCH (84.200.69.80)": "84.200.69.80",
    "Yandex (77.88.8.8)": "77.88.8.8",
    "ControlD (76.76.2.0)": "76.76.2.0"
}

EUROPE_DNS = {
    "Censurfridns (Denmark - 91.239.100.100)": "91.239.100.100",
    "UncensoredDNS (Denmark - 89.233.43.71)": "89.233.43.71",
    "Digitalcourage (Germany - 46.38.225.230)": "46.38.225.230",
    "FDN (France - 80.67.169.12)": "80.67.169.12",
    "XS4ALL (Netherlands - 194.109.6.66)": "194.109.6.66",
    "CZ.NIC (Czech Republic - 217.31.204.130)": "217.31.204.130",
    "NASK (Poland - 195.187.244.194)": "195.187.244.194",
    "GreenNet (UK - 81.187.96.109)": "81.187.96.109",
    "Sunet (Sweden - 192.36.125.150)": "192.36.125.150",
    "Funkfeuer (Austria - 193.238.164.8)": "193.238.164.8",
    "TIM (Italy - 85.37.17.15)": "85.37.17.15",
    "Telefonica (Spain - 80.58.61.250)": "80.58.61.250"
}

def get_system_resolvers():
    resolvers = []
    try:
        with open("/etc/resolv.conf", "r") as f:
            for line in f:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        resolvers.append(parts[1])
    except Exception as e:
        print(f"Error reading /etc/resolv.conf: {e}")
    return resolvers

def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "vh4bh.equestria.horse"
    qtype_str = sys.argv[2] if len(sys.argv) > 2 else "A"
    
    qtype_map = {
        "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "TXT": 16, "AAAA": 28, "ANY": 255,
        "DS": 43, "DNSKEY": 48, "RRSIG": 46, "NSEC": 47, "NSEC3": 50
    }
    try:
        qtype = int(qtype_str)
    except ValueError:
        qtype = qtype_map.get(qtype_str.upper(), 1)
    
    print(f"=== DNS Query Diagnostic ===")
    print(f"Target Domain: {domain}")
    print(f"Query Type:    {qtype_str} (Value: {qtype})")
    print(f"Timestamp:     {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 40)
    
    # Add system resolvers
    specific_server = sys.argv[3] if len(sys.argv) > 3 else None
    
    resolvers = {}
    if specific_server:
        resolvers[f"Target Server ({specific_server})"] = specific_server
    else:
        resolvers["System Resolver"] = None
        sys_ips = get_system_resolvers()
        for idx, ip in enumerate(sys_ips):
            resolvers[f"System Conf NS ({ip})"] = ip
            
        for name, ip in PUBLIC_DNS.items():
            resolvers[name] = ip

        for name, ip in EUROPE_DNS.items():
            resolvers[name] = ip
        
    for name, ip in resolvers.items():
        print(f"\nQuerying via: {name}")
        if ip is None:
            # Standard socket resolution (only A or AAAA supported easily, default is A)
            start_time = time.time()
            try:
                ips = socket.getaddrinfo(domain, None)
                elapsed = round((time.time() - start_time) * 1000, 2)
                resolved_ips = list(set([x[4][0] for x in ips]))
                print(f"  Result:  SUCCESS")
                print(f"  Time:    {elapsed} ms")
                print(f"  IPs:     {resolved_ips}")
            except Exception as e:
                elapsed = round((time.time() - start_time) * 1000, 2)
                print(f"  Result:  ERROR ({e})")
                print(f"  Time:    {elapsed} ms")
            continue
            
        res = query_server(ip, domain, qtype)
        if "error" in res:
            print(f"  Result:  ERROR ({res['error']})")
            print(f"  Time:    {res['time_ms']} ms")
        else:
            print(f"  Result:  {res['rcode_name']} (RCODE {res['rcode']})")
            print(f"  Time:    {res['time_ms']} ms")
            if res["answers"]:
                print("  Answers:")
                for r in res["answers"]:
                    print(f"    - Type {r['type']} | TTL {r['ttl']} | {r['data']}")
            if res["authorities"]:
                print("  Authorities:")
                for r in res["authorities"]:
                    print(f"    - Type {r['type']} | TTL {r['ttl']} | {r['data']}")
            if res["additionals"]:
                print("  Additionals:")
                for r in res["additionals"]:
                    print(f"    - Type {r['type']} | TTL {r['ttl']} | {r['data']}")

if __name__ == "__main__":
    main()
