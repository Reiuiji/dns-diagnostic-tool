import socket
import struct
import sys
import time

def build_query_ecs(domain, qtype=1, subnet_ip="0.0.0.0", prefix_len=24):
    # Header: 1 question, 1 additional record (the OPT RR)
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 1)
    
    # Question
    question = b''
    for part in domain.split('.'):
        if not part:
            continue
        question += bytes([len(part)]) + part.encode('utf-8')
    question += b'\x00'
    question += struct.pack('!HH', qtype, 1)
    
    # ECS Option Data
    parts = [int(x) for x in subnet_ip.split('.')]
    addr_bytes = bytes(parts[:(prefix_len + 7) // 8])
    
    # Option: Family=1 (IPv4), SourcePrefixLen, ScopePrefixLen=0, Address
    ecs_option_data = struct.pack('!HBB', 1, prefix_len, 0) + addr_bytes
    # Option Code = 8 (ECS), Length
    ecs_option = struct.pack('!HH', 8, len(ecs_option_data)) + ecs_option_data
    
    # OPT RR: Name=0, Type=OPT (41), PayloadSize=4096, ExtRCODE=0, Version=0, Flags=0, DataLen
    opt_rr = struct.pack('!BHHHIH', 0, 41, 4096, 0, 0, len(ecs_option)) + ecs_option
    
    return header + question + opt_rr

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
    # Skip questions
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4
        
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
            if rtype == 1 and len(rdata_raw) == 4: # A
                rdata_str = socket.inet_ntop(socket.AF_INET, rdata_raw)
            elif rtype == 28 and len(rdata_raw) == 16: # AAAA
                rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_raw)
            else:
                rdata_str = rdata_raw.hex()
                
            records.append({
                "name": name,
                "type": rtype,
                "data": rdata_str
            })
            offset += rdlen
        return records

    answers = parse_records(ancount)
    return {"rcode": rcode, "rcode_name": rcode_name, "answers": answers}

def query_with_ecs(server_ip, domain, subnet_ip, prefix_len=24):
    packet = build_query_ecs(domain, 1, subnet_ip, prefix_len)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(packet, (server_ip, 53))
        response, _ = sock.recvfrom(1024)
        return parse_response(response)
    except Exception as e:
        return {"error": str(e)}

def main():
    # Authoritative Cloudflare servers for equestria.horse
    auth_servers = ["172.64.34.181", "108.162.194.181"]
    domain = "vh4bh.equestria.horse"
    
    # Subnets from different regions
    subnets = {
        "Default (No ECS)": ("0.0.0.0", 0),
        "US East (Virginia)": ("198.51.100.0", 24),
        "UK (London)": ("188.39.0.0", 16),
        "Germany (Frankfurt)": ("93.184.216.0", 24),
        "France (Paris)": ("80.67.169.0", 24),
        "Lithuania (Vilnius)": ("88.216.0.0", 16),
        "Netherlands (Amsterdam)": ("194.109.6.0", 24),
        "Japan (Tokyo)": ("210.140.0.0", 16),
        "Australia (Sydney)": ("1.120.0.0", 16)
    }
    
    print(f"=== Authoritative DNS ECS Diagnostic for {domain} ===")
    print("This test queries the Cloudflare authoritative nameserver directly using EDNS Client Subnet (ECS) options.")
    print("=" * 70)
    
    auth_ip = auth_servers[0]
    print(f"Authoritative Server: {auth_ip} (millie.ns.cloudflare.com)\n")
    
    for name, (subnet, prefix) in subnets.items():
        res = query_with_ecs(auth_ip, domain, subnet, prefix)
        if "error" in res:
            print(f"{name:<25} (Subnet: {subnet}/{prefix:<2}) -> ERROR: {res['error']}")
        else:
            answers_str = ", ".join([r["data"] for r in res["answers"]]) if res["answers"] else "No Records"
            print(f"{name:<25} (Subnet: {subnet}/{prefix:<2}) -> RCODE: {res['rcode_name']:<8} | Answers: {answers_str}")

if __name__ == "__main__":
    main()
