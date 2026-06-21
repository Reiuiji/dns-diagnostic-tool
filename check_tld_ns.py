import socket
import struct
import sys

def build_query(domain, qtype=2): # default qtype=2 (NS)
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    question = b''
    for part in domain.split('.'):
        if not part:
            continue
        question += bytes([len(part)]) + part.encode('utf-8')
    question += b'\x00'
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
        return None
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    rcode = flags & 0x000F
    offset = 12
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
            if rtype == 2: # NS
                ns_name, _ = parse_name(data, offset)
                rdata_str = ns_name
            else:
                rdata_str = rdata_raw.hex()
            records.append(rdata_str)
            offset += rdlen
        return records

    # TLD servers usually return NS records in the Authority section for referrals
    answers = parse_records(ancount)
    authorities = parse_records(nscount)
    return rcode, answers, authorities

def query_server(server_ip, domain):
    query_packet = build_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(query_packet, (server_ip, 53))
        response, _ = sock.recvfrom(512)
        return parse_response(response)
    except Exception as e:
        return None

def main():
    tld_servers = ["a.nic.horse", "b.nic.horse", "c.nic.horse", "x.nic.horse", "y.nic.horse", "z.nic.horse"]
    domain = "equestria.horse"
    
    print(f"Checking TLD nameserver delegation consistency for {domain}...")
    print("=" * 60)
    
    for tld in tld_servers:
        try:
            # Resolve TLD server IP
            ips = socket.getaddrinfo(tld, 53, socket.AF_INET, socket.SOCK_DGRAM)
            ip = ips[0][4][0]
        except Exception as e:
            print(f"{tld}: Failed to resolve IP ({e})")
            continue
            
        res = query_server(ip, domain)
        if res is None:
            print(f"{tld} ({ip}): Query Timeout or Error")
        else:
            rcode, answers, authorities = res
            # For referrals, the NS records are in authorities
            ns_list = answers if answers else authorities
            ns_list = sorted([ns.lower().rstrip('.') for ns in ns_list])
            print(f"{tld} ({ip}): RCODE={rcode}, NS={ns_list}")

if __name__ == "__main__":
    main()
