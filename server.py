import http.server
import socketserver
import urllib.parse
import json
import socket
import struct
import time
import os
import sys
import argparse

PORT = 8000

# DNS Query building and parsing functions
def build_query(domain, qtype=1):
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
            try:
                if rtype == 1: # A
                    rdata_str = socket.inet_ntop(socket.AF_INET, rdata_raw) if len(rdata_raw) == 4 else rdata_raw.hex()
                elif rtype == 28: # AAAA
                    rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_raw) if len(rdata_raw) == 16 else rdata_raw.hex()
                elif rtype in (2, 5): # NS, CNAME
                    ns_name, _ = parse_name(data, offset)
                    rdata_str = ns_name
                elif rtype == 15: # MX
                    pref = struct.unpack('!H', rdata_raw[:2])[0]
                    mx_name, _ = parse_name(data, offset + 2)
                    rdata_str = f"{pref} {mx_name}"
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
        response, _ = sock.recvfrom(1024)
        elapsed = time.time() - start_time
        parsed = parse_response(response)
        parsed["time_ms"] = round(elapsed * 1000, 2)
        parsed["server"] = server_ip
        return parsed
    except socket.timeout:
        return {"server": server_ip, "error": "Timeout", "time_ms": round((time.time() - start_time) * 1000, 2)}
    except Exception as e:
        return {"server": server_ip, "error": str(e), "time_ms": round((time.time() - start_time) * 1000, 2)}

class DNSDiagnosticHTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        
        # API Route: /api/query
        if parsed_url.path == "/api/query":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            domain = query_params.get("domain", [""])[0]
            qtype_str = query_params.get("type", ["A"])[0]
            server_ip = query_params.get("server", ["8.8.8.8"])[0]
            
            qtype_map = {
                "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "ANY": 255
            }
            try:
                qtype = int(qtype_str)
            except ValueError:
                qtype = qtype_map.get(qtype_str.upper(), 1)
                
            if not domain:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing 'domain' parameter"}).encode())
                return
                
            # Perform query
            result = query_server(server_ip, domain, qtype)
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            return
            
        # Serve index.html on root
        elif parsed_url.path == "/" or parsed_url.path == "/index.html":
            try:
                with open("index.html", "r", encoding="utf-8") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Error loading index.html: {e}".encode())
            return
            
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

def main():
    parser = argparse.ArgumentParser(description="DNS Diagnostic Server")
    parser.add_argument("port", type=int, nargs="?", default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()
    port = args.port

    # Allow address reuse to prevent "address already in use" errors on restarts
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", port), DNSDiagnosticHTTPHandler) as httpd:
        print(f"DNS Diagnostic Server running at: http://localhost:{port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")

if __name__ == "__main__":
    main()
