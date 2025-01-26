import socket
import struct
import argparse
import time
import json
import curses
from collections import defaultdict
from cryptography.fernet import Fernet

ANOMALY_THRESHOLD = 100  # Customize threshold for anomalies

blacklist = {
    'mac': set(),
    'ip': set()
}

anomalies = defaultdict(int)

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'dest_mac': format_mac(dest_mac),
        'src_mac': format_mac(src_mac),
        'protocol': socket.htons(proto),
        'payload': data[14:]
    }

def parse_ip_header(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_length = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return {
        'version': version,
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'src_ip': socket.inet_ntoa(src),
        'dst_ip': socket.inet_ntoa(target),
        'payload': data[header_length:]
    }

def parse_tcp_header(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return {
        'src_port': src_port,
        'dst_port': dest_port,
        'sequence': sequence,
        'acknowledgment': acknowledgment,
        'header_length': offset,
        'payload': data[offset:]
    }

def parse_udp_header(data):
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', data[:8])
    return {
        'src_port': src_port,
        'dst_port': dest_port,
        'length': length,
        'checksum': checksum,
        'payload': data[8:]
    }

def parse_icmp_header(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return {
        'type': icmp_type,
        'code': code,
        'checksum': checksum,
        'payload': data[4:]
    }

def parse_dns_header(data):
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack('!HHHHHH', data[:12])
    return {
        'transaction_id': transaction_id,
        'flags': flags,
        'questions': questions,
        'answer_rrs': answer_rrs,
        'authority_rrs': authority_rrs,
        'additional_rrs': additional_rrs,
        'payload': data[12:]
    }

def parse_http_payload(payload):
    try:
        http_data = payload.decode(errors='ignore')
        if http_data.startswith("GET") or http_data.startswith("POST"):
            headers = http_data.split("\r\n")
            return {'headers': headers}
    except UnicodeDecodeError:
        pass
    return None

def format_mac(raw_mac):
    return ':'.join(format(byte, '02x') for byte in raw_mac)

def save_packet(packet_data, filename="packets.json"):
    with open(filename, "a") as f:
        f.write(json.dumps(packet_data) + "\n")

def encrypt_log(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

def detect_anomalies(packet_info):
    ip_src = packet_info.get('ip', {}).get('src_ip')
    if ip_src:
        anomalies[ip_src] += 1
        if anomalies[ip_src] > ANOMALY_THRESHOLD:
            print(f"[ALERT] Potential anomaly detected from {ip_src} with {anomalies[ip_src]} packets.")

def replay_packets(filename, interface):
    print(f"[*] Replaying packets from {filename} on interface {interface}.")
    with open(filename, 'r') as f:
        packets = [json.loads(line) for line in f]
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    conn.bind((interface, 0))
    for packet in packets:
        raw_data = reconstruct_packet(packet)
        conn.send(raw_data)
    print("[*] Replay completed.")

def reconstruct_packet(packet):
    eth_header = struct.pack('!6s6sH', 
                             bytes.fromhex(packet['ethernet']['dest_mac'].replace(':', '')),
                             bytes.fromhex(packet['ethernet']['src_mac'].replace(':', '')),
                             socket.htons(packet['ethernet']['protocol']))
    return eth_header  # Simplified for demo, append IP/TCP/UDP data as needed

def start_sniffer(interface=None, filters=None):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if interface:
        conn.bind((interface, 0))

    print(f"[*] Sniffing on {interface or 'all interfaces'}... Press Ctrl+C to stop.")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            eth = parse_ethernet_header(raw_data)

            if eth['src_mac'] in blacklist['mac'] or eth['dest_mac'] in blacklist['mac']:
                continue

            packet_info = {
                'timestamp': time.time(),
                'ethernet': {
                    'src_mac': eth['src_mac'],
                    'dest_mac': eth['dest_mac'],
                    'protocol': eth['protocol']
                }
            }

            if eth['protocol'] == 8:  # IPv4
                ip = parse_ip_header(eth['payload'])

                if ip['src_ip'] in blacklist['ip'] or ip['dst_ip'] in blacklist['ip']:
                    continue

                packet_info['ip'] = {
                    'src_ip': ip['src_ip'],
                    'dst_ip': ip['dst_ip'],
                    'protocol': ip['protocol']
                }

                detect_anomalies(packet_info)

                if ip['protocol'] == 6:  # TCP
                    tcp = parse_tcp_header(ip['payload'])
                    packet_info['tcp'] = {
                        'src_port': tcp['src_port'],
                        'dst_port': tcp['dst_port']
                    }
                    http = parse_http_payload(tcp['payload'])
                    if http:
                        packet_info['http'] = http

                elif ip['protocol'] == 17:  # UDP
                    udp = parse_udp_header(ip['payload'])
                    packet_info['udp'] = {
                        'src_port': udp['src_port'],
                        'dst_port': udp['dst_port']
                    }

                elif ip['protocol'] == 1:  # ICMP
                    icmp = parse_icmp_header(ip['payload'])
                    packet_info['icmp'] = icmp

            if not filters or packet_info.get('ip', {}).get('protocol') in filters:
                print(f"Captured Packet: {packet_info}")
                save_packet(packet_info)

    except KeyboardInterrupt:
        print("\n[*] Stopping the sniffer.")
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer with Filters, Replay, and Anomaly Detection")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all interfaces)")
    parser.add_argument("-f", "--filter", help="Filter by protocol (tcp, udp, all)", default="all")
    parser.add_argument("-r", "--replay", help="Replay packets from a file")
    parser.add_argument("-e", "--encrypt", help="Encrypt saved logs with a key")
    args = parser.parse_args()

    if args.replay:
        if not args.interface:
            print("[ERROR] Interface is required for packet replay.")
            return
        replay_packets(args.replay, args.interface)
        return

    if args.encrypt:
        key = Fernet.generate_key()
        encrypt_log("packets.json", "encrypted_packets.pcap", key)
        print(f"[*] Logs encrypted. Key: {key.decode()}")
        return

    filters = None
    if args.filter.lower() == "tcp":
        filters = [6]
    elif args.filter.lower() == "udp":
        filters = [17]

    start_sniffer(interface=args.interface, filters=filters)

if __name__ == "__main__":
    main()