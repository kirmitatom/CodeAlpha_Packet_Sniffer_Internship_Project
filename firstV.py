import socket
import struct
import argparse
import time
import json
from collections import defaultdict
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table

ANOMALY_THRESHOLD = 100  # Customize threshold for anomalies

blacklist = {
    'mac': set(),
    'ip': set()
}

anomalies = defaultdict(int)
console = Console()

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

def resolve_domain(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return "Unknown Host"

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

def display_packet(packet_info):
    table = Table(title="Captured Packet", show_lines=True)

    if "ethernet" in packet_info:
        eth = packet_info["ethernet"]
        table.add_column("Field", style="cyan", justify="right")
        table.add_column("Value", style="green")
        table.add_row("Timestamp", str(packet_info.get("timestamp", "")))
        table.add_row("Source MAC", eth.get("src_mac", ""))
        table.add_row("Destination MAC", eth.get("dest_mac", ""))
        table.add_row("Ethernet Protocol", str(eth.get("protocol", "")))

    if "ip" in packet_info:
        ip = packet_info["ip"]
        table.add_row("Source IP", ip.get("src_ip", ""))
        table.add_row("Destination IP", ip.get("dst_ip", ""))
        table.add_row("Destination Domain", ip.get("dst_domain", ""))
        table.add_row("IP Protocol", str(ip.get("protocol", "")))

    if "tcp" in packet_info:
        tcp = packet_info["tcp"]
        table.add_row("Source Port", str(tcp.get("src_port", "")))
        table.add_row("Destination Port", str(tcp.get("dst_port", "")))

    if "udp" in packet_info:
        udp = packet_info["udp"]
        table.add_row("Source Port", str(udp.get("src_port", "")))
        table.add_row("Destination Port", str(udp.get("dst_port", "")))

    if "icmp" in packet_info:
        icmp = packet_info["icmp"]
        table.add_row("ICMP Type", str(icmp.get("type", "")))
        table.add_row("ICMP Code", str(icmp.get("code", "")))

    console.print(table)

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

                domain_name = resolve_domain(ip['dst_ip'])

                packet_info['ip'] = {
                    'src_ip': ip['src_ip'],
                    'dst_ip': ip['dst_ip'],
                    'dst_domain': domain_name,
                    'protocol': ip['protocol']
                }

                detect_anomalies(packet_info)

                if ip['protocol'] == 6:  # TCP
                    tcp = parse_tcp_header(ip['payload'])
                    packet_info['tcp'] = {
                        'src_port': tcp['src_port'],
                        'dst_port': tcp['dst_port']
                    }

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
                display_packet(packet_info)
                save_packet(packet_info)

    except KeyboardInterrupt:
        print("\n[*] Stopping the sniffer.")
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer with Domain Resolution and Anomaly Detection")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all interfaces)")
    parser.add_argument("-f", "--filter", help="Filter by protocol (tcp, udp, all)", default="all")
    args = parser.parse_args()

    filters = None
    if args.filter.lower() == "tcp":
        filters = [6]
    elif args.filter.lower() == "udp":
        filters = [17]

    start_sniffer(interface=args.interface, filters=filters)

if __name__ == "__main__":
    main()