import socket
import struct
import argparse
import json
from collections import defaultdict
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table

ANOMALY_THRESHOLD = 100
DISPLAYED_DOMAINS = set()

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
    header_length = (version_header_len & 15) * 4
    ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])
    return {
        'header_length': header_length,
        'ttl': ttl,
        'protocol': proto,
        'src_ip': socket.inet_ntoa(src),
        'dst_ip': socket.inet_ntoa(dst),
        'payload': data[header_length:]
    }


def parse_tcp_header(data):
    src_port, dst_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'sequence': sequence,
        'acknowledgment': acknowledgment,
        'header_length': offset,
        'payload': data[offset:]
    }


def resolve_domain(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None


def get_host_from_http_payload(payload):
    try:
        payload_str = payload.decode(errors='ignore')
        if "Host: " in payload_str:
            lines = payload_str.split("\r\n")
            for line in lines:
                if line.startswith("Host: "):
                    return line.split("Host: ")[1]
    except UnicodeDecodeError:
        pass
    return None


def format_mac(raw_mac):
    return ':'.join(format(byte, '02x') for byte in raw_mac)


def save_packet(packet_data, filename="packets.json"):
    with open(filename, "a") as f:
        f.write(json.dumps(packet_data) + "\n")


def detect_anomalies(packet_info):
    ip_src = packet_info.get('ip', {}).get('src_ip')
    if ip_src:
        anomalies[ip_src] += 1
        if anomalies[ip_src] > ANOMALY_THRESHOLD:
            print(f"[ALERT] Potential anomaly detected from {ip_src} with {anomalies[ip_src]} packets.")


def display_packet(packet_info):
    table = Table(title="Captured Packet", show_lines=True)
    table.add_column("Field", style="cyan", justify="right")
    table.add_column("Value", style="green")

    if "ip" in packet_info:
        ip = packet_info["ip"]
        table.add_row("Source IP", ip.get("src_ip", ""))
        table.add_row("Destination IP", ip.get("dst_ip", ""))
        table.add_row("Destination Domain", ip.get("dst_domain", ""))

    if "tcp" in packet_info and packet_info["tcp"]:
        tcp = packet_info["tcp"]
        table.add_row("Source Port", str(tcp.get("src_port", "")))
        table.add_row("Destination Port", str(tcp.get("dst_port", "")))

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

            if eth['protocol'] == 8:  # IPv4
                ip = parse_ip_header(eth['payload'])

                if ip['src_ip'] in blacklist['ip'] or ip['dst_ip'] in blacklist['ip']:
                    continue

                domain_name = resolve_domain(ip['dst_ip']) or get_host_from_http_payload(ip['payload'])

                if domain_name and domain_name not in DISPLAYED_DOMAINS:
                    DISPLAYED_DOMAINS.add(domain_name)

                    packet_info = {
                        'ip': {
                            'src_ip': ip['src_ip'],
                            'dst_ip': ip['dst_ip'],
                            'dst_domain': domain_name,
                            'protocol': ip['protocol']
                        },
                        'tcp': None
                    }

                    if ip['protocol'] == 6:  # TCP
                        tcp = parse_tcp_header(ip['payload'])
                        packet_info['tcp'] = {
                            'src_port': tcp['src_port'],
                            'dst_port': tcp['dst_port']
                        }

                    display_packet(packet_info)
                    save_packet(packet_info)

    except KeyboardInterrupt:
        print("\n[*] Stopping the sniffer.")
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer with Unique Domain Filtering")
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
