import socket
import struct
import argparse
import json
import logging
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from functools import lru_cache

displayed_domains = set()
console = Console()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

@lru_cache(maxsize=1000)
def resolve_domain(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None

def format_mac(raw_mac):
    return ':'.join(format(byte, '02x') for byte in raw_mac)

def parse_ethernet_header(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return {
        'dest_mac': format_mac(dest_mac),
        'src_mac': format_mac(src_mac),
        'protocol': socket.htons(proto),
        'payload': data[14:]
    }

def parse_ip_header(data):
    try:
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
    except struct.error as e:
        logging.error(f"Failed to parse IP header: {e}")
        return {}

def parse_tcp_header(data):
    try:
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
    except struct.error as e:
        logging.error(f"Failed to parse TCP header: {e}")
        return {}

def get_host_from_http_payload(payload):
    try:
        payload_str = payload.decode(errors='ignore').lower()
        if "host: " in payload_str:
            lines = payload_str.split("\r\n")
            for line in lines:
                if line.startswith("host: "):
                    return line.split("host: ")[1].strip()
    except Exception as e:
        logging.error(f"Error extracting host from HTTP payload: {e}")
    return None

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

def start_sniffer(interface=None):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    if interface:
        conn.bind((interface, 0))

    logging.info(f"Sniffing on {interface or 'all interfaces'}... Press Ctrl+C to stop.")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            eth = parse_ethernet_header(raw_data)

            if eth['protocol'] == 8:  # IPv4
                ip = parse_ip_header(eth['payload'])
                if not ip:
                    continue

                domain_name = resolve_domain(ip['dst_ip'])

                if not domain_name and ip['protocol'] == 6:  # TCP
                    tcp = parse_tcp_header(ip['payload'])
                    if tcp:
                        domain_name = get_host_from_http_payload(tcp['payload'])

                if domain_name and domain_name not in displayed_domains:
                    displayed_domains.add(domain_name)
                    packet_info = {
                        'ip': {
                            'src_ip': ip['src_ip'],
                            'dst_ip': ip['dst_ip'],
                            'dst_domain': domain_name
                        },
                        'tcp': {
                            'src_port': tcp['src_port'],
                            'dst_port': tcp['dst_port']
                        } if 'tcp' in locals() and tcp else None
                    }
                    display_packet(packet_info)

    except KeyboardInterrupt:
        logging.info("Stopping the sniffer.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        conn.close()

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer with Accurate Domain Resolution")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all interfaces)")
    args = parser.parse_args()

    start_sniffer(interface=args.interface)

if __name__ == "__main__":
    main()
