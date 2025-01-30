import socket
import struct
import argparse
import logging
from functools import lru_cache
from rich.console import Console
from rich.table import Table

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console, displayed_domains = Console(), set()

@lru_cache(maxsize=1000)
def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0] if ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None

def format_mac(raw_mac):
    return ':'.join(f'{byte:02x}' for byte in raw_mac)

def parse_ethernet_header(data):
    if len(data) < 14:
        logging.error("Ethernet frame too short")
        return {}
    try:
        dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
        return {'dest_mac': format_mac(dest_mac), 'src_mac': format_mac(src_mac), 'protocol': socket.htons(proto), 'payload': data[14:]}
    except struct.error as e:
        logging.error(f"Failed to parse Ethernet header: {e}")
        return {}

def parse_ip_header(data):
    if len(data) < 20:
        logging.error("IP packet too short")
        return {}
    try:
        version_header_len = data[0]
        header_length = (version_header_len & 15) * 4
        if len(data) < header_length:
            logging.error("Incomplete IP header")
            return {}
        ttl, proto, src, dst = struct.unpack('!8xBB2x4s4s', data[:20])
        return {'header_length': header_length, 'ttl': ttl, 'protocol': proto, 'src_ip': socket.inet_ntoa(src), 'dst_ip': socket.inet_ntoa(dst), 'payload': data[header_length:]}
    except struct.error as e:
        logging.error(f"Failed to parse IP header: {e}")
        return {}

def parse_tcp_header(data):
    if len(data) < 14:
        logging.error("TCP segment too short")
        return {}
    try:
        src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        if len(data) < offset:
            logging.error("Incomplete TCP header")
            return {}
        return {'src_port': src_port, 'dst_port': dst_port, 'sequence': seq, 'acknowledgment': ack, 'header_length': offset, 'payload': data[offset:]}
    except struct.error as e:
        logging.error(f"Failed to parse TCP header: {e}")
        return {}

def get_host_from_http_payload(payload):
    try:
        payload_str = payload.decode(errors='ignore').lower()
        return next((line.split("host: ")[1].strip() for line in payload_str.split("\r\n") if line.startswith("host: ")), None)
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
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if interface:
            conn.bind((interface, 0))
    except socket.error as e:
        logging.error(f"Failed to bind to interface {interface}: {e}")
        return
    logging.info(f"Sniffing on {interface or 'all interfaces'}... Press Ctrl+C to stop.")
    try:
        while True:
            raw_data, _ = conn.recvfrom(65536)
            eth = parse_ethernet_header(raw_data)
            if eth.get('protocol') == 8:  # IPv4
                ip = parse_ip_header(eth['payload'])
                if not ip:
                    continue
                domain_name = resolve_domain(ip['dst_ip'])
                ip["dst_domain"] = domain_name if domain_name else "Unknown"
                packet_info = {"eth": eth, "ip": ip}
                
                if ip["protocol"] == 6:  # TCP
                    tcp = parse_tcp_header(ip["payload"])
                    if not tcp:
                        continue
                    packet_info["tcp"] = tcp
                    
                    http_host = get_host_from_http_payload(tcp["payload"])
                    if http_host and http_host not in displayed_domains:
                        displayed_domains.add(http_host)
                        console.print(f"[bold yellow]New HTTP Host Detected:[/] {http_host}")
                    
                display_packet(packet_info)
    except KeyboardInterrupt:
        logging.info("Sniffing stopped by user.")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet sniffer for monitoring network traffic.")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on.", default=None)
    args = parser.parse_args()
    start_sniffer(args.interface)