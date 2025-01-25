import socket
import struct


def main():
    con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = con.recvfrom(65536)
        dest_mac, src_mac, proto, data = ether_data(raw_data)
        print(f'DEST: {dest_mac}, SRC: {src_mac}, PROTOCOL: {proto}')


#Ethernet frame
def ether_data(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[14:]


# Convert MAC address format
def get_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


if __name__ == "__main__":
    main()