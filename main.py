import socket
import struct
import textwrap

#ethernet frame unpacking
def ether_data(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest_mac), get_mac(src_mac), socket.htons(proto), data[:14]