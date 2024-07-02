import struct
import threading
import socket

def check_host(ip):
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    icmp_packet = struct.pack('!BBHHH', 8, 0, 0, 0, 1) + b'pingdata'

    icmp_checksum = 0
    for i in range(0, len(icmp_packet), 2):
        icmp_checksum += (icmp_packet[i] << 8) + icmp_packet[i + 1]

    icmp_checksum = (icmp_checksum >> 16) + (icmp_checksum & 0xFFFF)
    icmp_checksum = ~icmp_checksum & 0xFFFF
    icmp_packet = struct.pack('!BBHHH', 8, 0, icmp_checksum, 0, 1) + b'pingdata'

    icmp_socket.sendto(icmp_packet, (ip, 0))

    try:
        response, _ = icmp_socket.recvfrom(1024)
        icmp_type = struct.unpack('!B', response[20:21])[0]

        if icmp_type == 0:
            return True
    except socket.error:
        pass

    return False

success = check_host("google.com")
if success:
    print("Ping pong!")
else:
    print("Ping...")