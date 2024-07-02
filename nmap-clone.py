import struct
import threading
import socket
import tkinter

# Controlla se un singolo host è online utilizzando il protocollo ICMP
def check_host(hostname):
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    icmp_packet = struct.pack('!BBHHH', 8, 0, 0, 0, 1) + b'pingdata'

    icmp_checksum = 0
    for i in range(0, len(icmp_packet), 2):
        icmp_checksum += (icmp_packet[i] << 8) + icmp_packet[i + 1]

    icmp_checksum = (icmp_checksum >> 16) + (icmp_checksum & 0xFFFF)
    icmp_checksum = ~icmp_checksum & 0xFFFF
    icmp_packet = struct.pack('!BBHHH', 8, 0, icmp_checksum, 0, 1) + b'pingdata'

    icmp_socket.sendto(icmp_packet, (hostname, 0))

    try:
        response, _ = icmp_socket.recvfrom(1024)
        icmp_type = struct.unpack('!B', response[20:21])[0]

        if icmp_type == 0:
            return True
    except socket.error:
        pass

    return False

# Controlla all'infinito lo stato di un singolo host, eseguendo delle lambda in base a se è online o no
def continuous_host_check(hostname, success_lambda, failure_lambda):
    while True:
        success = check_host(hostname)
        if success:
            success_lambda()
        else:
            failure_lambda()

# -------------------------------------------------------------------------------------------------------------------------

# Main
window = tkinter.Tk()
window.title("nmap-clone")

hosts_list = tkinter.Listbox(window, height=15, width=50)
hosts_list.insert(0, "test2")

tkinter.mainloop()

#ping_thread = threading.Thread(target=lambda: continuous_host_check("google.it", lambda: print("Ping pong!"), lambda: print("No response!")))
#ping_thread.start()
