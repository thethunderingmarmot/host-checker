import struct
import threading
import socket
import tkinter

# Calcola il checksum
def get_checksum(source):
    checksum = 0
    for i in range(0, len(source), 2):
        checksum += (source[i] << 8) + source[i + 1]
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

# Controlla se un singolo host è online utilizzando il protocollo ICMP
def check_host(hostname):
    # Creazione del socket
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Creazione del pacchetto ICMP
    icmp_packet = struct.pack('!BBHHH', 8, 0, 0, 0, 1) + b'pingdata'

    # Calcolo del checksum del pacchetto ICMP creato
    icmp_checksum = get_checksum(icmp_packet)

    # Aggiunta del checksum al pacchetto stesso
    icmp_packet = struct.pack('!BBHHH', 8, 0, icmp_checksum, 0, 1) + b'pingdata'

    # Invio del pacchetto ICMP all'hostname
    icmp_socket.sendto(icmp_packet, (hostname, 0))

    try:
        # Se c'è risposta, viene recuperata
        response, _ = icmp_socket.recvfrom(1024)
        # Si prende il parametro "type" dal pacchetto di risposta 
        icmp_type = struct.unpack('!B', response[20:21])[0]
        # Si chiude il socket
        icmp_socket.close()

        # Si verifica se la risposta è 0, "echo reply"
        if icmp_type == 0:
            return True
    except socket.error:
        pass

    return False

# Questo metodo verrà usato dai thread.
# Controlla continumente lo stato di un singolo host, eseguendo delle lambda in base a se è online o no
def continuous_host_check(hostname, success_lambda, failure_lambda):
    while True:
        success = check_host(hostname)
        if success:
            success_lambda()
        else:
            failure_lambda()

# -------------------------------------------------------------------------------------------------------------------------

def update_host():
    pass

def add_host(event = None):
    new_thread = threading.Thread(target=continuous_host_check, args=(input_ip.get(), lambda: print("ping pong"), lambda: print("fail")))
    new_thread.daemon = True
    new_thread.start()
    thread_list[input_ip.get()] = new_thread
    hosts_list.insert(tkinter.END, input_ip.get())

# Main
thread_list = {}

window = tkinter.Tk()
window.title("nmap-clone")
window.minsize(400, 300)
window.maxsize(400, 300)

hosts_list = tkinter.Listbox(window, width=30)
hosts_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)

title_label = tkinter.Label(window, text="Network mapping tool")
title_label.pack()

input_ip = tkinter.StringVar()

ip_field = tkinter.Entry(window, textvariable=input_ip)
ip_field.bind("<Return>", add_host)
ip_field.pack()

add_button = tkinter.Button(window, text="Aggiungi", command=add_host)
add_button.pack()


tkinter.mainloop()