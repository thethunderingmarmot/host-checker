import struct
import threading
import socket
import tkinter
import time

class utils:
    class Status:
        ERROR = -1
        ONLINE = 0
        OFFLINE = 1

    # Calcola il checksum come specificato in RFC1071
    def get_checksum(source):
        checksum = 0
        for i in range(0, len(source), 2):
            checksum += (source[i] << 8) + source[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum
    
    # Ritorna un pacchetto ICMP
    def get_icmp_packet():
        # Creazione del pacchetto ICMP
        icmp_packet = struct.pack('!BBHHH', 8, 0, 0, 0, 1) + b'pingdata'
        # Calcolo del checksum del pacchetto ICMP
        icmp_checksum = utils.get_checksum(icmp_packet)
        # Aggiunta del checksum al pacchetto stesso
        icmp_packet = struct.pack('!BBHHH', 8, 0, icmp_checksum, 0, 1) + b'pingdata'
        return icmp_packet
    
    # Controlla se un host è online utilizzando il protocollo ICMP
    def check_host(hostname):
        # Creazione del socket
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Creazione del pacchetto ICMP
        icmp_packet = utils.get_icmp_packet()

        try:
            # Invio del pacchetto ICMP all'host
            icmp_socket.sendto(icmp_packet, (hostname, 0))
            # Se c'è risposta, viene recuperata
            response, _ = icmp_socket.recvfrom(1024)
            # Si prende il parametro "type" dal pacchetto di risposta 
            icmp_type = struct.unpack('!B', response[20:21])[0]
            # Si chiude il socket
            icmp_socket.close()
            # Si verifica se la risposta è 0, "echo reply"
            if icmp_type == 0:
                return utils.Status.ONLINE
            else:
                return utils.Status.OFFLINE
        except Exception:
            return utils.Status.ERROR
    
class Host:
    # Costruttore di Host
    def __init__(self, hostname, timeout, on_status_updated):
        self.hostname = hostname
        self.timeout = timeout
        self.on_status_updated = on_status_updated

    # Esegue un singolo ping
    def check(self):
        self.status = utils.check_host(self.hostname)
        self.on_status_updated(self)
    
    # Esegue continui ping nel thread corrente
    def check_always(self):
        while True:
            self.check()
            time.sleep(self.timeout)

    # Esegue continui ping in un nuovo thread
    def check_always_threaded(self):
        self.linked_thread = threading.Thread(target=self.check)
        self.linked_thread.daemon = True
        self.linked_thread.start()

# Gestisce l'aggiornamento di una label in base al cambio di stato di un Host
def update_label(label:tkinter.Label, host: Host):
    if(host.status == utils.Status.ONLINE):
        label.config(text=host.hostname + " - online", background="lime green")
    elif(host.status == utils.Status.OFFLINE):
        label.config(text=host.hostname + " - offline", background="dim gray")
    elif(host.status == utils.Status.ERROR):
        label.config(text=host.hostname + " - error", background="orange red")

# Gestisce l'aggiunta di un nuovo host
def add_host(event = None):
    # Prende l'hostname inserito nell'Entry
    hostname = input_hostname.get()

    # Viene creata una nuova Label che mostrera lo stato dell'host
    new_label = tkinter.Label(hosts_frame, text=hostname + " - waiting", background="cadet blue")
    new_label.pack()

    # Viene creato un Host a cui si passa una lambda che gestirà l'aggiornamento della label
    new_host = Host(hostname, 2, lambda host: update_label(new_label, host))
    # Si inizia a fare il check continuo in un altro thread sull'Host
    new_host.check_always_threaded()

    # Si aggiunge l'Host appena creato ad una lista
    hosts_list.append(new_host)
    # Si svuota il valore inserito nell'Entry
    input_hostname.set("")

# Main
hosts_list = []

window = tkinter.Tk()
window.title("host-checker")
window.minsize(400, 300)
window.maxsize(400, 300)

hosts_frame = tkinter.Frame(window, width=50, background="white")
hosts_frame.pack(side=tkinter.LEFT, fill=tkinter.BOTH)

hosts_label = tkinter.Label(hosts_frame, text="Hosts")
hosts_label.pack()

title_label = tkinter.Label(window, text="Inserire un hostname")
title_label.pack()

input_hostname = tkinter.StringVar()

hostname_field = tkinter.Entry(window, textvariable=input_hostname)
hostname_field.bind("<Return>", add_host)
hostname_field.pack()

add_button = tkinter.Button(window, text="Aggiungi", command=add_host)
add_button.pack()

tkinter.mainloop()