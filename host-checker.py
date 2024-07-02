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
    
    # Ritorna un generico pacchetto ICMP
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
        # Si imposta il timeout di scadenza di una risposta a 5 secondi
        icmp_socket.settimeout(5)
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
        except TimeoutError:
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
        self.linked_thread = threading.Thread(target=self.check_always)
        self.linked_thread.daemon = True
        self.linked_thread.start()

class ScrollableFrame(tkinter.Frame):
    def __init__(self, container, width, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tkinter.Canvas(self, width=width)
        scrollbar = tkinter.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = tkinter.Frame(canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

# Gestisce l'aggiornamento di una label in base al cambio di stato di un Host
def update_label(label:tkinter.Label, host: Host):
    if(host.status == utils.Status.ONLINE):
        label.config(text=host.hostname + " - online", background="lime green")
    elif(host.status == utils.Status.OFFLINE):
        label.config(text=host.hostname + " - offline", background="dim gray")
    elif(host.status == utils.Status.ERROR):
        label.config(text=host.hostname + " - error", background="orange red")

# Gestisce l'aggiunta di un nuovo host
def add_host_label(event = None, last_label_added = None, default_timeout = 5):
    # Prende l'hostname inserito nell'Entry
    hostname = input_hostname.get()

    # Viene creata una nuova Label per mostrare lo stato dell'host
    new_label = tkinter.Label(hosts_container.scrollable_frame, text=hostname + " - waiting", background="cadet blue")
    new_label.pack()

    # Viene creato un oggetto Host a cui si passa una lambda che gestirà l'aggiornamento della label
    new_host = Host(hostname, default_timeout, lambda host: update_label(new_label, host))
    # Si inizia a fare il check continuo in un altro thread sull'Host
    new_host.check_always_threaded()

    # Si aggiunge l'Host appena creato ad una lista
    hosts_list.append(new_host)
    # Si svuota il valore inserito nell'Entry
    input_hostname.set("")

# ----------------------------------------------------------------------------------------------------------

hosts_list = []

# Creazione della finestra
window = tkinter.Tk()
window.title("host-checker")
window.minsize(200, 200)
window.maxsize(200, 200)

input_container = tkinter.Frame(window)
input_container.pack(fill=tkinter.BOTH, expand=True)

# Creazione del label di indicazione
indication_label = tkinter.Label(input_container, text="Inserire un hostname")
indication_label.pack()

# Creazione dell'Entry dove inserire l'hostname
input_hostname = tkinter.StringVar()
hostname_field = tkinter.Entry(input_container, textvariable=input_hostname)
hostname_field.pack()

# Premere invio nell'Entry è come premere il pulsante
hostname_field.bind("<Return>", add_host_label)

# Creazione del pulsante che aggiunge l'hostname
add_button = tkinter.Button(input_container, text="Aggiungi", command=add_host_label)
add_button.pack()

# Creazione dello spazio dedicato a mostrare gli host
hosts_container = ScrollableFrame(window, width=150)
hosts_container.pack(fill=tkinter.BOTH, expand=True)

tkinter.mainloop()