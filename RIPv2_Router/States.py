"""
    Starile automatului
"""

import socket
import time

from RIPv2 import *
from Router import *

DEBUG = 0

# setare durate timers
BASE_TIMER = 3
MAX_METRIC = 16
ROUTE_TIMEOUT = BASE_TIMER * 6
DELETE_TIMEOUT = BASE_TIMER * 4

AF_INET = 2


# folosita pentru a afisa mesaje de stare
def print_message(message):
    if DEBUG:
        print("[" + time.strftime("%H:%M:%S") + "]: " + message)


# clasa de baza pentru tranzitii
class Transistion:

    def __init__(self, to_state):
        self.to_state = to_state

    def execute(self):
        pass


# clasa de baza pentru stari
class State:
    packet = None
    addr = None

    def __init__(self, fsm):
        self.fsm = fsm

    # intrarea in stare
    def enter(self):
        pass

    # executia starii
    def execute(self):
        pass

    # iesirea din stare
    def exit(self):
        pass


# starea initiala
class StartUp(State):

    def __init__(self, fsm):
        super(StartUp, self).__init__(fsm)

    def execute(self):

        self.setup_routing_table()

        # extragem adresele ip ale interfetelor de retea ale routerului
        addr = self.fsm.router.get_inet_ips()

        # facem bind pe toate interfetele de retea ale routerului
        for i in addr:
            # initilizam socketuri pentru fiecare interfata
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            sock.bind((i, 520))

            # initializam header pentru pachet
            local_header = RIPHeader()

            # retinem toate intrarile din tabela de rutare
            entries = []
            for k in self.fsm.router.routing_table:
                if k != i:
                    entry = RIPRouteEntry(address=self.fsm.router.routing_table[k].addr,
                                          nexthop=self.fsm.router.routing_table[k].nexthop,
                                          metric=self.fsm.router.routing_table[k].metric, mask='255.255.255.0')
                    entries.append(entry)

            # introducem header-ul si intrarile din tabela intr-un pachet
            # pe care il vom trimite vecinilor prin multicast
            packet = RIPPacket(rtes=entries, header=local_header)
            sock.sendto(packet.serialize(), ('224.0.0.1', 520))

            # retinem socket-urile pentru interfete
            self.fsm.router.router_sockets.append(sock)

        # afisam tabela de rutare initiala
        self.fsm.router.print_routing_table()

        # trecem in starea urmatoare
        self.fsm.to_transition("toWaiting")

    # iesim din stare
    def exit(self):
        print_message("Router Setup Complete.")

    # initializare tabela de rutare cu adresele de retea proprii ruterului
    def setup_routing_table(self):
        addresses = self.fsm.router.get_inet_ips()  # Facem o lista cu adresele IP ale interfetelor de retea

        for adr in addresses:
            net = self.fsm.router.calculate_network(adr,
                                                    '255.255.255.0')  # Calculam adresele de retea in functie de adresele gasite
            self.fsm.router.routing_table[net] = RIPRouteEntry(address=net, nexthop=adr, metric=0, mask='255.255.255.0',
                                                               imported=True)  # Se adauga la tabela de rutare toate interfetele de retea


# starea de asteptare
class Waiting(State):

    def __init__(self, fsm):
        super(Waiting, self).__init__(fsm)

    # intrarea in stare
    def enter(self):
        print_message("Entering idle state...")

    def execute(self):
        # primim datele si adresa sursa
        data, State.addr = self.fsm.router.multicast_socket.recvfrom(
            8192)  # Datele sunt primite prin socketul multicast

        # verificam pe ce interfata a venit pachetul, ca sa nu ne trimitem noua inapoi
        # acelasi pachet din considerente de convergenta

        for k in self.fsm.router.router_sockets:
            if str(k.getsockname()[0]) == str(State.addr[0]):
                return

        # trimitem pachetul urmatoarei stari
        State.packet = RIPPacket(data=data)

        # trecem in starea de ReadMessage
        self.fsm.to_transition("toReadMessage")

    def exit(self):
        print_message("Message Received")


# starea in care citim pachetul si actualizam tabela de rutare
class ReadMessage(State):

    def __init__(self, fsm):
        super(ReadMessage, self).__init__(fsm)

    def enter(self):
        print_message("Reading Messages...")

    def execute(self):
        # actualizam tabela de rutare cu informatiile de la receptie
        self.fsm.router.update_routing_table(State.packet, State.addr)

        # daca o ruta a suferit modificari, declansam un update
        if self.fsm.router.route_change:
            self.fsm.router.trigger_update()

        # afisam tabela de rutare indiferent daca au avut loc schimbari
        self.fsm.router.print_routing_table()

        # ne intoarcem in starea de asteptare
        self.fsm.to_transition("toWaiting")

    def exit(self):
        print_message("Messages Read.")
