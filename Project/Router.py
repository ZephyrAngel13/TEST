"""
    Implementarea unui Router
"""

from RIPPacket import RIPRouteEntry
from States import *
import threading
from random import *
import time
from RIP_FSM import *
import socket
import psutil

DEBUG = 0


class Router:
    """
    Router class
    """

    def __init__(self):

        self.fsm = RouterFSM(self)

        self.readable_port = 520

        # socketurile care vor transmite pachete
        self.router_sockets = []

        # socketul de receptie multicast
        self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        group = socket.inet_aton('224.0.0.1')
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        self.multicast_socket.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_LOOP,0)
        self.multicast_socket.bind(('224.0.0.1',520))

        # tabela de routare
        self.routing_table = dict()
        self.route_change = False

        # lista cu interfetele la care este conectat( pentru a nu trimite pachete siesi )
        self.receiving_int = []

        # adaugare stari si tranzitii
        self.fsm.add_state("StartUp", StartUp(self.fsm))
        self.fsm.add_state("Waiting", Waiting(self.fsm))
        self.fsm.add_state("ReadMessage", ReadMessage(self.fsm))

        self.fsm.add_transistion("toWaiting", Transistion("Waiting"))
        self.fsm.add_transistion("toReadMessage", Transistion("ReadMessage"))

        # pornirea routerului
        self.fsm.set_state("StartUp")

    def execute(self):
        self.fsm.execute()

    # obtine adresele ip ale interfetelor de retea
    def get_inet_ips(self):

        addrs = psutil.net_if_addrs()
        vals = addrs.values()
        result = []

        for i in vals:
            if i[0][1] not in result and i[0][1]!='127.0.0.1':
                result.append(i[0][1])

        addresses = []

        for i in result:
            import re
            if re.match('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',str(i)) != None and re.match('10\..*',str(i)) == None:
                addresses.append(i)

        return addresses

    # calculeaza adresa de retea pe baza mastii si adresei host
    def calculate_network(self, ip, mask):
        network = ''

        iOctets = str(ip).split('.')
        mOctets = str(mask).split('.')

        network = str(int(iOctets[0]) & int(mOctets[0])) + '.'
        network += str(int(iOctets[1]) & int(mOctets[1])) + '.'
        network += str(int(iOctets[2]) & int(mOctets[2])) + '.'
        network += str(int(iOctets[3]) & int(mOctets[3]))

        return network

    def update_routing_table(self, packet: RIPPacket, address = None):

        print("Fac update de la " + str(address))
        string_keys = []

        if packet == None:
            return

        # salvam adresele din tabela de rutare dupa ce le convertim la string
        for k in self.routing_table.keys():
            string_keys.append(str(k))

        for rte in packet.rtes:
            # adresa de retea a sursei
            net_address = self.calculate_network(str(rte.addr),str(rte.mask))

            # verificam daca adresa de unde a venit pachetul se regaseste
            # in tabela de rutare
            if str(net_address) not in string_keys:
                # daca adresa a atins metrica maxima o ignoram
                if rte.metric == RIPRouteEntry.MAX_METRIC:
                    continue

                # daca nu se regaseste, o adaugam si setam next hop adresa de unde a venit(address)
                rte.set_nexthop(address[0])

                # metrica este aleasa intre metrica rutei primite + 1, si metrica maxima permisa de protocol
                rte.metric = min(rte.metric + 1, RIPRouteEntry.MAX_METRIC)

                # marcam ruta ca fiind schimbata
                rte.changed = True
                rte.route_change = True

                # salvam ruta in tabela
                self.routing_table[str(rte.addr)] = rte
                return
            else:
                # daca ruta exista si a atins metrica maxima o marcam pentru eliminare
                if self.routing_table[str(rte.addr)].metric == RIPRouteEntry.MAX_METRIC and self.routing_table[str(rte.addr)].garbage == False:
                   self.routing_table[str(rte.addr)].garbage = True

                # daca vecinii funizeaza o ruta infinita, router-ul curent o considera si el ca fiind de neatins
                if rte.metric == RIPRouteEntry.MAX_METRIC and self.routing_table[str(rte.addr)].imported == False and self.routing_table[str(rte.addr)].metric != RIPRouteEntry.MAX_METRIC:
                    self.routing_table[str(rte.addr)].metric = RIPRouteEntry.MAX_METRIC

                # consideram cazul in care rutele din partea vecinilor raman nemodificate si le resetam timerul
                if address[0] == str(self.routing_table[str(rte.addr)].nexthop) and self.routing_table[str(rte.addr)].metric != RIPRouteEntry.MAX_METRIC:
                    self.routing_table[str(rte.addr)].init_timeout()

                # consideram cazul in care exista mai multe variante pentru
                # a ajunge la aceeasi destinatie
                if str(rte.addr) == str(self.routing_table[str(rte.addr)].addr):
                    # daca ruta din pachet este mai mica decat ruta din tabela, preluam ruta din pachet
                    # si o actualizam pe cea din tabela de rutare
                    if rte.metric + 1 < self.routing_table[str(rte.addr)].metric and self.routing_table[str(rte.addr)].metric != RIPRouteEntry.MAX_METRIC:
                        self.routing_table[str(rte.addr)].init_timeout()
                        self.routing_table[str(rte.addr)].garbage = False
                        self.routing_table[str(rte.addr)].changed = True
                        self.routing_table[str(rte.addr)].metric = rte.metric + 1
                        self.routing_table[str(rte.addr)].nexthop = ipaddr.IPv4Address(str(address[0]))
                        self.route_change = True


    # functia de afisare tabela de rutare
    def print_routing_table(self):
        """
        prints the routing table
        """
        line = "+-----------+----------+-----------+---------------+----------+-------------+"
        print(line)
        print("|                  Routing Table   (Router " + "" + ")                    |")
        print(line)
        print("|Destination  |  Metric  |  NextHop  |  ChangedFlag  |  Garbage |  Timeout(s) |")
        print("+===========+==========+===========+===============+==========+=============+")

        for entry in self.routing_table.keys():
            print(self.routing_table[entry])
            print(line)
        print('\n')

    # functia care trateaza un update declansat
    def trigger_update(self):
        changed_routes = []
        print_message("Sending Trigger update.")
        for rte in self.routing_table.values():
            if rte.changed:
                changed_routes.append(rte)
                rte.changed = False

        self.route_change = False
        delay = randint(1, 5)

        threading.Timer(delay, self.update, [changed_routes])

    # functia care trateaza un update periodic
    def update(self, entries):
        # nu continuam daca pachetul contine rute goale
        if(entries == []):
            return

        local_header = RIPHeader()

        for sock in self.router_sockets:
            entries1 = []
            # cautam ca router-ul sa nu-si trimita pachete siesi
            for i in entries:
                net_sock = self.calculate_network(str(sock.getsockname()[0]),'255.255.255.0')
                if str(net_sock) != str(i.addr):
                    net_i = self.calculate_network(str(i.addr),'255.255.255.0')
                    i.addr = net_i
                    entries1.append(i)

            # trimitem pachet-ul vecinilor pe baza de multicast
            p = RIPPacket(header=local_header,rtes=entries1)
            sock.sendto(p.serialize(), ('224.0.0.1', 520))

        print_message("Message Sent To Routers")

    # functie pentru verificarea timpului de cand o ruta \
    # nu a mai fost folosita
    def check_timeout(self):
        print_message("Checking timeout...")
        if self.routing_table != {}:
            for rte in self.routing_table.values():
                if rte.timeout is not None and (datetime.datetime.now() - rte.timeout).total_seconds() >= ROUTE_TIMEOUT:
                    rte.garbage = True
                    rte.changed = True
                    self.route_change = True
                    rte.metric = RIPRouteEntry.MAX_METRIC
                    rte.timeout = datetime.datetime.now()
                    self.print_routing_table()
                    print_message("Router: " + str(rte.addr) + " timed out.")

    # marcheaza rutele garbage pentru stergere
    def garbage_timer(self):
        if self.routing_table != {}:
            for rte in self.routing_table.values():
                if rte.garbage:
                    if (datetime.datetime.now() - rte.timeout).total_seconds() >= DELETE_TIMEOUT:
                        rte.marked_for_delection = True

    # sterge rutele marcate cu garbage True
    def garbage_collection(self):

        if self.routing_table != {}:
            delete_routes = []
            for rte in self.routing_table.values():
                if rte.marked_for_delection:
                    delete_routes.append(rte.addr)
                    print_message("Router: " + str(rte.addr) + " has been " + "removed from the routing table.")

            for entry in delete_routes:
                del self.routing_table[str(entry)]
                self.print_routing_table()

    # porneste un timer generic
    def timer(self, function, param=None):
        if param is not None:
            function(list(param.values()))
            period = BASE_TIMER * randrange(8, 12, 1) / 10
        else:
            period = BASE_TIMER
            function()

        threading.Timer(period, self.timer, [function, param]).start()

    # porneste timers pentru: update, timeout, garbage si stergere
    def start_timers(self):
        self.timer(self.update, param=self.routing_table)
        self.timer(self.check_timeout)
        self.timer(self.garbage_timer)
        self.timer(self.garbage_collection)

    def main_loop(self):
        while True:
            self.execute()


def print_message(message):
    if DEBUG:
        pass

