"""
    Clasele care descriu RIPv2 PDU
"""
import struct
import datetime
from socket import *

import ipaddr


class RIPPacket:

    # in functie de sursa si formatul datelor, initializam pachetul
    # cu datele din alt pachet
    # sau construim un pachet cu header si intrari noi

    def __init__(self, data=None, header=None, rtes=None):
        if data:
            self._init_from_network(data)
        elif header and rtes:
            self._init_from_host(header, rtes)
        else:
            raise ValueError

    def __repr__(self):
        return "RIPPacket: Command {}, Ver. {}, number of RTEs {}.".format(self.header.cmd, self.header.ver, len(self.rtes))

    # initializam cu datele din alt pachet
    def _init_from_network(self, data):
        datalen = len(data)

        # verificam daca pachetul respecta parametrii definiti in protocol
        if datalen < RIPHeader.SIZE:
            raise FormatException

        malformed_rtes = (datalen - RIPHeader.SIZE) % RIPRouteEntry.SIZE

        if malformed_rtes:
            raise FormatException

        # calculam numarul de rute pe baza lungimii pachetului
        # si a lungimii unei rute
        num_rtes = int((datalen - RIPHeader.SIZE) / RIPRouteEntry.SIZE)

        # extragem header-ul
        self.header = RIPHeader(data[0:RIPHeader.SIZE])

        # extragem rutele
        self.rtes = []

        rte_start = RIPHeader.SIZE
        rte_end = RIPHeader.SIZE + RIPRouteEntry.SIZE

        for i in range(num_rtes):
            self.rtes.append(RIPRouteEntry(rawdata=data[rte_start:rte_end]))
            rte_start += RIPRouteEntry.SIZE
            rte_end += RIPRouteEntry.SIZE

    # initializam cu date deja verificate
    def _init_from_host(self, header, rtes):
        if header.ver != 2:
            raise ValueError("Version 2 Supported")
        self.header = header
        self.rtes = rtes

    # transformam pachetul in bytes si il returnam
    def serialize(self):
        packed = self.header.serialize()
        for rte in self.rtes:

            if(type(rte) == str):
                packed += bytes(rte,'ascii')
            else:
                packed += rte.serialize()

        return packed

# clasa care descrie header-ul unui pachet
# si metricile acestuia
class RIPHeader:

    # formatul unui pachet este descris de
    # - un octet pentru comanda
    # - un octet pentru versiune(implicit 2)
    # - doi octeti de zero
    FORMAT = "!BBH"
    SIZE = struct.calcsize(FORMAT)
    TYPE_RESPONSE = 2
    VERSION = 2


    # in functie de sursa si formatul datelor, initializam pachetul
    # cu datele din alt pachet
    # sau construim un pachet cu header si intrari noi
    def __init__(self, rawdata=None):
        self.packed = None

        if rawdata:
            self._init_from_network(rawdata)
        else:
            self._init_from_host()

    def __repr__(self):
        return "RIP Header (cmd = {}, ver = {})".format(self.cmd, self.ver)

    # initializare din alt pachet
    def _init_from_network(self, rawdata):
        header = struct.unpack(self.FORMAT, rawdata)
        self.cmd = header[0]
        self.ver = header[1]

    # initializarea unui header nou
    def _init_from_host(self):
        self.cmd = self.TYPE_RESPONSE
        self.ver = self.VERSION

    # transforma header-ul in bytes si il returneaza
    def serialize(self):
        return struct.pack(self.FORMAT, self.cmd, self.ver, 0)


# clasa descrie o intrare in pachet
class RIPRouteEntry:

    # formatul unui pachet este dat de:
    # - 2 octeti familia de adrese(implicit IPv4)
    # - 2 octeti taggul rutei
    # - 4 octeti adresa ip sursa
    # - 4 octeti masca retelei
    # - 4 octeti adresa ip a urmatorului hop

    FORMAT = ">HHIIII"
    SIZE = struct.calcsize(FORMAT)
    MIN_METRIC = 0
    MAX_METRIC = 16

    # in functie de sursa si formatul datelor, initializam pachetul
    # cu datele din alt pachet
    # sau construim o intrare cu date furnizate in mod explicit
    def __init__(self, rawdata=None, src_ip=None, address=None, nexthop=None, metric=None, mask=None, imported=False):
        self.changed = False
        self.imported = imported
        self.init_timeout()

        if rawdata:
            self._init_from_network(rawdata, src_ip)
        elif address and nexthop is not None and metric is not None:
            self._init_from_host(address, mask, nexthop, metric)
        else:
            raise ValueError

    # metoda folosita la afisrea tabelei de rutare
    def __repr__(self):
        template = "|{:^11}|{:^10}|{:^11}|{:^15}|{:^10}|{:^13}|"

        if self.timeout is None:
            return template.format(str(self.addr), str(self.metric), str(self.nexthop), str(self.changed), str(self.garbage), str(self.timeout))
        else:
            timeout = (datetime.datetime.now() - self.timeout).total_seconds()
            return template.format(str(self.addr), str(self.metric), str(self.nexthop), str(self.changed), str(self.garbage), str(round(timeout, 1)))

    # initializare intrare cu date noi
    def _init_from_host(self, address, mask, nexthop, metric):
        self.afi = AF_INET
        self.tag = 0
        self.addr = address
        self.mask = mask
        self.nexthop = nexthop
        self.metric = metric

    # initializare din alt pachet
    def _init_from_network(self, rawdata, src_ip):
        rte = struct.unpack(self.FORMAT, rawdata)

        self.afi = rte[0]
        self.tag = rte[1]
        self.addr = ipaddr.IPv4Address(rte[2])
        self.mask = ipaddr.IPv4Address(rte[3])
        self.set_nexthop(ipaddr.IPv4Address(rte[4]))
        self.metric = rte[5]

        if self.nexthop == 0:
            self.nexthop = src_ip

        if not self.MIN_METRIC <= self.metric <= self.MAX_METRIC:
            raise FormatException

    # initializeaza timer-ul unei rute
    def init_timeout(self):
        if self.imported:
            self.timeout = None
        else:
            self.timeout = datetime.datetime.now()

        self.garbage = False
        self.marked_for_delection = False

    def __eq__(self, other):
        if self.afi == other.afi and self.addr == other.addr and self.tag == other.tag and self.nexthop == other.nexthop and self.metric == other.metric:
            return True
        else:
            return False

    # metoda folosita pentru a seta urmatorul hop
    def set_nexthop(self, nexthop):
        self.nexthop = nexthop

    # pregateste intrarea conform cu standard-ul si o returneaza
    def serialize(self):
        if self.nexthop:
            self.nexthop = ipaddr.IPv4Address(self.nexthop)
        else:
            self.nexthop = 0
        if self.addr:
            self.addr = ipaddr.IPv4Address(self.addr)
        else:
            self.addr = 0
        if self.mask:
            self.mask = ipaddr.IPv4Address(self.mask)
        else:
            self.mask = 0

        return struct.pack(self.FORMAT, self.afi, self.tag, self.addr, self.mask, self.nexthop, self.metric)

# clasa folosita pentru afisarea exceptiilor
class FormatException(Exception):

    def __init__(self, message=""):
        self.message = message
