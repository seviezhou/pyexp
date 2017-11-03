from socketserver import BaseRequestHandler
from socketserver import UDPServer
from socketserver import TCPServer
from socketserver import ThreadingMixIn
from dnslib import *
from IPy import IP

import socket
import threading
import time
import operator
import random

from lib.core.data import logger
from lib.core.data import conf


class DNSProxy():
    def parse(self, data):
        response = ""
        dns = DNSRecord.parse(data)
        '''
        >>> dnslib.DNSRecord.parse(b'f\xe8\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05baidu\x03com\x00\x00\x01\x00\x01')
        <DNS Header: id=0x66e8 type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'baidu.com.' qtype=A qclass=IN>
        '''
        if QR[dns.header.qr] == "QUERY":
            qname = str(dns.q.qname)
            if qname[-1] == ".":
                qname = qname[:-1]

            qtype = QTYPE[dns.q.qtype]
            msg = "Proxying the response of type '%s' for %s" % (qtype, qname)
            logger.info(msg)

            fake_records = dict()

            for record in self.server.nametodns:
                fake_records[record] = self.findNameToDNS(qname, self.server.nametodns[record])

            if qtype in fake_records and fake_records[qtype]:

                fake_record = fake_records[qtype]

                response = DNSRecord(DNSHeader(id=dns.header.id, bitmap=dns.header.bitmap, qr=1, aa=1, ra=1), q=dns.q)

                if qtype == "AAAA":
                    """
                    >>> IPy.IP("127.0.0.1").strBin()
                    '01111111000000000000000000000001'
                    """
                    ipv6 = IP(fake_record)
                    ipv6_bin = ipv6.strBin()
                    ipv6_hex_tuple = [int(ipv6_bin[i:i + 8], 2) for i in range(0, len(ipv6_bin), 8)]
                    response.add_answer(RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](ipv6_hex_tuple)))

                elif qtype == "SOA":
                    mname, rname, t1, t2, t3, t4, t5 = fake_record.split(" ")
                    times = tuple([int(t) for t in [t1, t2, t3, t4, t5]])

                    if mname[-1] == ".": mname = mname[:-1]
                    if rname[-1] == ".": rname = rname[:-1]
                    response.add_answer(RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](mname, rname, times)))

                elif qtype == "NAPTR":
                    order, preference, flags, service, regexp, replacement = fake_record.split(" ")
                    order = int(order)
                    preference = int(preference)

                    if replacement[-1] == ".": replacement = replacement[:-1]

                    response.add_answer(RR(qname, getattr(QTYPE, qtype),
                                           rdata=RDMAP[qtype](order, preference, flags, service, regexp,
                                                              DNSLabel(replacement))))

                elif qtype == "SRV":
                    priority, weight, port, target = fake_record.split(" ")
                    priority = int(priority)
                    weight = int(weight)
                    port = int(port)
                    if target[-1] == ".": target = target[:-1]

                    response.add_answer(
                        RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](priority, weight, port, target)))

                elif qtype == "DNSKEY":
                    flags, protocol, algorithm, key = fake_record.split(" ")
                    flags = int(flags)
                    protocol = int(protocol)
                    algorithm = int(algorithm)
                    key = base64.b64decode(("".join(key)).encode('ascii'))

                    response.add_answer(
                        RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key)))

                elif qtype == "RRSIG":
                    covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(" ")
                    covered = getattr(QTYPE, covered)  # NOTE: Covered QTYPE
                    algorithm = int(algorithm)
                    labels = int(labels)
                    orig_ttl = int(orig_ttl)
                    sig_exp = int(time.mktime(time.strptime(sig_exp + 'GMT', "%Y%m%d%H%M%S%Z")))
                    sig_inc = int(time.mktime(time.strptime(sig_inc + 'GMT', "%Y%m%d%H%M%S%Z")))
                    key_tag = int(key_tag)
                    if name[-1] == '.': name = name[:-1]
                    sig = base64.b64decode(("".join(sig)).encode('ascii'))

                    response.add_answer(RR(qname, getattr(QTYPE, qtype),
                                           rdata=RDMAP[qtype](covered, algorithm, labels, orig_ttl, sig_exp, sig_inc,
                                                              key_tag, name, sig)))

                else:
                    if fake_record[-1] == ".": fake_record = fake_record[:-1]
                    response.add_answer(RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](fake_record)))

                response = response.pack()

            elif qtype == "ANY" and not None in fake_records.values():

                response = DNSRecord(DNSHeader(id=dns.header.id, bitmap=dns.header.bitmap, qr=1, aa=1, ra=1), q=dns.q)

                for qtype, fake_record in fake_records.items():
                    if fake_record:
                        if qtype == "AAAA":
                            ipv6 = IP(fake_record)
                            ipv6_bin = ipv6.strBin()
                            fake_record = [int(ipv6_bin[i:i + 8], 2) for i in range(0, len(ipv6_bin), 8)]

                        elif qtype == "SOA":
                            mname, rname, t1, t2, t3, t4, t5 = fake_record.split(" ")
                            times = tuple([int(t) for t in [t1, t2, t3, t4, t5]])

                            if mname[-1] == ".": mname = mname[:-1]
                            if rname[-1] == ".": rname = rname[:-1]

                            response.add_answer(
                                RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](mname, rname, times)))

                        elif qtype == "NAPTR":
                            order, preference, flags, service, regexp, replacement = fake_record.split(" ")
                            order = int(order)
                            preference = int(preference)

                            if replacement and replacement[-1] == ".": replacement = replacement[:-1]

                            response.add_answer(RR(qname, getattr(QTYPE, qtype),
                                                   rdata=RDMAP[qtype](order, preference, flags, service, regexp,
                                                                      replacement)))

                        elif qtype == "SRV":
                            priority, weight, port, target = fake_record.split(" ")
                            priority = int(priority)
                            weight = int(weight)
                            port = int(port)
                            if target[-1] == ".": target = target[:-1]

                            response.add_answer(
                                RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](priority, weight, port, target)))

                        elif qtype == "DNSKEY":
                            flags, protocol, algorithm, key = fake_record.split(" ")
                            flags = int(flags)
                            protocol = int(protocol)
                            algorithm = int(algorithm)
                            key = base64.b64decode(("".join(key)).encode('ascii'))

                            response.add_answer(
                                RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](flags, protocol, algorithm, key)))

                        elif qtype == "RRSIG":
                            covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig = fake_record.split(
                                " ")
                            covered = getattr(QTYPE, covered)  # NOTE: Covered QTYPE
                            algorithm = int(algorithm)
                            labels = int(labels)
                            orig_ttl = int(orig_ttl)
                            sig_exp = int(time.mktime(time.strptime(sig_exp + 'GMT', "%Y%m%d%H%M%S%Z")))
                            sig_inc = int(time.mktime(time.strptime(sig_inc + 'GMT', "%Y%m%d%H%M%S%Z")))
                            key_tag = int(key_tag)
                            if name[-1] == '.': name = name[:-1]
                            sig = base64.b64decode(("".join(sig)).encode('ascii'))

                            response.add_answer(RR(qname, getattr(QTYPE, qtype),
                                                   rdata=RDMAP[qtype](covered, algorithm, labels, orig_ttl, sig_exp,
                                                                      sig_inc, key_tag, name, sig)))

                        else:
                            if fake_record[-1] == ".": fake_record = fake_record[:-1]
                            response.add_answer(RR(qname, getattr(QTYPE, qtype), rdata=RDMAP[qtype](fake_record)))

                response = response.pack()

            else:
                nameserver = random.choice(conf.nameserver).split("#")
                msg = "Using the nameserver %s" % nameserver[0]
                logger.info(msg)
                response = self.requestToDNSServer(data, *nameserver)

        return response

    def findNameToDNS(self, qname, nametodns):

        qname = qname.lower()

        qnamelist = qname.split(".")
        qnamelist.reverse()

        '''
        >>> d = {'a': 1, 'b': 2, 'c': 3}
        >>> d.items()
        dict_items([('a', 1), ('b', 2), ('c', 3)])
        >>> list(d.items())
        [('a', 1), ('b', 2), ('c', 3)]
        '''
        for domain, host in sorted(nametodns.items(), key=operator.itemgetter(1)):

            domain = domain.split(".")
            domain.reverse()

            if len(qnamelist) < len(domain):
                for i in range(len(domain) - len(qnamelist)):
                    qnamelist.append(None)
            else:
                for i in range(len(qnamelist) - len(domain)):
                    domain.append(None)

            for a, b in list(zip(qnamelist, domain)):
                if a != b and b != "*":
                    break
            else:
                return host
        else:
            return False

    def requestToDNSServer(self, request, host, port="53", protocol="udp"):
        reply = None
        '''
        $ host -t A baidu.com 127.0.0.1
        >>> dnslib.DNSRecord.parse(b'\xe0|\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00\x05baidu\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00r\x00\x04\xdc\xb59\xd9\xc0\x0c\x00\x01\x00\x01\x00\x00\x00r\x00\x04o\re\xd0\xc0\x0c\x00\x01\x00\x01\x00\x00\x00r\x00\x04{}r\x90\xc0\x0c\x00\x01\x00\x01\x00\x00\x00r\x00\x04\xb4\x95\x84/')
        <DNS Header: id=0xe07c type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=4 ns=0 ar=0>
        <DNS Question: 'baidu.com.' qtype=A qclass=IN>
        <DNS RR: 'baidu.com.' rtype=A rclass=IN ttl=114 rdata='220.181.57.217'>
        <DNS RR: 'baidu.com.' rtype=A rclass=IN ttl=114 rdata='111.13.101.208'>
        <DNS RR: 'baidu.com.' rtype=A rclass=IN ttl=114 rdata='123.125.114.144'>
        <DNS RR: 'baidu.com.' rtype=A rclass=IN ttl=114 rdata='180.149.132.47'>
        '''
        try:
            if self.server.ipv6:
                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)

            else:
                if protocol == "udp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                elif protocol == "tcp":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            sock.settimeout(3.0)

            if protocol == "udp":
                sock.sendto(request, (host, int(port)))
                reply = sock.recv(1024)
                sock.close()

            elif protocol == "tcp":
                print("asdsad")
                sock.connect((host, int(port)))
                length = binascii.unhexlify("%04x", len(request))
                sock.sendall(length + request)
                reply = sock.recv(1024)
                reply = reply[2:]
                sock.close()

        except Exception as e:
            errMsg = "Could not proxy request: %s" % e
            logger.error(errMsg)

        else:
            return reply


class ThreadedUDPHandler(DNSProxy, BaseRequestHandler):

    def handle(self):
        (data, socket) = self.request
        response = self.parse(data)

        if response:
            socket.sendto(response, self.client_address)


class ThreadedTCPHandler(DNSProxy, BaseRequestHandler):

    def handle(self):
        data = self.request.recv(1024)
        # Remove the addition "length" parameter used in the
        # TCP DNS protocol
        data = data[2:]
        response = self.parse(data)

        if response:
            # Calculate and add the additional "length" parameter
            # used in TCP DNS protocol
            length = binascii.unhexlify("%04x" % len(response))
            self.request.sendall(length + response)


class ThreadedUDPServer(ThreadingMixIn, UDPServer):

    def __init__(self, server_address, HandlerClass, nametodns, nameserver, ipv6):
        self.ipv6 = ipv6
        self.nametodns = nametodns
        self.nameserver = nameserver
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET

        UDPServer.__init__(self, server_address, HandlerClass)


class ThreadedTCPServer(ThreadingMixIn, TCPServer):

    def __init__(self, server_address, HandlerClass, nametodns, nameserver, ipv6):
        self.ipv6 = ipv6
        self.nametodns = nametodns
        self.nameserver = nameserver
        self.address_family = socket.AF_INET6 if self.ipv6 else socket.AF_INET

        TCPServer.__init__(self, server_address, HandlerClass)