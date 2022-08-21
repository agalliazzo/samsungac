import datetime
import pprint
import socket
import struct
import time
from threading import Thread
import select


class SamsungDiscovery:
    MCAST_GRP = '239.255.255.250'
    MCAST_PORT = 1900
    MULTICAST_TTL = 5

    def __init__(self, mcast_grp='192.168.2.255', ttl=5):
        self.discovered_items = {}
        self.MCAST_GRP = mcast_grp
        self.MULTICAST_TTL = ttl
        self._recv_thread = Thread(target=self.receive)
        self._recv_thread.start()
        time.sleep(1)
        self.send_request()
        self.discovery_finished = False

    def send_request(self):
        data = b'''NOTIFY * HTTP/1.1\r
HOST: 239.255.255.250:1900\r
CACHE-CONTROL: max-age=20\r
SERVER: AIR CONDITIONER\r
\r
SPEC_VER: MSpec-1.00\r
SERVICE_NAME: ControlServer-MLib\r
MESSAGE_TYPE: CONTROLLER_START\r
'''
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.MULTICAST_TTL)
        sock.sendto(data, (self.MCAST_GRP, self.MCAST_PORT))

    def receive(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.MCAST_PORT))
        mreq = struct.pack("4sl", socket.inet_aton('239.255.255.250'), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        start_dt = datetime.datetime.now()

        sock.setblocking(False)
        while (datetime.datetime.now() - start_dt) < datetime.timedelta(seconds=5):
            ready = select.select([sock], [], [], 1)
            if ready[0]:
                msg = sock.recv(10240)
                msgs = msg.decode('utf-8').split('\r\n')
                properties = {}
                for m in msgs:
                    colon_pos = m.find(':')
                    key = m[:colon_pos].strip()
                    value = m[colon_pos+1:].strip()
                    properties[key] = value

                if 'SERVER' not in properties.keys():
                    continue

                if 'SAMSUNG-AC' in properties['SERVER']:
                    print("Found AC at %s with ID %s" % (properties['LOCATION'][7:], properties['MAC_ADDR']))
                    if properties['MAC_ADDR'] in self.discovered_items.keys():
                        continue
                    self.discovered_items[properties['MAC_ADDR']] = properties['LOCATION'][7:]
        self.discovery_finished = True
