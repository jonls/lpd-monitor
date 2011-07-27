# BitTorrent Local Peer Discovery
# as implemented by uTorrent et al.

import socket
import struct

class MulticastUDPSocket(socket.socket):
    def __init__(self, local_port, reuse=False):
        socket.socket.__init__(self, socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        if reuse:
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, 'SO_REUSEPORT'):
                self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.bind(('', local_port))

    def mcast_add(self, addr):
	mreq = struct.pack('=4sl', socket.inet_aton(addr), socket.INADDR_ANY)
        self.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

class LPDSocket(MulticastUDPSocket):
    ADDRESS = '239.192.152.143'
    PORT = 6771

    def __init__(self):
        super(LPDSocket, self).__init__(LPDSocket.PORT)
        self.mcast_add(LPDSocket.ADDRESS)

    def send_announce(self, infohash, port):
        msg = ('BT-SEARCH * HTTP/1.1\r\n' +
               'Host: {}:{}\r\n' +
               'Port: {}\r\n' +
               'Infohash: {}\r\n' +
               '\r\n\r\n').format(LPDSocket.ADDRESS, LPDSocket.PORT, port, infohash)
        self.sendto(msg, 0, (LPDSocket.ADDRESS, LPDSocket.PORT))

    def recv_announce(self):
        data, sender = self.recvfrom(1280)

        lines = data.split('\r\n')
        if lines[0] != 'BT-SEARCH * HTTP/1.1':
            return None, sender

        port = None
        infohash = None
        for line in lines[1:]:
            p = line.split(':', 1)
            if len(p) < 2:
                continue
            name, value = p[0].rstrip(), p[1].strip()

            if name == 'Port':
                try:
                    port = int(value)
                except ValueError:
                    return None, sender
            elif name == 'Infohash':
                infohash = value

        if port is None or infohash is None:
            return None, sender

        return (infohash, port), sender
