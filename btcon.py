
import socket
import struct
import random
import hashlib
import errno

from gi.repository import GLib
from gi.repository import GObject

from bencode import bencode, bdecode, bdecode_all


class Bitfield(object):
    def __init__(self, size, data=None):
        if size < 0:
            raise ValueError('Bitfield size must be non-negative')
        self._size = size

        self._data = bytearray((size+7)//8)
        if data is not None:
            for i in range(self._size):
                bi = i // 8
                if ord(data[bi]) & (1 << (7 - (i % 8))):
                    self.set(i)

    def set(self, index):
        if index >= self._size or index < 0:
            raise IndexError('Invalid Bitfield index: %d' % index)
        bi = index // 8
        self._data[bi] |= 1 << (7 - (index % 8))

    def count(self):
        return sum(self)

    def __iter__(self):
        for i in range(self._size):
            bi = i // 8
            yield bool(self._data[bi] & (1 << (7 - (i % 8))))

    def __len__(self):
        return self._size

    def __repr__(self):
        return 'Bitfield(%d, %r)' % (self._size, ''.join(chr(x) for x in self._data))


class BTConnectionError(Exception):
    pass

class BTConnection(GObject.GObject):
    __gsignals__ = {
        'state-changed': (GObject.SIGNAL_RUN_LAST, None, (int,)),
        'metadata-changed': (GObject.SIGNAL_RUN_LAST, None, ()),
        'peer-progress-changed': (GObject.SIGNAL_RUN_LAST, None, ())
        }

    STATE_NOT_CONNECTED = 0
    STATE_HEADERS = 1
    STATE_EXT_HEADERS = 2
    STATE_RUNNING = 3
    STATE_CLOSED = 4

    HEADERS_LENGTH = 68

    BYTE_EXT_EXTENSION = 44
    BYTE_EXT_FAST_PEERS = 62

    MSG_TYPE_CHOKE = 0
    MSG_TYPE_UNCHOKE = 1
    MSG_TYPE_INTERESTED = 2
    MSG_TYPE_NOT_INTERESTED = 3
    MSG_TYPE_HAVE = 4
    MSG_TYPE_BITFIELD = 5
    MSG_TYPE_REQUEST = 6
    MSG_TYPE_PIECE = 7
    MSG_TYPE_CANCEL = 8

    MSG_TYPE_HAVE_ALL = 14
    MSG_TYPE_HAVE_NONE = 15

    MSG_TYPE_EXTENDED = 20

    def __init__(self, infohash, peer_id=None):
        super(BTConnection, self).__init__()

        self._infohash = infohash
        self._my_id = peer_id or ''.join(chr(random.randint(0, 255)) for i in range(20))
        self._my_exts = {1: 'ut_metadata'}

        self._metadata = None

        self._ut_metadata_size = None
        self._ut_metadata_buffer = ''
        self._ut_metadata_last_req = None

        self._peer_id = None
        self._peer_byte_exts = set()
        self._peer_exts = {}

        self._peer_have = None
        self._peer_have_queue = []

        self._packet_len = None
        self._packet = ''
        self._packet_timeout = None
        self._packet_callback = None

        self._msg_len = None
        self._msg_callback = None

        self._socket = None
        self._socket_queue = []

        self._state = self.STATE_NOT_CONNECTED

        self._input_source = None
        self._output_source = None
        self._connect_source = None
        self._hangup_source = None

    def open(self, address):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setblocking(0)
        self._socket.bind(('', 0))

        self._connect_source = GLib.io_add_watch(self._socket, GLib.IO_OUT, self._socket_connect_cb)
        self._hangup_source = GLib.io_add_watch(self._socket, GLib.IO_HUP, self._socket_hangup_cb)

        self._packet_expect_input(self.HEADERS_LENGTH, self._handle_headers, 30)
        err = self._socket.connect_ex(address)
        if err not in (0, errno.EINPROGRESS):
            raise BTConnectionError('Unable to connect: {}'.format(errno.errorcode[err]))

        self._send_headers()
        self._change_state(self.STATE_HEADERS)

    def close(self):
        self._close_sources()
        self._socket.close()
        self._change_state(self.STATE_CLOSED)
        print('Closed')

    @property
    def metadata(self):
        return self._metadata

    @property
    def peer_progress(self):
        if self._peer_have is None:
            return None
        return self._peer_have.count()

    @property
    def piece_count(self):
        if self._metadata is None:
            return None
        return (self.data_length + self._metadata['piece length'] - 1) // self._metadata['piece length']

    @property
    def data_length(self):
        if self._metadata is None:
            return None

        if 'files' in self._metadata:
            return sum(f['length'] for f in self._metadata['files'])
        else:
            return self._metadata['length']

    def _change_state(self, state):
        self._state = state
        self.emit('state-changed', self._state)

    def _close_sources(self):
        for source in (self._hangup_source, self._connect_source,
                       self._input_source, self._output_source,
                       self._packet_timeout):
            if source is not None:
                GLib.source_remove(source)

    def _socket_connect_cb(self, source, cond):
        err = self._socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            print 'Unable to connect: {}'.format(errno.errorcode[err])
            self.close()
        return False

    def _socket_hangup_cb(self, source, cond):
        print('Hangup')
        self.close()
        return False

    def _socket_input_cb(self, source, cond):
        self._packet += self._socket.recv(self._packet_len-len(self._packet))
        if len(self._packet) == self._packet_len:
            GLib.source_remove(self._packet_timeout)
            packet = self._packet
            self._packet = ''
            self._packet_callback(packet)
            return False
        return True

    def _socket_output_cb(self, source, cond):
        while len(self._socket_queue) > 0:
            packet = self._socket_queue[0]
            n = self._socket.send(packet)
            if n < len(packet):
                self._socket_queue[0] = packet[n:]
                return True
            else:
                self._socket_queue.pop(0)
        return False

    def _packet_timeout_cb(self):
        print('No activity')
        self.close()
        return False

    def _packet_expect_input(self, length, callback, timeout):
        self._packet_len = length
        self._packet_callback = callback
        self._packet_timeout = GLib.timeout_add_seconds(timeout, self._packet_timeout_cb)
        self._input_source = GLib.io_add_watch(self._socket, GLib.IO_IN, self._socket_input_cb)

    def _packet_send(self, packet):
        self._socket_queue.append(packet)
        if len(self._socket_queue) == 1:
            GLib.io_add_watch(self._socket, GLib.IO_OUT, self._socket_output_cb)

    def _send_headers(self):
        bt_header = chr(19) + 'BitTorrent protocol'
        ext_bytes = '\x00\x00\x00\x00\x00\x10\x00\x04'
        self._packet_send(bt_header + ext_bytes + self._infohash + self._my_id)

    def _send_message(self, msg):
        msg_len = struct.pack('>L', len(msg))
        self._packet_send(msg_len + msg)

    def _send_ext_headers(self):
        msg = chr(20) + chr(0) + bencode({'m': dict((v, k) for k, v in self._my_exts.iteritems())})
        self._send_message(msg)

    def _send_initial_have(self):
        if self.BYTE_EXT_FAST_PEERS in self._peer_byte_exts:
            msg = chr(self.MSG_TYPE_HAVE_NONE)
            self._send_message(msg)

    def _ut_metadata_send_request(self, piece):
        ext_id = self._peer_exts['ut_metadata']
        msg = chr(20) + chr(ext_id) + bencode({'msg_type': 0, 'piece': piece})
        self._ut_metadata_last_req = piece
        self._send_message(msg)

    def _ut_metadata_validate(self):
        def validate_files_list(files):
            if len(files) == 0:
                return False

            for f in files:
                if not (type(f) is dict and
                        'length' in f and type(f['length']) is int and
                        'path' in f and type(f['path']) is list and
                        len(f['path']) > 0 and all(f['path'])):
                    return False
            return True

        if hashlib.sha1(self._ut_metadata_buffer).digest() == self._infohash:
            info_dict = bdecode(self._ut_metadata_buffer)
            if ('name' in info_dict and type(info_dict['name']) is str and
                'piece length' in info_dict and type(info_dict['piece length']) is int and
                'pieces' in info_dict and type(info_dict['pieces']) is str and
                (('length' in info_dict and type(info_dict['length']) is int) or
                 ('files' in info_dict and type(info_dict['files']) is list and
                  validate_files_list(info_dict['files'])))):
                self._ut_metadata_buffer = None

                self._metadata = info_dict
                if len(self._metadata['pieces']) != 20*self.piece_count:
                    self._metadata = None
                    return False

                self.emit('metadata-changed')

                self._play_have_queue()
                return True

        return False

    def _handle_headers(self, packet):
        bt_header_len, packet = ord(packet[:1]), packet[1:]
        if bt_header_len != 19:
            self.close()
            return

        bt_header, packet = packet[:bt_header_len], packet[bt_header_len:]
        if bt_header != 'BitTorrent protocol':
            self.close()
            return

        print('Connected to {!r}'.format(self._socket.getpeername()))

        ext_bytes, packet = packet[:8], packet[8:]
        print('Extension bytes {!r}'.format(ext_bytes))

        if ord(ext_bytes[7]) & 0x4:
            self._peer_byte_exts.add(self.BYTE_EXT_FAST_PEERS)
        if ord(ext_bytes[5]) & 0x10:
            self._peer_byte_exts.add(self.BYTE_EXT_EXTENSION)

        infohash, packet = packet[:20], packet[20:]
        if infohash != self._infohash:
            self.close()
            return

        self._peer_id = packet[:20]
        print('Peer id {!r}'.format(self._peer_id))

        if self.BYTE_EXT_EXTENSION in self._peer_byte_exts:
            self._change_state(self.STATE_EXT_HEADERS)
            self._msg_callback = self._handle_ext_headers

            self._send_ext_headers()
        else:
            self._change_state(self.STATE_RUNNING)
            self._msg_callback = self._handle_message

            self._send_initial_have()

        self._packet_expect_input(4, self._handle_message_input, 240)

    def _handle_message_input(self, packet):
        if self._msg_len is None:
            self._msg_len = struct.unpack('>L', packet)[0]

            if self._msg_len == 0:
                self._msg_len = None
                self._packet_expect_input(4, self._handle_message_input, 240)

                if self._msg_len > 64*1024*1024:
                    self.close()
                    return
            else:
                self._packet_expect_input(self._msg_len, self._handle_message_input, 60)
        else:
            self._msg_callback(packet)
            self._msg_len = None
            self._packet_expect_input(4, self._handle_message_input, 240)

    def _handle_ext_headers(self, msg):
        msg_type, msg = ord(msg[:1]), msg[1:]
        if msg_type != self.MSG_TYPE_EXTENDED or len(msg) < 2:
            self.close()
            return

        msg_ext_type, msg = ord(msg[:1]), msg[1:]
        if msg_ext_type != 0:
            self.close()
            return

        msg = bdecode(msg)
        print('Extended handshake: {!r}'.format(msg))

        if 'm' in msg and type(msg['m']) is dict:
            for ext, ext_id in msg['m'].iteritems():
                self._peer_exts[ext] = ext_id

        if 'metadata_size' in msg and type(msg['metadata_size']) is int:
            self._ut_metadata_size = msg['metadata_size']

        self._change_state(self.STATE_RUNNING)
        self._msg_callback = self._handle_message

        self._send_initial_have()
        if self._peer_exts.get('ut_metadata', 0) > 0:
            self._ut_metadata_send_request(0)

    def _play_have_queue(self):
        if len(self._peer_have_queue) > 0:
            msg_type, msg = self._peer_have_queue.pop(0)
            self._handle_first_have_message(msg_type, msg)

        while len(self._peer_have_queue) > 0:
            msg_type, msg = self._peer_have_queue.pop(0)
            self._handle_have_message(msg_type, msg)

    def _handle_first_have_message(self, msg_type, msg):
        def handle_bitfield(msg):
            if 8*len(msg) < self.piece_count:
                self.close()
                return

            self._peer_have = Bitfield(self.piece_count, msg)

        def handle_have_all():
            self._peer_have = Bitfield(self.piece_count)
            for i in range(len(self._peer_have)):
                self._peer_have.set(i)

        def handle_have_none():
            self._peer_have = Bitfield(self.piece_count)

        if msg_type == self.MSG_TYPE_BITFIELD:
            handle_bitfield(msg)
        elif msg_type == self.MSG_TYPE_HAVE_ALL:
            handle_have_all()
        elif msg_type == self.MSG_TYPE_HAVE_NONE:
            handle_have_none()
        elif (msg_type == self.MSG_TYPE_HAVE and
              not self.BYTE_EXT_FAST_PEERS in self._peer_byte_exts):
            self._peer_have = Bitfield(self.piece_count)
            self._handle_have_message(msg_type, msg)
        else:
            self.close()
            return

        self.emit('peer-progress-changed')

    def _handle_have_message(self, msg_type, msg):
        if msg_type == self.MSG_TYPE_HAVE:
            index = struct.unpack('>L', msg)[0]
            self._peer_have.set(index)
        else:
            self.close()
            return

        self.emit('peer-progress-changed')

    def _handle_message(self, msg):
        msg_type, msg = ord(msg[:1]), msg[1:]

        def print_message():
            print('Message: {}, {!r}'.format(msg_type, msg))

        if ((msg_type == self.MSG_TYPE_HAVE and len(msg) == 4) or
            (msg_type == self.MSG_TYPE_HAVE_ALL and len(msg) == 1) or
            (msg_type == self.MSG_TYPE_HAVE_NONE and len(msg) == 1) or
            msg_type == self.MSG_TYPE_BITFIELD):
            if self.piece_count is None:
                self._peer_have_queue.append((msg_type, msg))
            elif self._peer_have is None:
                self._handle_first_have_message(msg_type, msg)
            else:
                self._handle_have_message(msg_type, msg)
        elif msg_type == self.MSG_TYPE_EXTENDED:
            if len(msg) < 1:
                self.close()
                return

            msg_ext_id, msg = ord(msg[:1]), msg[1:]
            if msg_ext_id > 0 and msg_ext_id in self._my_exts:
                msg_ext = self._my_exts[msg_ext_id]
                if msg_ext == 'ut_metadata':
                    msg, rest = bdecode_all(msg)

                    total_pieces = (self._ut_metadata_size + (2**14-1)) / (2**14)
                    last_piece_size = self._ut_metadata_size - (2**14)*(total_pieces-1)

                    if 'msg_type' in msg and type(msg['msg_type']) is int:
                        if msg['msg_type'] == 0:
                            pass
                        elif msg['msg_type'] == 1:
                            if ('piece' in msg and type(msg['piece']) is int and
                                msg['piece'] == self._ut_metadata_last_req and
                                ((msg['piece'] < total_pieces - 1 and
                                  len(rest) == 2**14) or
                                 (msg['piece'] == total_pieces - 1 and
                                  len(rest) == last_piece_size))):
                                self._ut_metadata_buffer += rest

                                print('Metadata download: {}%'.format(int(100*float(self._ut_metadata_last_req+1)/total_pieces)))

                                if msg['piece'] == total_pieces - 1:
                                    self._ut_metadata_last_req = None
                                    self._ut_metadata_validate()
                                else:
                                    self._ut_metadata_send_request(self._ut_metadata_last_req+1)
                        elif msg['msg_type'] == 2:
                            pass
                else:
                    self.close()
                    return
            elif msg_ext_id == 0:
                print_message()
            else:
                self.close()
                return
        else:
            print_message()
