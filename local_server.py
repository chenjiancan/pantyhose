# coding=utf-8
"""
    local_server
    Run a SOCKs proxy server that support SOCKS5(ref. RFC1928)
    On the one hand, serve local tcp coming connection via SOCKS, name the socket LOCAL;
    on the other hand, connection to a REMOTE tcp server serve at (SERVER_ADDRESS, SERVER_PORT), name the socket REMOTE.
    As soon as the SOCKS negotiation done, real traffic data follows, function `data_loop` relay one's incoming stream
    bytes to another's input

"""

import platform
import socket
import struct
from socketserver import ThreadingTCPServer, StreamRequestHandler
import logging

import select

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

LOCAL_PORT = 9011

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 9988

# SOCKS5
SOCKS_VERSION = 0x05
SOCKS_METHOD_NO_AUTH = 0x00

SOCKS_CMD_CONNECT = 0x01
# BIND X'02'
# UDP ASSOCIATE X'03'
SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAINNAME = 0x03
SOCKS_ATYP_IPV6 = 0x04


HEADER = 'header'

class Handler(StreamRequestHandler):
    """
    handle LOCAL socks request and relay traffic to REMOTE
    """

    def handle(self):
        logger.debug("accept request from: {0}:{1}".format(*self.client_address))

        remote = self.handle_socks()
        if not remote:
            self.server.close_request(self.request)
            return

        # data traffic loop
        self.data_loop(self.connection, remote)
        self.server.close_request(self.request)

    def data_loop(self, local:socket.socket, remote:socket.socket):
        selector_set = [local, remote]
        while True:
            try:
                r, _, _ = select.select(selector_set, [], [])
                if local in r:
                    data = local.recv(4096)
                    if len(data) <= 0:
                        break
                    remote.sendall(data)

                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    local.sendall(data)
            except Exception as e:
                logger.error("exception in data_loop: " + e)
                break

        remote.close()

    def issue_remote_connect(self, dst_addr, dst_port, atyp=SOCKS_ATYP_IPV4):
        try:
            remote_sock = socket.socket()
            remote_sock.connect((SERVER_ADDRESS, SERVER_PORT))  # connect to remote server

            dst_addr_len = len(dst_addr)
            issue_header = HEADER.encode() + struct.pack("!BB{0}sH".format(dst_addr_len), atyp, dst_addr_len, dst_addr, dst_port)
            remote_sock.sendall(issue_header)
        except:
            logger.warning("connect remote fail")
            return None
        else:
            return remote_sock

    def handle_socks(self):
        """
        handle local socks protocol
        :return:
        """
        """
        The client connects to the server, and sends a version
        identifier/method selection message:

                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+
        """
        methed_msg = self.connection.recv(1 + 1 + 255)
        if len(methed_msg) < 3 or methed_msg[0] != SOCKS_VERSION:
            logger.warning("request not match SOCK5 protocol, pass")
            return

        methed_count = methed_msg[1]
        method_list = [m for i, m in enumerate(methed_msg[2:]) if i < methed_count]
        logger.debug("client support method: {}".format(method_list))

        if SOCKS_METHOD_NO_AUTH not in method_list:
            logger.warning("client dont support AUTH Free method, quit")
            return

        """
        The server selects from one of the methods given in METHODS, and
        sends a METHOD selection message:

                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+
        """
        self.connection.sendall(b'\x05\x00')  # METHOD selection reply

        """
           The SOCKS request is formed as follows:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        """
        socks_req = self.connection.recv(4)
        if len(socks_req) != 4:
            logger.warning("SOCKS request message error")
            return

        ver, cmd, _, atyp = socks_req
        if ver != SOCKS_VERSION or cmd != SOCKS_CMD_CONNECT:
            return

        dst_addr = None
        if atyp == SOCKS_ATYP_IPV4:
            dst_addr = self.connection.recv(4)
            dst_addr = socket.inet_ntoa(dst_addr)
        elif atyp == SOCKS_ATYP_DOMAINNAME:
            dst_addr_len = self.connection.recv(1)[0]
            dst_addr = self.connection.recv(dst_addr_len)
        elif atyp == SOCKS_ATYP_IPV6:
            logger.warning("SOCKS_ATYP_IPV6 not support")
            return

        dst_port = self.connection.recv(2)
        dst_port = struct.unpack("!H", dst_port)[0]

        """
        The server evaluates the request, and
        returns a reply formed as follows:
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+
        """
        remote_sock = self.issue_remote_connect(dst_addr, dst_port, atyp=atyp)
        if not remote_sock:
            reply = struct.pack("!BBBB", SOCKS_VERSION, 1, 0, SOCKS_ATYP_IPV4)
        else:
            bind_addr, bind_port = remote_sock.getsockname()
            bind_addr = socket.inet_aton(bind_addr)
            reply = struct.pack("!BBBB{}sH".format(len(bind_addr)), SOCKS_VERSION, 0, 0, SOCKS_ATYP_IPV4, bind_addr,
                                bind_port)
            logger.debug("socks5 negotiation done! {0} {1} -> {2} {3}".format(self.client_address[0], self.client_address[1]
                                                                          , dst_addr, dst_port))
        self.connection.sendall(reply)

        return remote_sock


def start_server():
    if platform.python_version_tuple()[0] == '3' and int(platform.python_version_tuple()[1]) >= 6:
        with ThreadingTCPServer(('127.0.0.1', LOCAL_PORT), Handler, bind_and_activate=False) as server:
            server.allow_reuse_address = True
            server.server_bind()
            server.server_activate()
            server.serve_forever()
    else:
        server = ThreadingTCPServer(('127.0.0.1', LOCAL_PORT), Handler, bind_and_activate=False)
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
        server.serve_forever()
        server.server_close()


if __name__ == '__main__':
    start_server()
