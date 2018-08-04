# coding=utf-8
"""
    remote server
    Run a TCP server to proxy tcp traffic from LOCAL SERVER.
    Assume that the first few bytes are `header` that carrying target address info and parse the target from it.
    Once the target server was known and connection established, do that traffic relay as we do in local_server
"""

import logging
import platform
import socket
import struct
from socketserver import ThreadingTCPServer, StreamRequestHandler

# SERVER_ADDRESS = "104.153.102.152"
import select

SERVER_ADDRESS = ''
SERVER_PORT = 9988

SOCKS_ATYP_IPV4 = 0x01
SOCKS_ATYP_DOMAINNAME = 0x03
SOCKS_ATYP_IPV6 = 0x04

HEADER = b'header'

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Handler(StreamRequestHandler):
    def handle(self):
        remote = self.issue_connection()
        if not remote:
            logger.warning("fail to issue connection")
            self.server.close_request(self.request)
            return

        self.data_loop(self.request, remote)
        self.server.close_request(self.request)

    def data_loop(self, local: socket.socket, remote: socket.socket):
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

    def issue_connection(self):

        header = self.connection.recv(len(HEADER))
        if len(header) != len(HEADER) or header != HEADER:
            logger.warning("header not match, quit")
            return None

        atyp = self.connection.recv(1)[0]
        dst_addr_len = self.connection.recv(1)[0]
        dst_addr = self.connection.recv(dst_addr_len)

        if atyp == SOCKS_ATYP_DOMAINNAME:
            dst_addr = dst_addr
        else:
            dst_addr = socket.inet_ntoa(dst_addr)

        dst_port = struct.unpack("!H", self.connection.recv(2))[0]

        logger.warning("issued remote: {0}, {1}".format(dst_addr, dst_port))
        try:
            remote = socket.socket()
            remote.connect((dst_addr, dst_port))
        except:
            logger.warning(
                "establishing remote connection error: fail to connect to {0}, {1}".format(dst_addr, dst_port))
            return None
        else:
            return remote


def start_server():
    if platform.python_version_tuple()[0] == '3' and int(platform.python_version_tuple()[1]) >= 6:
        with ThreadingTCPServer((SERVER_ADDRESS, SERVER_PORT), Handler, bind_and_activate=False) as server:
            server.allow_reuse_address = True
            server.server_bind()
            server.server_activate()
            server.serve_forever()
    else:
        server = ThreadingTCPServer((SERVER_ADDRESS, SERVER_PORT), Handler, bind_and_activate=False)
        server.allow_reuse_address = True
        server.server_bind()
        server.server_activate()
        server.serve_forever()
        server.server_close()


if __name__ == '__main__':
    start_server()
