#!/usr/bin/env python3
# coding: utf-8

import sys
import socket
import struct
import logging
import asyncio
import signal
from enum import Enum


class Operation(Enum):
    AUTH_DATA = 1
    AUTH_RESULT = 2
    CODE_DATA = 3
    CODE_RESULT = 4


class Server:
    def __init__(self, port: int, password: str):
        addr = ("", port)
        if socket.has_dualstack_ipv6():
            self._listener = socket.create_server(
                addr, family=socket.AF_INET6, dualstack_ipv6=True)
        else:
            self._listener = socket.create_server(addr)
        self._listener.setblocking(False)
        self._loop = asyncio.get_event_loop()
        self._connections = 0
        self._password = password

    def handle_connection(self):
        s, ep = self._loop.run_until_complete(
            self._loop.sock_accept(self._listener))
        logging.info(f"Client {ep} opened")
        self._loop.create_task(self._handle_connection_impl(s, ep))

    async def _handle_connection_impl(self, s: socket, ep):
        self._connections += 1
        try:
            password = await self.tlv_recv(s, Operation.AUTH_DATA)
            if self._password == password:
                await self.tlv_send(s, "Success", Operation.AUTH_RESULT)
            else:
                await self.tlv_send(s, "Failure", Operation.AUTH_RESULT)
                raise ValueError("bad password")
            code = await self.tlv_recv(s, Operation.CODE_DATA)
            result = eval(code)
            await self.tlv_send(s, str(result), Operation.CODE_RESULT)
            logging.info(f"Client {ep} closed gracefully")
        except Exception as e:
            logging.warning(f"Client {ep} closed forcefully: {e}")
        finally:
            self._connections -= 1
            s.close()

    async def tlv_send(self, s: socket, value: str, _type: Operation):
        data = value.encode()
        header = struct.pack(">II", _type.value, len(data))
        await self._loop.sock_sendall(s, header + data)

    async def sock_recvall(self, s: socket, _len: int) -> bytes:
        data = b""
        while len(data) < _len:
            data += await self._loop.sock_recv(s, _len - len(data))
        return data

    async def tlv_recv(self, s: socket, req_type: Operation) -> str:
        header = await self.sock_recvall(s, 8)
        (_type, _len) = struct.unpack(">II", header)
        _type = Operation(_type)
        data = await self.sock_recvall(s, _len)
        if _type != req_type:
            raise TypeError(
                f"Invalid packet type. Expected {req_type}, got {_type}")
        return data.decode()

    def __repr__(self):
        return f"Server instance with {self._connections} clients"


SERVER = None


def print_status(sig, frame):
    print(repr(SERVER))


def main():
    global SERVER
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) != 2:
        print("Usage: server.py <password>", file=sys.stderr)
        return
    SERVER = Server(1337, sys.argv[1])
    signal.signal(signal.SIGUSR1, print_status)
    logging.info("Server started")
    try:
        while True:
            SERVER.handle_connection()
    except KeyboardInterrupt:
        logging.info("Server finished")


if __name__ == "__main__":
    main()
