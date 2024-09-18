import logging
from socket import socket

LOGGER = logging.getLogger(__name__)


def _readnbytes(sock: socket, n) -> bytes:
    """Allows reading exactly n bytes from the socket"""
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            return b""
        pos += cr
    return bytes(buff)


def receive(sock: socket) -> bytes:
    """Application level read function. Reads the packet's length first, then read exactly the packet's size."""
    # wait for first packet giving payload size
    data = _readnbytes(sock, 2)
    # if data == b"CLOSE":
    #     # for some commands, pcbu does not send the size first
    #     return data
    # LOGGER.debug(f"Received {len(data)} bytes")
    payload_size = int.from_bytes(data, byteorder="big")

    if payload_size == 0:
        LOGGER.debug("Empty packet received")
        return b""

    LOGGER.debug(f"Expecting next payload size of {payload_size} bytes")

    # return actual payload
    return _readnbytes(sock, payload_size)


def send(sock: socket, data: bytes):
    """Application level write function. Sends the packet's length first, then the packet."""
    # pcbu's protocol requires to send the bytes length before the payload
    sock.sendall(len(data).to_bytes(2, "big"))
    sock.sendall(data)
