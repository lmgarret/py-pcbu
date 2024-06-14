import logging
import socketserver

import hass_pcbu.conf as conf
from hass_pcbu.unlock_service import UnlockService

LOGGER = logging.getLogger(__name__)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):

        unlock_service = UnlockService(conf.PC_PAIRINGS)

        while True:
            self.data = self.receive()

            if len(self.data) == 0:
                LOGGER.debug("Received empty packet, stopping")
                self.server.close_request(self.request)
                return

            data_str = self.data.decode()

            if data_str == "CLOSE":
                self.server.close_request(self.request)
                return
            else:
                ip_addr = self.client_address[0]
                response = unlock_service.unlock_response(self.data, ip_addr)
                LOGGER.info(f"Sending password to {ip_addr} to unlock")

                self.send(response)

    def receive(self) -> bytes:
        # wait for first packet giving payload size
        data = self.request.recv(1024).strip()
        if data == b"CLOSE":
            # for some commands, pcbu does not send the size first...
            return data
        ip_addr = self.client_address[0]
        LOGGER.debug(f"Received {len(data)} bytes from {ip_addr}")
        LOGGER.debug(data)
        payload_size = int.from_bytes(data)
        LOGGER.debug(f"Expecting next payload size of {payload_size} bytes")

        # return actual payload
        return self.request.recv(1024).strip()

    def send(self, data: bytes):
        # pcbu have this weird protocol where you send the bytes length before the payload
        self.request.sendall(len(data).to_bytes(2, "big"))
        self.request.sendall(data)

    def close(self):
        self.server.close_request(self.request)
