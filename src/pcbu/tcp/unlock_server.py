from collections.abc import Callable
import json
import logging
import socketserver
import threading
import time
from contextlib import ContextDecorator, ExitStack
from typing import Optional, Tuple

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import PCPairing, PCPairingFull

LOGGER = logging.getLogger(__name__)

UnlockHandler = Callable[[PCPairing], bool]


class TCPUnlockServer(ContextDecorator):
    def __init__(
        self,
        paired_pcs: list[PCPairingFull],
        port: int = 43298,
        unlock_handler: Optional[UnlockHandler] = None,
    ) -> None:
        super().__init__()
        self.port = port
        self.paired_pcs = paired_pcs
        self.servers_contexts_stack = ExitStack()
        self.tcp_servers: list[socketserver.TCPServer] = []
        self.closed = False
        self.unlock_handler: Optional[UnlockHandler] = unlock_handler

    def __enter__(self):
        self.servers_contexts_stack.__enter__()
        LOGGER.info("Starting TCPUnlockServer...")

        # group pairs per ip addresses
        pairs_per_ip: dict[str, list[PCPairingFull]] = {}
        for pair in self.paired_pcs:
            if pair.server_ip_address not in pairs_per_ip:
                pairs_per_ip[pair.server_ip_address] = []
            pairs_per_ip[pair.server_ip_address].append(pair)

        # for each server ip address, create a TCP server
        LOGGER.info("TCPUnlockServer will listen on:")
        for server_ip, pairs in pairs_per_ip.items():
            tcp_server = CustomTCPServer(
                (server_ip, self.port),
                unlock_handler=self.unlock_handler,
                paired_pcs=pairs,
            )
            self.tcp_servers.append(tcp_server)
            self.servers_contexts_stack.enter_context(tcp_server)
            LOGGER.info(f" - {server_ip}:{self.port}")

        return self

    def listen(self):
        if not self.tcp_servers:
            raise ValueError(
                "TCP Servers was not initialized. Did you open the context using `with`?"
            )
        if self.unlock_handler is None:
            LOGGER.warn(
                "Unlock server has no handler registered: it will accept all (authenticated) unlock requests."
            )
        for tcp_server in self.tcp_servers:
            server_thread = threading.Thread(target=tcp_server.serve_forever)
            # Exit the server thread when the main thread terminates
            server_thread.daemon = True
            server_thread.start()
            LOGGER.debug(f"Server loop running in thread '{server_thread.name}'")
        LOGGER.info("TCPUnlockServer started listening for unlock requests")
        while not self.closed:
            time.sleep(1)

    def register_unlock_handler(self, unlock_handler):
        self.unlock_handler = unlock_handler

    def __exit__(self, *exc):
        self.closed = True
        self.servers_contexts_stack.close()
        LOGGER.info("TCPUnlockServer closed.")
        return False


class CustomTCPServer(socketserver.TCPServer):
    def __init__(
        self,
        server_address,
        paired_pcs: list[PCPairingFull],
        unlock_handler: Optional[UnlockHandler],
    ) -> None:
        super().__init__(
            server_address,
            lambda *args, **kwargs: TCPHandler(
                # pass only the pairs for the given server ip address
                paired_pcs=paired_pcs,
                unlock_handler=unlock_handler,
                *args,
                **kwargs,
            ),
        )


class TCPHandler(socketserver.BaseRequestHandler):
    def __init__(
        self,
        request,
        client_address,
        tcp_server,
        paired_pcs: list[PCPairingFull],
        unlock_handler: Optional[UnlockHandler],
    ) -> None:
        self.paired_pcs = paired_pcs
        self.unlock_handler = unlock_handler
        super().__init__(request, client_address, tcp_server)

    def handle(self):
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
                pair, unlock_token = self.get_matching_pair(self.data, ip_addr)
                if pair is None or unlock_token is None:
                    # no match, continue listening
                    LOGGER.debug(
                        f"Client listening to {self.server.server_address} found no pair found for desktop at {ip_addr}, ignoring."
                    )
                    continue

                response = self.unlock_response(pair, unlock_token)
                unlock = False
                if self.unlock_handler is None:
                    LOGGER.info(
                        "Unlock server has no handler registered: accepting (authenticated) unlock request."
                    )
                    unlock = True
                else:
                    pair_lite = PCPairing(
                        pairing_id=pair.pairing_id,
                        desktop_ip_address=pair.desktop_ip_address,
                        server_ip_address=pair.server_ip_address,
                    )
                    unlock = self.unlock_handler(pair_lite)

                if unlock:
                    LOGGER.info(f"Sending password to {ip_addr} to unlock")
                    self.send(response)
                else:
                    LOGGER.info("Unlock handler returned false, denying unlock request")
                    # TODO send correct payload to deny unlocking
                    self.send(b"\0x")

    def _clean_hex_str(self, s: str) -> str:
        return s.replace("\u0000", "").replace("\x00", "")

    def _decrypt_enc_data(self, enc_data: str, enc_key: str) -> dict:
        enc_data = self._clean_hex_str(enc_data)

        decrypted = decrypt_aes(bytes.fromhex(enc_data), enc_key)

        return json.loads(decrypted.decode())

    def get_matching_pair(
        self, data: bytes, desktop_ip_address: str
    ) -> Tuple[Optional[PCPairingFull], Optional[str]]:
        req_dict = json.loads(data.decode())
        pairing_id = req_dict["pairingId"]

        for pair in self.paired_pcs:
            if pairing_id == pair.pairing_id:
                try:
                    enc_data = self._decrypt_enc_data(
                        req_dict["encData"], pair.encryption_key
                    )
                except Exception as e:
                    raise ValueError(
                        f"Could not decrypt encData from unlock request: {e}"
                    ) from e
                auth_user = enc_data["authUser"]

                if (
                    desktop_ip_address == pair.desktop_ip_address
                    and auth_user == pair.username
                ):
                    LOGGER.info(
                        f"Found matching PC for request from {desktop_ip_address}"
                    )
                    return pair, enc_data["unlockToken"]
        return None, None

    def unlock_response(self, pair: PCPairingFull, unlock_token: str) -> bytes:
        response_dict = {
            "unlockToken": unlock_token,
            "password": pair.password,
        }
        return encrypt_aes(json.dumps(response_dict).encode(), pair.encryption_key)

    def receive(self) -> bytes:
        # wait for first packet giving payload size
        data = self.request.recv(1024).strip()
        if data == b"CLOSE":
            # for some commands, pcbu does not send the size first...
            return data
        ip_addr = self.client_address[0]
        LOGGER.debug(f"Received {len(data)} bytes from {ip_addr}")
        payload_size = int.from_bytes(data, byteorder="big")
        LOGGER.debug(f"Expecting next payload size of {payload_size} bytes")

        # return actual payload
        return self.request.recv(1024).strip()

    def send(self, data: bytes):
        # pcbu have this weird protocol where you send the bytes length before the payload
        self.request.sendall(len(data).to_bytes(2, "big"))
        self.request.sendall(data)

    def close(self):
        self.server.close_request(self.request)
