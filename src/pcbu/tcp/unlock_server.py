from abc import ABCMeta, abstractmethod

from collections.abc import Callable
import asyncio
import json
import logging
import socketserver
import threading
import time
from contextlib import ContextDecorator, ExitStack
from typing import Optional, Tuple

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import PCPairing, PCPairingSecret
from pcbu.tcp.common import receive, send

LOGGER = logging.getLogger(__name__)
UnlockHandler = Callable[[PCPairing], bool]
ErrorUnlockHandler = Callable[[str], None]


class TCPUnlockServerBase(ContextDecorator, metaclass=ABCMeta):
    def __init__(
        self,
        pc_pairings: list[PCPairingSecret],
        port: int = 43298,
    ) -> None:
        super().__init__()
        self.port = port
        self.pc_pairings = pc_pairings
        self.servers_contexts_stack = ExitStack()
        self.tcp_servers: list[CustomTCPServer] = []
        self.closed = False

    def on_enter(self) -> bool:
        """Method called whenever the server's context is entered.
        Can be overridden by the user."""
        pass

    def on_listen(
        self, ip_address: str, port: int, pc_pairings: list[PCPairing]
    ) -> bool:
        """Method called whenever the server's context is entered.
        Can be overridden by the user."""
        pass

    @abstractmethod
    def on_valid_unlock_request(self, pairing: PCPairing) -> bool:
        """Method called whenever an unlock request has been received and authenticated.
        The return boolean determines whether the password should be sent (encrypted) to the desktop
        to unlock it."""
        pass

    def on_invalid_unlock_request(self, ip_address: str) -> None:
        """Method called whenever an unlock request has been received and is deemed invalid.
        This can happen if:
         - the requesting ip address is unknown in all the PCPairs
         - the received payload could not be decrypted (invalid encryption key, wrong AES timestamp...)

        Can be overridden by the user.
        """
        pass

    def on_exit(self) -> bool:
        """Method called whenever the server's context is exited. Can be overriden by user"""
        pass

    def __enter__(self):
        self.servers_contexts_stack.__enter__()
        LOGGER.info("Starting TCPUnlockServer...")

        # group pairs per ip addresses
        pairs_per_ip: dict[str, list[PCPairingSecret]] = {}
        for pairing in self.pc_pairings:
            if pairing.server_ip_address not in pairs_per_ip:
                pairs_per_ip[pairing.server_ip_address] = []
            pairs_per_ip[pairing.server_ip_address].append(pairing)

        # for each server ip address, create a TCP server
        LOGGER.info("TCPUnlockServer will listen on:")
        for server_ip, pairs in pairs_per_ip.items():
            tcp_server = CustomTCPServer(
                (server_ip, self.port),
                unlock_handler=self.on_valid_unlock_request,
                error_unlock_handler=self.on_invalid_unlock_request,
                pc_pairings=pairs,
            )
            self.tcp_servers.append(tcp_server)
            self.servers_contexts_stack.enter_context(tcp_server)
            LOGGER.info(f" - {server_ip}:{self.port}")

        self.on_enter()
        return self

    def _listen(self):
        if not self.tcp_servers:
            raise ValueError(
                "TCP Servers was not initialized. Did you open the context using `with`?"
            )

        for tcp_server in self.tcp_servers:
            server_thread = threading.Thread(target=tcp_server.serve_forever)
            # Exit the server thread when the main thread terminates
            server_thread.daemon = True
            server_thread.start()
            self.on_listen(
                tcp_server.ip_address,
                tcp_server.port,
                [p.mask() for p in tcp_server.pc_pairings],
            )
            LOGGER.debug(f"Server loop running in thread '{server_thread.name}'")
        LOGGER.info("TCPUnlockServer started listening for unlock requests")

    def listen(self):
        self._listen()
        while not self.closed:
            time.sleep(1)

    async def async_listen(self):
        self._listen()
        while not self.closed:
            await asyncio.sleep(1)
        LOGGER.info("TCPUnlockServer closed.")

    def register_unlock_handler(self, unlock_handler):
        self.unlock_handler = unlock_handler

    def __exit__(self, *exc):
        self.on_exit()
        self.closed = True
        self.servers_contexts_stack.close()
        LOGGER.info("TCPUnlockServer closed.")

        return False


class CustomTCPServer(socketserver.TCPServer):
    def __init__(
        self,
        server_address,
        pc_pairings: list[PCPairingSecret],
        unlock_handler: UnlockHandler,
        error_unlock_handler: ErrorUnlockHandler,
    ) -> None:
        self.ip_address = server_address[0]
        self.port = server_address[1]
        self.pc_pairings = pc_pairings
        super().__init__(
            server_address,
            lambda *args, **kwargs: TCPHandler(
                # pass only the pairs for the given server ip address
                pc_pairings=pc_pairings,
                unlock_handler=unlock_handler,
                error_unlock_handler=error_unlock_handler,
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
        pc_pairings: list[PCPairingSecret],
        unlock_handler: UnlockHandler,
        error_unlock_handler: ErrorUnlockHandler,
    ) -> None:
        self.pc_pairings = pc_pairings
        self.unlock_handler = unlock_handler
        self.error_unlock_handler = error_unlock_handler
        super().__init__(request, client_address, tcp_server)

    def handle(self):
        while True:
            self.data = receive(self.request)

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
                pairing, unlock_token = self.get_matching_pairing(self.data, ip_addr)
                if pairing is None or unlock_token is None:
                    # no match, continue listening
                    LOGGER.debug(
                        f"Client listening to {self.server.server_address} found no pairing for desktop at {ip_addr}, ignoring."
                    )
                    self.error_unlock_handler(ip_addr)
                    continue

                unlock = False

                unlock = self.unlock_handler(pairing.mask())

                response = self.unlock_response(pairing, unlock_token)
                if unlock:
                    LOGGER.info(f"Sending password to {ip_addr} to unlock")
                    send(self.request, response)
                else:
                    LOGGER.info("Unlock handler returned false, denying unlock request")
                    # TODO send correct payload to deny unlocking
                    send(self.request, b"\0x")

    def _clean_hex_str(self, s: str) -> str:
        return s.replace("\u0000", "").replace("\x00", "")

    def _decrypt_enc_data(self, enc_data: str, enc_key: str) -> dict:
        enc_data = self._clean_hex_str(enc_data)

        decrypted = decrypt_aes(bytes.fromhex(enc_data), enc_key)

        return json.loads(decrypted.decode())

    def get_matching_pairing(
        self, data: bytes, desktop_ip_address: str
    ) -> Tuple[Optional[PCPairingSecret], Optional[str]]:
        """Given the received data and the sender's ip address, tries to match the unlock requester to
        a registered PCPairing. Return the found pairing if any along with the unlock token.
        Returns (None,None) if none were found"""
        req_dict = json.loads(data.decode())
        pairing_id = req_dict["pairingId"]

        for pairing in self.pc_pairings:
            if pairing_id == pairing.pairing_id:
                try:
                    enc_data = self._decrypt_enc_data(
                        req_dict["encData"], pairing.encryption_key
                    )
                except Exception as e:
                    raise ValueError(
                        f"Could not decrypt encData from unlock request: {e}"
                    ) from e
                auth_user = enc_data["authUser"]

                if (
                    desktop_ip_address == pairing.desktop_ip_address
                    and auth_user == pairing.username
                ):
                    LOGGER.info(
                        f"Found matching PC for request from {desktop_ip_address}"
                    )
                    return pairing, enc_data["unlockToken"]
        return None, None

    def unlock_response(self, pairing: PCPairingSecret, unlock_token: str) -> bytes:
        response_dict = {
            "unlockToken": unlock_token,
            "password": pairing.password,
        }
        return encrypt_aes(json.dumps(response_dict).encode(), pairing.encryption_key)

    def close(self):
        self.server.close_request(self.request)
