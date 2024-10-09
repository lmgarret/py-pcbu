from abc import ABCMeta, abstractmethod
from asyncio import Server, StreamReader, StreamWriter
import asyncio
from collections.abc import Callable
from contextlib import AsyncContextDecorator, AsyncExitStack
import logging
from typing import Any, Awaitable, Coroutine, Optional, Tuple

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import (
    EncryptedUnlockPayload,
    PacketUnlockRequest,
    PacketUnlockResponse,
    PCPairing,
    PCPairingSecret,
)
from pcbu.tcp.common import areceive, asend

LOGGER = logging.getLogger(__name__)


class UnlockPacketWriter:
    def __init__(
        self, unlock_token: str, pc_pairing: PCPairingSecret, writer: StreamWriter
    ) -> None:
        self.unlock_token = unlock_token
        self.writer = writer
        self.pc_pairing = pc_pairing

    async def send_unlock_packet(self):
        await asend(self.writer, self.unlock_response())

    def unlock_response(self) -> bytes:
        response = PacketUnlockResponse(
            unlock_token=self.unlock_token, password=self.pc_pairing.password
        )
        return encrypt_aes(response.to_json().encode(), self.pc_pairing.encryption_key)


class TCPUnlockServerBase(AsyncContextDecorator, metaclass=ABCMeta):
    """This emulate the 'server' part of PCBU in the pairing process, i.e. the desktop to be unlocked."""

    def __init__(
        self,
        pc_pairings: list[PCPairingSecret],
    ) -> None:
        self.pc_pairings = pc_pairings
        self._context_stack = AsyncExitStack()
        self._servers: dict[int, Server] = dict()
        # necessary to decouple unlocking. The int tuple is [server_port, client_ip_addr]
        self._unlock_packet_writers: dict[Tuple[int, int], UnlockPacketWriter] = dict()

    async def __aenter__(self):
        await self._context_stack.__aenter__()
        for port in {pair.server_port for pair in self.pc_pairings}:
            ips = {
                pair.server_ip_address
                for pair in self.pc_pairings
                if pair.server_port == port
            }
            LOGGER.info(f"Binding TCPUnlockServer to {ips}:{port}")
            server = await asyncio.start_server(
                self._create_handler(ips, port), list(ips), port
            )
            self._servers[port] = server
            await self._context_stack.enter_async_context(server)
        await self.on_enter()
        return self

    async def __aexit__(self, *exc):
        await self.on_exit()
        await self._context_stack.__aexit__(*exc)
        self._servers = dict()
        LOGGER.info("TCPUnlockServer closed.")
        return False

    async def start(self):
        if not self._servers:
            raise RuntimeError("Cannot start TCPUnlockServer as it was closed.")

        LOGGER.info("Starting TCPUnlockServer...")

        await self.on_start()

        async with asyncio.TaskGroup() as tg:
            for s in self._servers.values():
                tg.create_task(s.serve_forever())

    async def on_enter(self) -> bool:
        """Method called whenever the server's context is entered.
        Can be overridden by the user."""
        pass

    async def on_start(
        self,
    ) -> bool:
        """Method called upon starting the server.
        Can be overridden by the user."""
        pass

    @abstractmethod
    async def on_valid_unlock_request(self, pairing: PCPairing) -> None:
        """Method called whenever an unlock request has been received and authenticated.
        The return boolean determines whether the password should be sent (encrypted) to the desktop
        to unlock it."""
        pass

    async def on_invalid_unlock_request(self, ip: str) -> None:
        """Method called whenever an unlock request has been received and is deemed invalid.
        This can happen if:
         - the requesting ip address is unknown in all the PCPairs
         - the received payload could not be decrypted (invalid encryption key, wrong AES timestamp...)

        Can be overridden by the user.
        """
        pass

    async def on_exit(self) -> bool:
        """Method called whenever the server's context is exited. Can be overriden by user"""
        pass

    async def unlock(self, pairing: PCPairing):
        """Sends the unlock packet with credentials to the desktop requesting it."""
        key = (pairing.server_port, pairing.desktop_ip_address)
        if key not in self._unlock_packet_writers:
            raise ValueError(
                f"Cannot send unlock packet to { pairing.desktop_ip_address}: no packet writer was registered for it."
            )
        writer = self._unlock_packet_writers[key]
        await writer.send_unlock_packet()

        # can only use it once
        del self._unlock_packet_writers[key]

    def _create_handler(
        self, ips: str, port: int
    ) -> Callable[[StreamReader, StreamWriter], Awaitable[None] | None]:
        async def handle(reader: StreamReader, writer: StreamWriter):
            # TODO add logging filter so that the ip and port show up in the logs automatically

            LOGGER.debug("Wait for packets...")
            rcv_data = await areceive(reader)
            client_ip, client_port = writer.get_extra_info("peername")

            # TODO check that:
            # 1. the CLOSE instruction is exactly like that (probably should decode)
            # 2. should close writer here?
            if rcv_data == b"CLOSE":
                LOGGER.info(
                    f"Received a CLOSE message from {client_ip}, restarting listener."
                )
                return

            try:
                pairing, unlock_token = self.get_matching_pairing(rcv_data, client_ip)
                LOGGER.debug("Decrypted & parsed PacketUnlockRequest")

                if pairing is None or unlock_token is None:
                    raise ValueError(
                        f"Server listening on {ips}:{port} found no pairing for desktop at {client_ip}."
                    )
                LOGGER.info(
                    f"Received PacketUnlockRequest from {client_ip}, for user {pairing.username}"
                )
            except ValueError:
                LOGGER.exception(
                    "Could not match client ip and received request with a pairing."
                )
                await self.on_invalid_unlock_request(client_ip)
                return

            # register writer for async unlock request sending
            self._unlock_packet_writers[
                (pairing.server_port, pairing.desktop_ip_address)
            ] = UnlockPacketWriter(
                unlock_token=unlock_token, pc_pairing=pairing, writer=writer
            )
            await self.on_valid_unlock_request(pairing.mask())

        return handle

    def get_matching_pairing(
        self, data: bytes, desktop_ip_address: str
    ) -> Tuple[Optional[PCPairingSecret], Optional[str]]:
        """Given the received data and the sender's ip address, tries to match the unlock requester to
        a registered PCPairing. Return the found pairing if any along with the unlock token.
        Returns (None,None) if none were found"""
        request = PacketUnlockRequest.from_json(data.decode())

        for pairing in self.pc_pairings:
            if request.pairing_id == pairing.pairing_id:
                try:
                    enc_data = decrypt_aes(
                        bytes.fromhex(request.enc_data), pairing.encryption_key
                    )
                    enc_payload = EncryptedUnlockPayload.from_json(enc_data.decode())
                except Exception as e:
                    raise ValueError(
                        f"Could not decrypt encData from unlock request: {e}"
                    ) from e

                if (
                    desktop_ip_address == pairing.desktop_ip_address
                    and enc_payload.auth_user == pairing.username
                ):
                    return pairing, enc_payload.unlock_token
        return None, None


class TCPUnlockServer(TCPUnlockServerBase):
    """A simple implementation of the TCPUnlockServerBase, which
    automatically unlocks if a valid unlock request was received"""

    async def on_valid_unlock_request(
        self, pairing: PCPairing
    ) -> Coroutine[Any, Any, bool]:
        await self.unlock(pairing=pairing)
