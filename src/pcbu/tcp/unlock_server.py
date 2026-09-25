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
        # key derivation is CPU-heavy, keep it off the event loop
        data = await asyncio.to_thread(self.unlock_response)
        await asend(self.writer, data)

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except (ConnectionError, OSError):
            pass

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
        # necessary to decouple unlocking. Keyed by pairing_id
        self._unlock_packet_writers: dict[str, UnlockPacketWriter] = dict()

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
        # close pending connections, otherwise the servers never finish closing
        writers = list(self._unlock_packet_writers.values())
        self._unlock_packet_writers.clear()
        for writer in writers:
            await writer.close()
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
        Call `unlock(pairing)` (now or later) to send the password (encrypted) to the desktop
        and unlock it."""
        pass

    async def on_unlock_request_cancelled(self, pairing: PCPairing) -> None:
        """Method called whenever a pending unlock request can no longer be answered,
        e.g. the desktop closed the connection before `unlock` was called.

        Can be overridden by the user.
        """
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

    def has_pending_unlock_request(self, pairing: PCPairing) -> bool:
        """Whether an unlock request from this pairing is waiting to be answered."""
        return pairing.pairing_id in self._unlock_packet_writers

    async def unlock(self, pairing: PCPairing):
        """Sends the unlock packet with credentials to the desktop requesting it."""
        # can only use it once, even if sending fails
        writer = self._unlock_packet_writers.pop(pairing.pairing_id, None)
        if writer is None:
            raise ValueError(
                f"Cannot send unlock packet to {pairing.desktop_ip_address}: no packet writer was registered for it."
            )
        try:
            await writer.send_unlock_packet()
        finally:
            await writer.close()

    def _create_handler(
        self, ips: set[str], port: int
    ) -> Callable[[StreamReader, StreamWriter], Awaitable[None] | None]:
        async def handle(reader: StreamReader, writer: StreamWriter):
            # TODO add logging filter so that the ip and port show up in the logs automatically
            client_ip = writer.get_extra_info("peername")[0]
            try:
                await self._handle_unlock_request(reader, writer, client_ip, ips, port)
            finally:
                writer.close()

        return handle

    async def _handle_unlock_request(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        client_ip: str,
        ips: set[str],
        port: int,
    ):
        LOGGER.debug("Wait for packets...")
        try:
            rcv_data = await areceive(reader)
        except (asyncio.IncompleteReadError, ConnectionError) as e:
            LOGGER.debug(f"Connection from {client_ip} closed before a request: {e}")
            return

        # TODO check that the CLOSE instruction is exactly like that (probably should decode)
        if rcv_data == b"CLOSE":
            LOGGER.info(
                f"Received a CLOSE message from {client_ip}, restarting listener."
            )
            return

        try:
            # key derivation is CPU-heavy, keep it off the event loop
            pairing, unlock_token = await asyncio.to_thread(
                self.get_matching_pairing, rcv_data, client_ip
            )
            LOGGER.debug("Decrypted & parsed PacketUnlockRequest")

            if pairing is None or unlock_token is None:
                raise ValueError(
                    f"Server listening on {ips}:{port} found no pairing for desktop at {client_ip}."
                )
            LOGGER.info(
                f"Received PacketUnlockRequest from {client_ip}, for user {pairing.username}"
            )
        except Exception:
            LOGGER.exception(
                "Could not match client ip and received request with a pairing."
            )
            await self.on_invalid_unlock_request(client_ip)
            return

        # register writer for async unlock request sending, replacing any stale one
        packet_writer = UnlockPacketWriter(
            unlock_token=unlock_token, pc_pairing=pairing, writer=writer
        )
        previous = self._unlock_packet_writers.pop(pairing.pairing_id, None)
        self._unlock_packet_writers[pairing.pairing_id] = packet_writer
        if previous is not None:
            await previous.close()
        await self.on_valid_unlock_request(pairing.mask())

        # wait for the connection to end: either the desktop gave up, or we closed it after unlocking
        try:
            while await reader.read(1024):
                pass
        except ConnectionError:
            pass

        if self._unlock_packet_writers.get(pairing.pairing_id) is packet_writer:
            del self._unlock_packet_writers[pairing.pairing_id]
            LOGGER.info(f"Desktop at {client_ip} closed its pending unlock request.")
            await self.on_unlock_request_cancelled(pairing.mask())

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

                # Windows may give a different case for username on cold boot
                # see https://github.com/MeisApps/pcbu-desktop/issues/22
                ignore_case = "windows" in pairing.desktop_os.lower()
                username_matches = enc_payload.auth_user == pairing.username or (
                    ignore_case
                    and enc_payload.auth_user.lower() == pairing.username.lower()
                )
                if (
                    desktop_ip_address == pairing.desktop_ip_address
                    and username_matches
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
