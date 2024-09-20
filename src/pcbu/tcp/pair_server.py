from asyncio import StreamReader, StreamWriter
import asyncio
from contextlib import ContextDecorator
import logging
from typing import Optional

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import PacketPairInit, PacketPairResponse, PairingQRData
from pcbu.tcp.common import areceive, asend

LOGGER = logging.getLogger(__name__)


class TCPPairServer(ContextDecorator):
    """This emulate the 'server' part of PCBU in the pairing process, i.e. the desktop to be unlocked."""

    def __init__(
        self,
        pairing_qr_data: PairingQRData,
        pairing_response: PacketPairResponse,
    ) -> None:
        self.pairing_qr_data = pairing_qr_data
        self.pairing_response = pairing_response
        self._server = None

    async def __aenter__(self):
        self._server = await asyncio.start_server(
            self._handle, self.pairing_qr_data.ip, self.pairing_qr_data.port
        )
        await self._server.__aenter__()
        return self

    async def __aexit__(self, *exc):
        await self._server.__aexit__()
        self._server = None
        LOGGER.info("TCPPairServer closed.")
        return False

    async def start(self, timeout: Optional[float] = None):
        if self._server is None:
            raise RuntimeError("Cannot start TCPPairServer as it was closed.")

        LOGGER.info(
            f"Starting TCPPairServer on {self.pairing_qr_data.ip}:{self.pairing_qr_data.port}..."
        )
        await self._server.serve_forever()

    async def _handle(self, reader: StreamReader, writer: StreamWriter):
        try:
            LOGGER.debug("Wait for PacketPairInit...")
            rcv_data = await areceive(reader)
            LOGGER.debug("Received PacketPairInit")

            decrypted_data = decrypt_aes(rcv_data, self.pairing_qr_data.enc_key)
            LOGGER.debug("Decrypted PacketPairInit")

            packet_pair_init = PacketPairInit.from_json(decrypted_data)
            LOGGER.debug("Parsed PacketPairInit")
            LOGGER.debug(packet_pair_init)

            LOGGER.debug("Send PacketPairResponse...")
            snd_data = self.pairing_response.to_json().encode()
            snd_enc_data = encrypt_aes(snd_data, self.pairing_qr_data.enc_key)
            await asend(writer, snd_enc_data)
            LOGGER.debug("Sent PacketPairResponse")

        except Exception:
            LOGGER.exception("Error handling connection")
