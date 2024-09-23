import asyncio
import logging
import platform
from typing import Optional

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import PacketPairInit, PacketPairResponse, PairingQRData
from pcbu.helpers import get_ip, get_uuid
from pcbu.tcp.common import areceive, asend

LOGGER = logging.getLogger(__name__)


class TCPPairClient:
    """Client initiating the pairing process, i.e. emulating your smartphone in PCBU's default setup."""

    def __init__(
        self,
        pairing_qr_data: PairingQRData,
        device_name: Optional[str] = None,
        ip_address: Optional[str] = None,
        machine_uuid: Optional[str] = None,
    ) -> None:
        self.pairing_qr_data = pairing_qr_data
        self.device_name = device_name or platform.node()
        self.ip_address = ip_address or get_ip()
        self.machine_uuid = machine_uuid or get_uuid()

    async def pair(self, timeout: float = 5.0) -> PacketPairResponse:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.pairing_qr_data.ip, self.pairing_qr_data.port),
            timeout=timeout,
        )

        LOGGER.info(
            f"Connected to {self.pairing_qr_data.ip}:{self.pairing_qr_data.port}"
        )

        LOGGER.debug("Send PackerPairInit...")
        packet_pair_init = PacketPairInit.from_dict(
            {
                "deviceUUID": self.machine_uuid,
                "deviceName": self.device_name,
                "ipAddress": self.ip_address,
            }
        )
        snd_data = packet_pair_init.to_json().encode()
        snd_enc_data = encrypt_aes(snd_data, self.pairing_qr_data.enc_key)
        await asend(writer=writer, data=snd_enc_data)
        LOGGER.debug("Sent PackerPairInit")

        LOGGER.debug("Wait for PacketPairResponse...")
        rcv_data = await areceive(reader)
        LOGGER.debug("Received PacketPairResponse")
        data = decrypt_aes(rcv_data, self.pairing_qr_data.enc_key)
        LOGGER.debug("Decrypted PacketPairResponse")
        response = PacketPairResponse.from_json(data)
        LOGGER.debug("Parsed PacketPairResponse")

        return response
