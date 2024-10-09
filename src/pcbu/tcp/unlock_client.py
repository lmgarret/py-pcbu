import asyncio
import logging
import uuid

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import (
    PCPairingSecret,
    PacketUnlockResponse,
    PacketUnlockRequest,
    EncryptedUnlockPayload,
)
from pcbu.tcp.common import areceive, asend

LOGGER = logging.getLogger(__name__)


class TCPUnlockClient:
    """Client initiating the pairing process, i.e. emulating your smartphone in PCBU's default setup."""

    def __init__(
        self,
        pairing: PCPairingSecret,
    ) -> None:
        self.pairing = pairing

    async def unlock(self, timeout: float = 5.0) -> PacketUnlockResponse:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                self.pairing.server_ip_address, self.pairing.server_port
            ),
            timeout=timeout,
        )

        LOGGER.info(
            f"Connected to {self.pairing.server_ip_address}:{self.pairing.server_port}"
        )

        LOGGER.debug("Send PacketUnlockRequest...")
        unlock_token = str(
            uuid.uuid4()
        )  # TODO check that this is a valid and secure way to generate the token
        unlock_req_payload = EncryptedUnlockPayload(
            auth_user=self.pairing.username, unlock_token=unlock_token
        )
        packet_unlock_req = PacketUnlockRequest(
            pairing_id=self.pairing.pairing_id,
            enc_data=encrypt_aes(
                unlock_req_payload.to_json().encode(), self.pairing.encryption_key
            ).hex(),
        )

        await asend(writer=writer, data=packet_unlock_req.to_json().encode())
        LOGGER.debug("Sent PacketUnlockRequest")

        LOGGER.debug("Wait for PacketUnlockResponse...")
        rcv_data = await areceive(reader)
        LOGGER.debug("Received PacketUnlockResponse")
        data = decrypt_aes(rcv_data, self.pairing.encryption_key)
        LOGGER.debug("Decrypted PacketUnlockResponse")
        response = PacketUnlockResponse.from_json(data)
        LOGGER.debug("Parsed PacketUnlockResponse")

        return response
