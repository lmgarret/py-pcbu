import logging
import socket
from typing import Optional

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import PacketPairInit, PacketPairResponse, PairingQRData
from pcbu.helpers import get_ip, get_uuid

LOGGER = logging.getLogger(__name__)


class TCPPairClient:
    """Client initiating the pairing process,  i.e. emulating your smartphone in PCBU's default setup."""
    def __init__(
        self,
        pairing_qr_data: PairingQRData,
        device_name: str,
        ip_address: Optional[str] = None,
        machine_uuid: Optional[str] = None,
    ) -> None:
        self.pairing_qr_data = pairing_qr_data
        self.device_name = device_name
        self.ip_address = ip_address or get_ip()
        self.machine_uuid = machine_uuid or get_uuid()

    def create_packet_pair_init(self) -> PacketPairInit:
        packet_pair_init = PacketPairInit.from_dict(
            {
                "protoVersion": "1.3.0",
                "deviceUUID": self.machine_uuid,
                "deviceName": self.device_name,
                "cloudToken": "",
                "ipAddress": self.ip_address,
            }
        )
        return packet_pair_init

    def pair(self, timeout: float = 5.0) -> PacketPairResponse:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return self._pair(s)

    def _pair(self, socket: socket.socket) -> PacketPairResponse:
        socket.connect((self.pairing_qr_data.ip, self.pairing_qr_data.port))
        LOGGER.debug("Connected")

        LOGGER.debug("Send PackerPairInit...")
        snd_data = self.create_packet_pair_init().to_json().encode()
        snd_enc_data = encrypt_aes(snd_data, self.pairing_qr_data.enc_key)
        snd_enc_data_size = len(snd_enc_data).to_bytes(2, byteorder="big")
        # first two bytes are the payload side
        socket.sendall(snd_enc_data_size)
        socket.sendall(snd_enc_data)
        LOGGER.debug("Sent PackerPairInit")

        LOGGER.debug("Wait for PacketPairResponse size...")
        rcv_data = socket.recv(1024)
        rcv_size = int.from_bytes(rcv_data, byteorder="big")
        LOGGER.debug(f"Received PacketPairResponse size: {rcv_size}")
        LOGGER.debug("Wait for PacketPairResponse...")
        rcv_data = socket.recv(1024)
        LOGGER.debug("Received PacketPairResponse")
        # first two bytes are the payload side
        data = decrypt_aes(rcv_data, self.pairing_qr_data.enc_key)
        LOGGER.debug("Decrypted PacketPairResponse")
        response = PacketPairResponse.from_json(data)
        LOGGER.debug("Parsed PacketPairResponse")

        return response