import logging
import socket
import uuid

from hass_pcbu.crypto import decrypt_aes, encrypt_aes
from hass_pcbu.models import PacketPairInit, PacketPairResponse, PairingQRData

LOGGER = logging.getLogger(__name__)


class TCPPairClient:
    def __init__(self, pairing_qr_data: PairingQRData, device_name: str) -> None:
        self.pairing_qr_data = pairing_qr_data
        self.device_name = device_name

    def create_packet_pair_init(self) -> PacketPairInit:
        packet_pair_init = PacketPairInit.from_dict(
            {
                "protoVersion": "1.2.0",
                "deviceUUID": str(uuid.uuid4()),  # TODO get real one
                "deviceName": self.device_name,
                "cloudToken": "",
                "ipAddress": "192.168.1.39",  # TODO get real one
            }
        )
        return packet_pair_init

    def pair(self) -> PacketPairResponse:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.pairing_qr_data.ip, self.pairing_qr_data.port))
            s.settimeout(5.0)
            LOGGER.debug("Connected")

            LOGGER.debug("Send PackerPairInit...")
            data = self.create_packet_pair_init().to_json().encode()
            enc_data = encrypt_aes(data, self.pairing_qr_data.enc_key)
            enc_data_size = len(enc_data).to_bytes(2)
            # first two bytes are the payload side
            s.sendall(enc_data_size)
            s.sendall(enc_data)
            LOGGER.debug("Sent PackerPairInit")

            LOGGER.debug("Wait for PacketPairResponse...")
            enc_data = s.recv(1024)
            LOGGER.debug("Received PacketPairResponse")
            # first two bytes are the payload side
            data = decrypt_aes(enc_data[2:], self.pairing_qr_data.enc_key)
            LOGGER.debug("Decrypted PacketPairResponse")
            response = PacketPairResponse.from_json(data)
            LOGGER.debug("Parsed PacketPairResponse")
        return response
