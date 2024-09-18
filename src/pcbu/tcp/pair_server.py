import logging
import socket
from typing import Optional

from pcbu.crypto import decrypt_aes, encrypt_aes
from pcbu.models import PacketPairInit, PacketPairResponse, PairingQRData
from pcbu.helpers import get_ip, get_uuid
from pcbu.tcp.common import receive, send

LOGGER = logging.getLogger(__name__)


class TCPPairServer:
    """This emulate the 'server' part of PCBU in the pairing process, i.e. the desktop to be unlocked."""

    def __init__(
        self,
        pairing_qr_data: PairingQRData,
        pairing_response: PacketPairResponse,
    ) -> None:
        self.pairing_qr_data = pairing_qr_data
        self.pairing_response = pairing_response
        self.ip_address = get_ip()
        self.machine_uuid = get_uuid()

    def start(self, timeout: Optional[float] = None):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.bind((self.pairing_qr_data.ip, self.pairing_qr_data.port))
            s.listen()
            LOGGER.info(
                f"Server listening on {self.pairing_qr_data.ip}:{self.pairing_qr_data.port}"
            )

            while True:
                conn, addr = s.accept()
                with conn:
                    LOGGER.info(f"Connected with {addr}")
                    self._handle_connection(conn)

    def _handle_connection(self, conn: socket.socket):
        try:
            LOGGER.debug("Wait for PacketPairInit...")
            rcv_data = receive(conn)
            LOGGER.debug("Received PacketPairInit")

            decrypted_data = decrypt_aes(rcv_data, self.pairing_qr_data.enc_key)
            LOGGER.debug("Decrypted PacketPairInit")

            packet_pair_init = PacketPairInit.from_json(decrypted_data)
            LOGGER.debug("Parsed PacketPairInit")
            LOGGER.debug(packet_pair_init)

            LOGGER.debug("Send PacketPairResponse...")
            snd_data = self.pairing_response.to_json().encode()
            snd_enc_data = encrypt_aes(snd_data, self.pairing_qr_data.enc_key)
            send(conn, snd_enc_data)
            LOGGER.debug("Sent PacketPairResponse")

        except Exception as e:
            LOGGER.exception("Error handling connection")
