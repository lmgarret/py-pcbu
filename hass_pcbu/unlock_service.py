from dataclasses import dataclass
import json
import logging
from hass_pcbu.crypto import decrypt_aes, encrypt_aes

LOGGER = logging.getLogger(__name__)


@dataclass
class PCPairing:
    pairing_id: str
    ip_address: str
    username: str
    password: str
    encryption_key: str


class UnlockService:

    def __init__(self, paired_pcs: list[PCPairing]) -> None:
        self.paired_pcs = paired_pcs

    def _clean_hex_str(self, s: str) -> str:
        return s.replace("\u0000", "").replace("\x00", "")

    def _decrypt_enc_data(self, enc_data: str, enc_key: str) -> dict:
        enc_data = self._clean_hex_str(enc_data)

        decrypted = decrypt_aes(bytes.fromhex(enc_data), enc_key)

        return json.loads(decrypted[8:].decode())

    def unlock_response(self, data: bytes, ip_address: str) -> bytes:
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
                    )
                auth_user = enc_data["authUser"]
                LOGGER.debug(enc_data)

                if ip_address == pair.ip_address and auth_user == pair.username:
                    response_dict = {
                        "unlockToken": enc_data["unlockToken"],
                        "password": pair.password,
                    }
                    LOGGER.info(f"Found matching PC for request from {ip_address}")
                    return encrypt_aes(
                        json.dumps(response_dict).encode(), pair.encryption_key
                    )

        raise ValueError(
            f"Found no paired PC for ip_address={ip_address}, pairing_id={pairing_id}"
        )
