import json
import logging

from pcbu.models import PCPairing, PCPairingSecret
from pcbu.tcp.unlock_server import TCPUnlockServerBase

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)

# just a small test file to validate the good behavior of the unlock server


def get_pc_pairings():
    with open("./conf.local.json") as json_file:
        conf_json = json.load(json_file)
        return [
            PCPairingSecret.from_dict(json_obj) for json_obj in conf_json["paired_pcs"]
        ]

class TCPUnlockServer(TCPUnlockServerBase):

    def on_valid_unlock_request(self, pairing: PCPairing) -> bool:
        LOGGER.info(f"Accepting unlock request from {pairing.desktop_ip_address}!")
        return True

with TCPUnlockServer(get_pc_pairings()) as server:
    server.listen()
