import json
import logging

from pcbu.models import  PCPairing
from pcbu.tcp.unlock_server import TCPUnlockServer

logging.basicConfig(level=logging.DEBUG)

# just a small test file to validate the good behavior of the unlock server
def get_pc_pairings():
    with open("./conf.json") as json_file:
        conf_json = json.load(json_file)
        return [
            PCPairing(
                pairing_id=json_obj["pairing_id"],
                server_ip_address=json_obj["server_ip_address"],
                desktop_ip_address=json_obj["desktop_ip_address"],
                username=json_obj["username"],
                password=json_obj["password"],
                encryption_key=json_obj["encryption_key"],
            )
            for json_obj in conf_json
        ]


PC_PAIRINGS = get_pc_pairings()

with TCPUnlockServer(PC_PAIRINGS) as server:
    server.listen()
