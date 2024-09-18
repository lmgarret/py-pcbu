import json
from pcbu.tcp.pair_client import TCPPairClient
from pcbu.models import PairingQRData
import logging

logging.basicConfig(level=logging.DEBUG)


def get_pc_pairing_data():
    with open("./conf.local.json") as json_file:
        conf_json = json.load(json_file)
        return PairingQRData.from_dict(conf_json["pairing_data"])


client = TCPPairClient(pairing_qr_data=get_pc_pairing_data(), device_name="MyHomeLab")
pair_response = client.pair()
logging.debug(pair_response)
