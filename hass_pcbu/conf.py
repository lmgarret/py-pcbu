import json

from hass_pcbu.unlock_service import PCPairing


def get_pc_pairings():
    with open('./conf.json') as json_file:
        conf_json = json.load(json_file)
        return [
            PCPairing(
                pairing_id=json_obj["pairing_id"],
                ip_address=json_obj["ip_address"],
                username=json_obj["username"],
                password=json_obj["password"],
                encryption_key=json_obj["encryption_key"],
            )
            for json_obj in conf_json
        ]

PC_PAIRINGS = get_pc_pairings()