import json
from pathlib import Path

from pcbu.models import (
    PacketPairInit,
    PacketPairResponse,
    PairingMethod,
    PairingQRData,
    PCPairing,
    PCPairingSecret,
)


def test_pair_init_json_keys():
    packet = PacketPairInit(device_uuid="uuid", ip_address="1.2.3.4", device_name="HA")
    data = json.loads(packet.to_json())
    assert data["deviceUUID"] == "uuid"
    assert data["ipAddress"] == "1.2.3.4"
    assert data["deviceName"] == "HA"


def test_pair_response_from_desktop_json():
    response = PacketPairResponse.from_json(
        json.dumps(
            {
                "errMsg": "",
                "pairingId": "id",
                "pairingMethod": "TCP",
                "hostName": "desktop",
                "hostOS": "Windows",
                "hostAddress": "1.2.3.4",
                "hostPort": 43296,
                "macAddress": "AA:BB",
                "username": "user",
                "password": "pwd",
            }
        )
    )
    assert response.host_os == "Windows"
    assert response.user_name == "user"
    assert response.pairing_method is PairingMethod.TCP


def test_pairing_secret_dict_roundtrip(make_pairing):
    """Home Assistant stores pairings with to_dict() and reloads them with from_dict()."""
    pairing = make_pairing()
    data = pairing.to_dict()
    assert data["desktopOs"] == "Linux"
    assert data["encryptionKey"] == "key"
    assert PCPairingSecret.from_dict(data) == pairing


def test_mask_drops_secrets(make_pairing):
    masked = make_pairing().mask()
    assert type(masked) is PCPairing
    assert not hasattr(masked, "password")
    assert not hasattr(masked, "encryption_key")


def test_pair_response_dumps_protocol_keys():
    response = PacketPairResponse.from_json(
        json.dumps(
            {
                "errMsg": "",
                "pairingId": "id",
                "pairingMethod": "TCP",
                "hostName": "desktop",
                "hostOS": "Windows",
                "hostAddress": "1.2.3.4",
                "hostPort": 43296,
                "macAddress": "AA:BB",
                "username": "user",
                "password": "pwd",
            }
        )
    )
    data = json.loads(response.to_json())
    assert data["hostOS"] == "Windows"
    assert data["username"] == "user"
    assert data["pairingMethod"] == "TCP"


def test_load_snake_case_keys(make_pairing):
    """conf.local.json files may use snake_case keys."""
    pairing = make_pairing()
    assert (
        PCPairingSecret.from_dict(
            {
                "pairing_id": "a",
                "desktop_ip_address": "127.0.0.1",
                "desktop_os": "Linux",
                "server_ip_address": "127.0.0.1",
                "server_port": pairing.server_port,
                "username": "user",
                "password": "pwd-a",
                "encryption_key": "key",
            }
        )
        == pairing
    )


def test_load_template_conf():
    """The CLI's conf.template.json mixes camelCase and snake_case keys."""
    conf = json.loads((Path(__file__).parent.parent / "conf.template.json").read_text())
    assert (
        PairingQRData.from_dict(conf["pairing_data"]).enc_key == "some_super_long_key"
    )
    response = PacketPairResponse.from_dict(conf["pairing_response"])
    assert response.host_os == "Some OS"
    assert response.user_name == "user1@desktop"
    assert [PCPairingSecret.from_dict(p).desktop_os for p in conf["paired_pcs"]] == [
        "Windows",
        "Ubuntu",
    ]
