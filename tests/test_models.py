import json

from pcbu.models import (
    PacketPairInit,
    PacketPairResponse,
    PairingMethod,
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
