from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from dataclass_wizard import JSONWizard, json_key


class PairingMethod(Enum):
    TCP = "TCP"
    BLUETOOTH = "BLUETOOTH"
    CLOUD_TCP = "CLOUD_TCP"


@dataclass
class PairingQRData(JSONWizard):
    """Pairing data encoded in the QR code shown in the desktop app when pairing"""

    ip: str
    port: int
    method: int
    enc_key: str


@dataclass
class PacketPairInit(JSONWizard):
    """Initial packet sent by the client to the desktop to start the pairing process"""

    device_uuid: Annotated[str, json_key("deviceUUID", all=True)]
    ip_address: str
    device_name: str
    proto_version: str = "1.3.0"
    cloud_token: str = ""


@dataclass
class PacketPairResponse(JSONWizard):
    """Response from the desktop to the PacketPairInit"""

    err_msg: str
    pairing_id: str
    pairing_method: PairingMethod
    host_name: str
    host_os: Annotated[str, json_key("hostOS", all=True)]
    host_address: str
    host_port: int
    mac_address: str
    user_name: Annotated[str, json_key("username")]
    password: str


@dataclass
class PCPairing(JSONWizard):
    """Model reprensenting a desktop (unlock-client) paired with a (unlock-server)"""

    pairing_id: str
    desktop_ip_address: str  # the ip address sending unlock requests, i.e. the desktop
    server_ip_address: str  # the ip to listen on for unlock requests
    server_port: int  # the port to listen on for unlock requests


@dataclass
class PCPairingSecret(PCPairing):
    """Augmented PCPairing with sensitive fields"""

    username: str
    password: str
    encryption_key: str

    def mask(self) -> PCPairing:
        """Returns a PCPairing without any of the secrets"""
        return PCPairing.from_dict(self.to_dict())


@dataclass
class PacketUnlockRequest(JSONWizard):
    pairing_id: str
    enc_data: str  # an EncryptedUnlockPayload, encrypted of course


@dataclass
class EncryptedUnlockPayload(JSONWizard):
    """Model for PacketUnlockRequest.enc_data once decrypted"""

    auth_user: str
    unlock_token: str


@dataclass
class PacketUnlockResponse(JSONWizard):
    unlock_token: str
    password: str  # SENSITIVE! The account's password
