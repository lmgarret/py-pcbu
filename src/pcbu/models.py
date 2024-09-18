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

    proto_version: str
    deviceUUID: str
    device_name: str
    ipAddress: str
    cloudToken: str


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
    """Model reprensenting a collection of desktop paired with this client"""

    pairing_id: str
    desktop_ip_address: str  # the ip address sending unlock requests, i.e. the desktop
    server_ip_address: str  # the ip to listen on for unlock requests
    server_port: int  # the port to listen on for unlock requests


@dataclass
class PCPairingSecret(PCPairing):
    """Model reprensenting a desktop paired with this client. Contains sensitive fields"""

    username: str
    password: str
    encryption_key: str

    def mask(self) -> PCPairing:
        """Returns a PCPairing without any of the secrets"""
        return PCPairing.from_dict(self.to_dict())