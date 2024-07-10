from dataclasses import dataclass
from enum import Enum

from dataclass_wizard import JSONWizard


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
    hostOS: str
    mac_address: str
    user_name: str
    password: str


@dataclass
class PCPairing:
    """Model reprensenting a collection of desktop paired with this client"""

    pairing_id: str
    desktop_ip_address: str  # the ip address sending unlock requests, i.e. the desktop
    server_ip_address: str  # the ip to listen on for unlock requests
    username: str
    password: str
    encryption_key: str
