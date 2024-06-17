from dataclasses import dataclass
from enum import Enum

from dataclass_wizard import JSONWizard


class PairingMethod(Enum):
    TCP = "TCP"
    BLUETOOTH = "BLUETOOTH"
    CLOUD_TCP = "CLOUD_TCP"


@dataclass
class PairingQRData(JSONWizard):
    ip: str
    port: int
    method: int
    enc_key: str


@dataclass
class PacketPairInit(JSONWizard):
    proto_version: str
    deviceUUID: str
    device_name: str
    ipAddress: str
    cloudToken: str


@dataclass
class PacketPairResponse(JSONWizard):
    err_msg: str
    pairing_id: str
    pairing_method: PairingMethod
    host_name: str
    hostOS: str
    mac_address: str
    user_name: str
    password: str

