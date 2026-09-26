from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from dataclass_wizard import Alias, JSONWizard


class PCBUModel(JSONWizard):
    """Base of all the models: loads keys in any case (the desktop app uses camelCase)
    and dumps them in camelCase.

    Subclass it for models nested in these ones, so that they load and dump alike.
    """

    def __init_subclass__(cls, **kwargs):
        kwargs.setdefault("load_case", "AUTO")
        kwargs.setdefault("dump_case", "CAMEL")
        super().__init_subclass__(**kwargs)


class PairingMethod(Enum):
    TCP = "TCP"
    BLUETOOTH = "BLUETOOTH"
    CLOUD_TCP = "CLOUD_TCP"


@dataclass
class PairingQRData(PCBUModel):
    """Pairing data encoded in the QR code shown in the desktop app when pairing"""

    ip: str
    port: int
    method: int
    enc_key: str


@dataclass
class PacketPairInit(PCBUModel):
    """Initial packet sent by the client to the desktop to start the pairing process"""

    device_uuid: Annotated[str, Alias("deviceUUID", "device_uuid")]
    ip_address: str
    device_name: str
    proto_version: str = "1.3.0"
    cloud_token: str = ""


@dataclass
class PacketPairResponse(PCBUModel):
    """Response from the desktop to the PacketPairInit"""

    err_msg: str
    pairing_id: str
    pairing_method: PairingMethod
    host_name: str
    host_os: Annotated[str, Alias("hostOS", "host_os")]
    host_address: str
    host_port: int
    mac_address: str
    user_name: Annotated[str, Alias("username", "user_name", "userName")]
    password: str


@dataclass
class PCPairing(PCBUModel):
    """Model reprensenting a desktop (unlock-client) paired with a (unlock-server)"""

    pairing_id: str
    desktop_ip_address: str  # the ip address sending unlock requests, i.e. the desktop
    desktop_os: str
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
class PacketUnlockRequest(PCBUModel):
    pairing_id: str
    enc_data: str  # an EncryptedUnlockPayload, encrypted of course


@dataclass
class EncryptedUnlockPayload(PCBUModel):
    """Model for PacketUnlockRequest.enc_data once decrypted"""

    auth_user: str
    unlock_token: str


@dataclass
class PacketUnlockResponse(PCBUModel):
    unlock_token: str
    password: str  # SENSITIVE! The account's password
