import socket

import pytest

from pcbu.models import PCPairingSecret


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def port() -> int:
    return free_port()


@pytest.fixture
def make_pairing(port):
    def _make(
        pairing_id: str = "a",
        username: str = "user",
        desktop_os: str = "Linux",
        desktop_ip: str = "127.0.0.1",
        key: str = "key",
    ) -> PCPairingSecret:
        return PCPairingSecret(
            pairing_id=pairing_id,
            desktop_ip_address=desktop_ip,
            desktop_os=desktop_os,
            server_ip_address="127.0.0.1",
            server_port=port,
            username=username,
            password=f"pwd-{pairing_id}",
            encryption_key=key,
        )

    return _make
