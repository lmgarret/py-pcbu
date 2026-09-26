import asyncio

import pytest

from pcbu.errors import PairingError
from pcbu.models import PacketPairResponse, PairingMethod, PairingQRData
from pcbu.tcp.pair_client import TCPPairClient
from pcbu.tcp.pair_server import TCPPairServer


def _response(err_msg: str = "") -> PacketPairResponse:
    return PacketPairResponse(
        err_msg=err_msg,
        pairing_id="id",
        pairing_method=PairingMethod.TCP,
        host_name="desktop",
        host_os="Linux",
        host_address="127.0.0.1",
        host_port=43296,
        mac_address="AA:BB",
        user_name="user",
        password="pwd",
    )


async def test_pair(port):
    qr_data = PairingQRData(ip="127.0.0.1", port=port, method=0, enc_key="key")
    expected = _response()
    async with TCPPairServer(
        pairing_qr_data=qr_data, pairing_response=expected
    ) as server:
        task = asyncio.create_task(server.start())
        client = TCPPairClient(
            qr_data, device_name="test", ip_address="127.0.0.1", machine_uuid="uuid"
        )
        assert await client.pair(timeout=5) == expected
        task.cancel()


async def test_pair_refused(port):
    qr_data = PairingQRData(ip="127.0.0.1", port=port, method=0, enc_key="key")
    async with TCPPairServer(qr_data, _response("Pairing refused")) as server:
        task = asyncio.create_task(server.start())
        client = TCPPairClient(
            qr_data, device_name="t", ip_address="127.0.0.1", machine_uuid="u"
        )
        with pytest.raises(PairingError, match="Pairing refused"):
            await client.pair(timeout=5)
        task.cancel()


async def test_pair_wrong_key(port):
    qr_data = PairingQRData(ip="127.0.0.1", port=port, method=0, enc_key="key")
    wrong = PairingQRData(ip="127.0.0.1", port=port, method=0, enc_key="wrong")
    async with TCPPairServer(qr_data, _response()) as server:
        task = asyncio.create_task(server.start())
        client = TCPPairClient(
            wrong, device_name="t", ip_address="127.0.0.1", machine_uuid="u"
        )
        with pytest.raises(PairingError):
            await client.pair(timeout=5)
        task.cancel()
