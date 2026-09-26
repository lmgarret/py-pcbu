import asyncio

from pcbu.models import PacketPairResponse, PairingMethod, PairingQRData
from pcbu.tcp.pair_client import TCPPairClient
from pcbu.tcp.pair_server import TCPPairServer


async def test_pair(port):
    qr_data = PairingQRData(ip="127.0.0.1", port=port, method=0, enc_key="key")
    expected = PacketPairResponse(
        err_msg="",
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
    async with TCPPairServer(
        pairing_qr_data=qr_data, pairing_response=expected
    ) as server:
        task = asyncio.create_task(server.start())
        client = TCPPairClient(
            qr_data, device_name="test", ip_address="127.0.0.1", machine_uuid="uuid"
        )
        assert await client.pair(timeout=5) == expected
        task.cancel()
