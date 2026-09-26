import asyncio
import contextlib

import pytest

from pcbu.crypto import encrypt_aes
from pcbu.errors import UnlockRejectedError
from pcbu.models import EncryptedUnlockPayload, PacketUnlockRequest, PCPairing
from pcbu.tcp.common import asend
from pcbu.tcp.unlock_client import TCPUnlockClient
from pcbu.tcp.unlock_server import TCPUnlockServer, TCPUnlockServerBase


class RecordingServer(TCPUnlockServerBase):
    """Records callbacks and only unlocks when asked to."""

    def __init__(self, pairings):
        super().__init__(pairings)
        self.valid: list[str] = []
        self.invalid: list[str] = []
        self.cancelled: list[str] = []

    async def on_valid_unlock_request(self, pairing: PCPairing) -> None:
        self.valid.append(pairing.pairing_id)

    async def on_invalid_unlock_request(self, ip: str) -> None:
        self.invalid.append(ip)

    async def on_unlock_request_cancelled(self, pairing: PCPairing) -> None:
        self.cancelled.append(pairing.pairing_id)


@contextlib.asynccontextmanager
async def running(server):
    async with server:
        task = asyncio.create_task(server.start())
        await asyncio.sleep(0.05)
        try:
            yield server
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def until(predicate, timeout=5.0):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


async def send_request(pairing, username=None):
    """Send an unlock request like a desktop would, and return the open connection."""
    reader, writer = await asyncio.open_connection(
        pairing.server_ip_address, pairing.server_port
    )
    payload = EncryptedUnlockPayload(
        auth_user=username or pairing.username, unlock_token="token"
    )
    request = PacketUnlockRequest(
        pairing_id=pairing.pairing_id,
        enc_data=encrypt_aes(payload.to_json().encode(), pairing.encryption_key).hex(),
    )
    await asend(writer, request.to_json().encode())
    return reader, writer


async def test_auto_unlock(make_pairing):
    pairing = make_pairing()
    async with running(TCPUnlockServer([pairing])):
        response = await TCPUnlockClient(pairing).unlock(timeout=5)
    assert response.password == pairing.password


async def test_deferred_unlock(make_pairing):
    pairing = make_pairing()
    async with running(RecordingServer([pairing])) as server:
        request = asyncio.create_task(TCPUnlockClient(pairing).unlock(timeout=5))
        await until(lambda: server.valid == ["a"])
        assert server.has_pending_unlock_request(pairing)
        assert not request.done()

        await server.unlock(pairing)
        assert (await request).password == pairing.password
        assert not server.has_pending_unlock_request(pairing)


async def test_unlock_the_right_pairing(make_pairing):
    a, b = make_pairing("a"), make_pairing("b", key="other")
    async with running(RecordingServer([a, b])) as server:
        request_a = asyncio.create_task(TCPUnlockClient(a).unlock(timeout=5))
        request_b = asyncio.create_task(TCPUnlockClient(b).unlock(timeout=5))
        await until(lambda: sorted(server.valid) == ["a", "b"])

        await server.unlock(b)
        assert (await request_b).password == b.password
        assert not request_a.done()
        await server.unlock(a)
        assert (await request_a).password == a.password


async def test_case_insensitive_username_on_windows(make_pairing):
    pairing = make_pairing(username="User", desktop_os="Windows 11")
    async with running(RecordingServer([pairing])) as server:
        _, writer = await send_request(pairing, username="user")
        await until(lambda: server.valid == ["a"])
        writer.close()


async def test_case_sensitive_username_elsewhere(make_pairing):
    pairing = make_pairing(username="User", desktop_os="Linux")
    async with running(RecordingServer([pairing])) as server:
        _, writer = await send_request(pairing, username="user")
        await until(lambda: server.invalid == ["127.0.0.1"])
        assert server.valid == []
        writer.close()


@pytest.mark.parametrize("desktop_os", ["Windows", "Linux"])
async def test_reject_unknown_desktop_ip(make_pairing, desktop_os):
    pairing = make_pairing(desktop_os=desktop_os, desktop_ip="10.0.0.9")
    async with running(RecordingServer([pairing])) as server:
        _, writer = await send_request(pairing)
        await until(lambda: server.invalid == ["127.0.0.1"])
        assert server.valid == []
        writer.close()


async def test_reject_wrong_key(make_pairing):
    pairing = make_pairing()
    async with running(RecordingServer([pairing])) as server:
        _, writer = await send_request(make_pairing(key="wrong"))
        await until(lambda: server.invalid == ["127.0.0.1"])
        writer.close()


async def test_malformed_packet(make_pairing, port):
    async with running(RecordingServer([make_pairing()])) as server:
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        await asend(writer, b"garbage")
        await until(lambda: server.invalid == ["127.0.0.1"])
        writer.close()


async def test_early_disconnect(make_pairing, port):
    pairing = make_pairing()
    async with running(TCPUnlockServer([pairing])):
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x00")
        writer.close()
        # the server keeps serving afterwards
        assert (
            await TCPUnlockClient(pairing).unlock(timeout=5)
        ).password == pairing.password


async def test_dropped_request(make_pairing):
    pairing = make_pairing()
    async with running(RecordingServer([pairing])) as server:
        _, writer = await send_request(pairing)
        await until(lambda: server.valid == ["a"])
        writer.close()
        await until(lambda: server.cancelled == ["a"])
        assert not server.has_pending_unlock_request(pairing)
        with pytest.raises(ValueError):
            await server.unlock(pairing)


async def test_exit_with_pending_request(make_pairing):
    pairing = make_pairing()
    async with running(RecordingServer([pairing])) as server:
        request = asyncio.create_task(TCPUnlockClient(pairing).unlock(timeout=5))
        await until(lambda: server.valid == ["a"])
    # exiting closed the pending connection instead of hanging, and cancelled it
    with pytest.raises(UnlockRejectedError):
        await asyncio.wait_for(request, 5)
    assert server.cancelled == ["a"]


async def test_stop_with_silent_connection(make_pairing, port):
    """A connection that never sends anything does not block stopping the server."""
    async with running(RecordingServer([make_pairing()])):
        reader, _ = await asyncio.open_connection("127.0.0.1", port)
    assert await asyncio.wait_for(reader.read(), 5) == b""


async def test_client_timeout(port, make_pairing):
    async def never_answer(reader, writer):
        await reader.read()  # wait for the client to give up
        writer.close()

    server = await asyncio.start_server(never_answer, "127.0.0.1", port)
    async with server:
        with pytest.raises(TimeoutError):
            await TCPUnlockClient(make_pairing()).unlock(timeout=0.5)


async def test_client_rejected(make_pairing):
    pairing = make_pairing()
    async with running(RecordingServer([pairing])) as server:
        with pytest.raises(UnlockRejectedError):
            await TCPUnlockClient(make_pairing(key="wrong")).unlock(timeout=5)
        assert server.invalid == ["127.0.0.1"]
