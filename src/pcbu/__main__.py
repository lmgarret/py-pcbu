import asyncio
import io
import json
from pathlib import Path
from typing import Annotated, Any, Optional
import typer
import logging
from pcbu.helpers import get_ip
from pcbu.tcp.pair_client import TCPPairClient
from pcbu.tcp.pair_server import TCPPairServer
from pcbu.models import (
    PCPairingSecret,
    PairingQRData,
    PacketPairResponse,
)
from qrcode.main import QRCode

from pcbu.tcp.unlock_server import TCPUnlockServer

app = typer.Typer(pretty_exceptions_show_locals=False)

LOGGER = logging.getLogger(__name__)

CONF_PAIRING_DATA = "pairing_data"
CONF_PAIRING_RESPONSE = "pairing_response"
CONF_PAIRINGS = "paired_pcs"

# may be overidden by --conf option
_CONF_PATH: Path = Path("conf.local.json")


def print_qr(data: str):
    qr = QRCode(border=2)
    qr.add_data(data)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    LOGGER.info(f.read())


def load_conf() -> dict[str, Any]:
    if not _CONF_PATH.exists():
        LOGGER.info(f"Conf file {_CONF_PATH} does not exist")
        raise typer.Exit(code=1)
    with open(_CONF_PATH) as f:
        return json.load(f)


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Logs in debug mode"),
    conf: Annotated[
        Path,
        typer.Option("--conf", "-c", help="Path to a local conf file."),
    ] = _CONF_PATH,
):
    global _CONF_PATH
    _CONF_PATH = conf

    lvl = logging.INFO
    fmt = "%(message)s"
    if verbose:
        lvl = logging.DEBUG
    logging.basicConfig(level=lvl, format=fmt)


@app.command()
def pair_server(
    ip: Annotated[
        str,
        typer.Option(
            help="IP to bind to. Defaults to the 'pairing_data.ip' value in the conf file."
            " 'auto' will derive the IP automatically."
        ),
    ] = "",
):
    conf = load_conf()
    if CONF_PAIRING_DATA not in conf:
        LOGGER.info(f"Conf file is missing a '{CONF_PAIRING_DATA}' section.")
        raise typer.Exit(code=1)
    if CONF_PAIRING_RESPONSE not in conf:
        LOGGER.info(f"Conf file is missing a '{CONF_PAIRING_RESPONSE}' section.")
        raise typer.Exit(code=1)

    pairing_data: PairingQRData = PairingQRData.from_dict(conf[CONF_PAIRING_DATA])
    pairing_response: PacketPairResponse = PacketPairResponse.from_dict(
        conf[CONF_PAIRING_RESPONSE]
    )

    if ip:
        LOGGER.debug(
            f"IP {ip} was given in CLI, will bind to it instead of the conf one."
        )
        if ip == "auto":
            ip = get_ip()
            LOGGER.debug(f"'auto' was passed as IP, will automatically bind to {ip}.")
        pairing_data.ip = ip
        pairing_response.host_address = ip

    LOGGER.info("You can scan the following QR Code with the PCBU mobile app:")
    print_qr(json.dumps(pairing_data.to_dict()))

    async def _astart_server():
        async with TCPPairServer(
            pairing_qr_data=pairing_data, pairing_response=pairing_response
        ) as server:
            await server.start()

    asyncio.run(_astart_server())


@app.command()
def pair_client(
    device_name: Annotated[
        Optional[str],
        typer.Option(
            "-n", help="Override this client's name. Defaults to the host name."
        ),
    ] = None,
    timeout: Annotated[
        int,
        typer.Option(help="Timeout for packet exchange, in seconds."),
    ] = 5,
    show_password: Annotated[
        bool,
        typer.Option(
            "-k",
            help="Prints the whole PairingResponse, including the password. !DANGER!",
        ),
    ] = False,
):
    conf = load_conf()
    if CONF_PAIRING_DATA not in conf:
        LOGGER.info(f"Conf file is missing a '{CONF_PAIRING_DATA}' section.")
        raise typer.Exit(code=1)

    pairing_data: PairingQRData = PairingQRData.from_dict(conf[CONF_PAIRING_DATA])

    async def _apair():
        client = TCPPairClient(pairing_qr_data=pairing_data, device_name=device_name)
        LOGGER.info(f"Start pairing with {pairing_data.ip}:{pairing_data.port}...")
        response: PacketPairResponse = await client.pair(timeout=float(timeout))
        LOGGER.info("Received: ")
        if not show_password:
            # mask password
            response.password = ""
        LOGGER.info(response)

        LOGGER.info(
            f"Successfully paired with {response.host_name} ({response.host_address})."
        )

    asyncio.run(_apair())


@app.command()
def unlock_server(
    ip: Annotated[
        str,
        typer.Option(
            help="IP to bind to. Defaults to the 'pairing_data.ip' value in the conf file."
            " 'auto' will derive the IP automatically."
        ),
    ] = "",
):
    conf = load_conf()
    if CONF_PAIRINGS not in conf:
        LOGGER.info(f"Conf file is missing a '{CONF_PAIRINGS}' section.")
        raise typer.Exit(code=1)

    pairings: list[PCPairingSecret] = [
        PCPairingSecret.from_dict(d) for d in conf[CONF_PAIRINGS]
    ]

    if ip:
        LOGGER.debug(
            f"IP {ip} was given in CLI, will bind to it instead of the conf one."
        )
        if ip == "auto":
            ip = get_ip()
            LOGGER.debug(f"'auto' was passed as IP, will automatically bind to {ip}.")
        for pairing in pairings:
            pairing.server_ip_address = ip

    async def _astart_server():
        async with TCPUnlockServer(pc_pairings=pairings) as server:
            await server.start()

    asyncio.run(_astart_server())


if __name__ == "__main__":
    app()
