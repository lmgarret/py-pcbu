import asyncio
import io
import json
from pathlib import Path
from typing import Annotated
import typer
import logging
from pcbu.helpers import get_ip
from pcbu.tcp.pair_server import TCPPairServer
from pcbu.models import PairingQRData, PacketPairResponse
from qrcode.main import QRCode

app = typer.Typer(pretty_exceptions_show_locals=False)

LOGGER = logging.getLogger(__name__)

CONF_PAIRING_DATA = "pairing_data"
CONF_PAIRING_RESPONSE = "pairing_response"

# may be overidden by --conf option
_CONF_PATH: Path = Path("conf.local.json")


def print_qr(data: str):
    qr = QRCode(border=2)
    qr.add_data(data)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    LOGGER.info(f.read())


def load_conf() -> dict[str, any]:
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
    if ip == "auto":
        auto_ip = get_ip()
        LOGGER.debug(f"'auto' was passed as IP, will automatically bind to {auto_ip}.")
        pairing_data.ip = auto_ip
        pairing_response.host_address = auto_ip
    elif ip != "":
        LOGGER.debug(
            f"IP {ip} was given in CLI, will bind to it instead of the conf one."
        )
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


if __name__ == "__main__":
    app()