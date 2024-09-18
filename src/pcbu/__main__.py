import io
import json
from pathlib import Path
import typer
import logging
from pcbu.tcp.pair_server import TCPPairServer
from pcbu.models import PairingQRData, PacketPairResponse
from qrcode.main import QRCode

app = typer.Typer(pretty_exceptions_show_locals=False)

CONF_PAIRING_DATA = "pairing_data"
CONF_PAIRING_RESPONSE = "pairing_response"


def print_qr(data: str):
    qr = QRCode(border=2)
    qr.add_data(data)
    f = io.StringIO()
    qr.print_ascii(out=f)
    f.seek(0)
    print(f.read())


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")):
    lvl = logging.INFO
    fmt = "%(message)s"
    if verbose:
        lvl = logging.DEBUG
    logging.basicConfig(level=lvl, format=fmt)


@app.command()
def pair_server(conf_file_path: Path = Path("conf.local.json")):
    if not conf_file_path.exists():
        print(f"Conf file {conf_file_path} does not exist")
        raise typer.Exit(code=1)

    with open(conf_file_path) as f:
        conf = json.load(f)
        if CONF_PAIRING_DATA not in conf:
            print(f"Conf file is missing a '{CONF_PAIRING_DATA}' section.")
            raise typer.Exit(code=1)
        if CONF_PAIRING_RESPONSE not in conf:
            print(f"Conf file is missing a '{CONF_PAIRING_RESPONSE}' section.")
            raise typer.Exit(code=1)

        pairing_data_json = conf[CONF_PAIRING_DATA]
        pairing_data: PairingQRData = PairingQRData.from_dict(pairing_data_json)
        pairing_response: PacketPairResponse = PacketPairResponse.from_dict(
            conf[CONF_PAIRING_RESPONSE]
        )

    print("You can scan the following QR Code with the PCBU mobile app:")
    print_qr(json.dumps(pairing_data_json))

    server = TCPPairServer(
        pairing_qr_data=pairing_data, pairing_response=pairing_response
    )
    server.start()


if __name__ == "__main__":
    app()
