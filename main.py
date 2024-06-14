import logging
import socketserver
import sys
from hass_pcbu.tcp_server import TCPHandler

LOGGER = logging.getLogger(__name__)

if __name__ == "__main__":
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    HOST, PORT = "", 43298

    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        LOGGER.info(f"Started server on {HOST}:{PORT}")
        server.serve_forever()