# py-pcbu

This library simplifies interactions with [PC Bio Unlock](https://github.com/MeisApps/pcbu-desktop) by implementing its protocol.

## Usage
### Pairing

1. First, install [PC Bio Unlock](https://meis-apps.com/pc-bio-unlock/how-to-install) normally. Currently, versions >2.0.0 are supported, probably lower versions too.
2. In the desktop app, click on `Pair device`. Go through the wizard steps, until you reach the QR Code.
3. Get the JSON string out of the QR Code. On Android, I can only recommend using  the FOSS app https://gitlab.com/Atharok/BarcodeScanner
4. Write a `TCPPairClient` as follows:
```python
from pcbu.tcp.pair_client import TCPPairClient
from pcbu.models import PairingQRData

pairing_data = PairingQRData.from_json(your_qr_json_string_here)

client = TCPPairClient(pairing_qr_data=pairing_data, device_name="The name of the device authorizing unlocks")
pair_response = client.pair()
print(pair_response)
```

This snippet prints in plaintext the payload received from the desktop. It contains **sensitive informations** such as your account password! So make sure to store it somewhere safe

### Unlocking
py-pcbu gives you a base class to create a server listening for TCP unlock requests. Here is a minimalistic code to get it up and running:
```python
from pcbu.models import PCPairing, PCPairingSecret
from pcbu.tcp.unlock_server import TCPUnlockServerBase

pairings_dicts =   [
    {
        "server_ip_address": "192.168.1.Y",
        "server_port": 43296,
        "pairing_id": "abcdef",
        "desktop_ip_address": "192.168.1.X",
        "encryption_key": "some_super_long_key",
        "username": "user1@desktop",
        "password": "pwd1"
    },
    {
        "server_ip_address": "192.168.2.Z",
        "server_port": 43296,
        "pairing_id": "ghijk",
        "desktop_ip_address": "192.168.1.X",
        "encryption_key": "another_super_long_key",
        "username": "user2@desktop",
        "password": "pwd2"
    }
]
pc_pairings = [PCPairingSecret.from_dict(d) for d in pairing_dicts]

class TCPUnlockServer(TCPUnlockServerBase):

    def on_valid_unlock_request(self, pairing: PCPairing) -> bool:
        print(f"Accepting unlock request from {pairing.desktop_ip_address}!")
        return True

with TCPUnlockServer(pc_pairings) as server:
    server.listen()
```

This snippet will start a `TCPUnlockServer` listening on each of the `server_ip_address` from the `PCPairingSecret` list, using port `43298` by default (same as PC Bio Unlock's default).
When the server receivces an unlocking request, it will validate that the requestee's ip addres matches one of the `PCPairingSecret` instances, decrypt the unlock request, and call `on_valid_unlock_request` which you have to implement.
In this snippet, the implementation of `on_valid_unlock_request` automatically accepts the unlocking request, but you could add more external conditions to allow it.

## Development
For easier development, we include two scripts with VSCode launch configuration:
 - `scripts/test_pair.py`
 - `scripts/test_unlock.py`

Both scripts expect a gitignored `conf.local.json` file at the root of the repository. You can `cp conf.template.json conf.local.json` to get a base file to start from.

## Releasing
Releases are automatically created when a change to `version` in `pyproject.toml` is detected. The new files are automatically uploaded to PyPI and the signed release is uploaded to GitHub Releases.
The current steps to release are:
1. Make sure `pyproject.toml` is updated with the new version
2. Using [cucumber/changelog](https://github.com/cucumber/changelog), add the changes and update `CHANGELOG.md` with the new version
```console
./changelog -o CHANGELOG.md added "Add this and that"
./changelog -o CHANGELOG.md release 0.1.2
```
3. Commit the pyproject.toml and CHANGELOG.md changes
4. Push the changes to GitHub
5. Wait for the release to be published on PyPI
6. Wait for the release to be published on GitHub Releases
