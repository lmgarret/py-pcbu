# py-pcbu

This library automates interactions with [PC Bio Unlock](https://github.com/MeisApps/pcbu-desktop) by implementing its protocol.

> [!CAUTION]
> PCBU and this library handles your accounts passwords. This project's license includes a NO-LIABILITY disclaimer that I won't repeat here. Please handle your account passwords responsibly!
> And always inspect projects that handle such sensitive data, even if they're FOSS.

## Installation
```bash
pip install py-pcbu
```

and if you plan on using the CLI, you also need to install the `cli` extra:

```bash
pip install py-pcbu[cli]
```

## Usage
### Pairing

1. First, install [PC Bio Unlock](https://meis-apps.com/pc-bio-unlock/how-to-install) normally. Currently, versions >2.0.0 are supported, probably lower versions too.
2. In the desktop app, click on `Pair device`. Go through the wizard steps, until you reach the QR Code.
3. Get the JSON string out of the QR Code. On Android, I can only recommend using  the FOSS app https://gitlab.com/Atharok/BarcodeScanner

Then we need to run the pair client using `py-pcbu`:

#### Option 1: `py-pcbu` as CLI

With a `conf.local.json` file similar to the `conf.template.json`, one can directly call:
```bash
python -m pcbu pair-client
```

#### Option 2: `py-pcbu` as library

Write a `TCPPairClient` as follows:
```python
from pcbu.tcp.pair_client import TCPPairClient
from pcbu.models import PairingQRData

pairing_data = PairingQRData.from_json(your_qr_json_string_here)

client = TCPPairClient(pairing_qr_data=pairing_data, device_name="My unlock program")
await pair_response = client.pair()
print(pair_response)
```

This snippet prints in plaintext the payload received from the desktop. It contains **sensitive informations** such as your account password! So make sure to store it somewhere safe.

### Unlocking
#### Option 1: `py-pcbu` as CLI

With a `conf.local.json` file similar to the `conf.template.json`, one can directly call:
```bash
python -m pcbu unlock-server
```

#### Option 2 `py-pcbu` as library
`py-pcbu` gives a simple `TCPUnlockServer` to run out of the box. It will automatically unlock any authenticated request matching a stored `pairing_id`:
```python
from pcbu.models import PCPairing, PCPairingSecret
from pcbu.tcp.unlock_server import TCPUnlockServer

pairings_dicts =   [
    {
        "server_ip_address": "192.168.1.Y",
        "server_port": 43296,
        "pairing_id": "abcdef",
        "desktop_ip_address": "192.168.1.Y",
        "encryption_key": "some_super_long_key",
        "username": "user1@desktop",
        "password": "pwd1"
    },
    {
        "server_ip_address": "192.168.1.Y",
        "server_port": 43297,
        "pairing_id": "ghijk",
        "desktop_ip_address": "192.168.2.Z",
        "encryption_key": "another_super_long_key",
        "username": "user2@desktop",
        "password": "pwd2"
    }
]
pc_pairings = [PCPairingSecret.from_dict(d) for d in pairing_dicts]

async with TCPUnlockServer(pc_pairings) as server:
    await server.start()
```

This snippet will start a `TCPUnlockServer` listening on each of the `server_ip_address`:`server_port` from the `PCPairingSecret` list (i.e. on both ports `43296` and `43297`).
When the server receives an unlocking request, it will validate that the requesting's ip address matches one of the `PCPairingSecret` instances, decrypt the unlock request, and call the callback method `TCPUnlockServerBase.on_valid_unlock_request` which automatically accepts the unlocking request in this `TCPUnlockServer` implementation.

For more advanced use cases, one can also extend `TCPUnlockServerBase` from `pcbu.tcp.unlock_server`. The following methods can be overriden to react to events on the unlock server:
 - `on_enter(self)`: called when the server's context is entered.
 - `on_start(self)`: called upon starting the server.
 - `on_valid_unlock_request(self, pairing: PCPairing)`: called when an unlock request has been authenticated and matches one of the registered PC pairings. The match is passed to the method. The basic `TCPUnlockServer` implementation directly calls `self.unlock(pairing)` in this method, but one can add other checks or defer the unlocking to a later time.
 - `on_invalid_unlock_request(self, ip: str)`: called when an unlock request could not be authenticated or matched against the registerd pairings. The requesting ip address is passed.
 - `on_exit(self)`: called when the server's context is exited, but just before exiting the individual TCP servers.


## Development
For easier development, we include several VSCode launch configuration to allow easier debugging:
 - `Pair Server`: runs the `pair-server` CLI command. Emulates a pairing server (i.e. emulates the desktop's PCBU app showing you the QR Code). Automatically binds to the host's ip address, ignoring the `.conf` one.
 - `Pair Client`: runs the `pair-client` CLI command. Expects a pairing server to be up, and initiates the pairing process.
 - `Unlock Server`: runs the `unlock-server` CLI command. Waits for unlock requests. Automatically binds to the host's ip address, ignoring the `.conf` one.

All commands expect a gitignored `conf.local.json` file at the root of the repository. You can `cp conf.template.json conf.local.json` to get a base file to start from. Some conf options can be overwritten via CLI options, see
```bash
python -m pcbu --help
```
for more info.

## TODOs
 - [X] Rewrite `TCPPairServer` with `asyncio`
 - [X] Rewrite `TCPPairClient` with `asyncio`
 - [X] Rewrite `TCPUnlockServer` with `asyncio`
 - [X] Write a `TCPUnlockClient` (i.e. emulating a Desktop requesting an unlock) with `asyncio`
 - [X] Add `pair-client` command (removing `scripts/test_pair.py`)
 - [X] Add `unlock-client` command
 - [ ] Handle more failure cases (e.g. rejected UnlockRequest on the client)

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
