# /pay QR initialization regression checks

The setup address must be rendered when `/pay` first loads. An existing offer,
including one selected while the configuration request is pending, takes priority.
Refreshing the QR uses the same active value. Clearing the offer restores the
configured address.

Run from the repository root with Python 3 and Node.js 22:

```sh
python3 -m unittest discover -s app/tests -p 'test_pay_qr_runtime.py' -v
```

The eight tests execute the shipped JavaScript functions, initialization call and
refresh listener extracted from `app/frontend/admin/index.html`. Only browser DOM,
configuration fetch and QR drawing boundaries are faked. They also cover config
aliases, config errors and delayed QR library availability. They require no npm
packages. CI installs Node explicitly and includes these tests in its Python suite.

Replacing `renderOfferQr(getActiveValue())` in the configuration loader with the
old `renderQr(DEFAULT_ADDRESS)` causes the initialization assertions to fail.

For the complete Python application suite, install `app/requirements.txt` in a
virtual environment and run from `app` with an isolated data directory:

```sh
APP_DATA_DIR=/tmp/lndk-pay-test-data python -m unittest discover -s tests -p 'test_*.py' -v
```

These are local function-level regression checks, not a real-browser QR scan or
an on-device Android test. They do not initiate payments or require a wallet.
