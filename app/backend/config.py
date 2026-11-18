import copy
import json
import os
import tempfile

CONFIG_PATH = os.getenv("APP_CONFIG_PATH", "/data/config.json")


DEFAULT_CONFIG = {
    "public_bolt12_address": "bolt12@pay.local",
    "bip353_base_domain": "",  # Empty on legacy installs: derive from the public address.
    "public_lnurl_address": "lnurl@pay.local",
    "lnurl_base_domain": "",
    "lnurl_base_url": "",
    "payment_mode": "compatibility",  # compatibility | privacy
    "dns_mode": "none",   # none | manual | cloudflare
    "ui_password_hash": "",
    "cloudflare": {
        "enabled": False,
        "zone_name": "",
        "zone_id": "",
        "api_token": ""
    },
    "lightning_backend": {"active": "lnd-default", "phoenixd": None},
    "aliases": {}
}


def _deep_merge(defaults, current):
    if not isinstance(defaults, dict):
        return current

    merged = copy.deepcopy(defaults)
    for key, value in (current or {}).items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return copy.deepcopy(DEFAULT_CONFIG)

    with open(CONFIG_PATH, "r") as f:
        current = json.load(f)

    return _deep_merge(DEFAULT_CONFIG, current)


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    # Atomic, owner-only file: configuration contains backend API credentials.
    fd, temporary = tempfile.mkstemp(prefix=".config-", dir=os.path.dirname(CONFIG_PATH))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, CONFIG_PATH)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
