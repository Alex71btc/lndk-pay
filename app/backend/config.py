import json
import os

CONFIG_PATH = os.getenv("APP_CONFIG_PATH", "/data/config.json")


DEFAULT_CONFIG = {
    "public_bolt12_address": "bolt12@pay.local",
    "public_lnurl_address": "lnurl@pay.local",
    "lnurl_base_domain": "",
    "lnurl_base_url": "",
    "dns_mode": "none",   # none | manual | cloudflare
    "cloudflare": {
        "enabled": False,
        "zone_name": "",
        "zone_id": "",
        "api_token": ""
    }
}


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG

    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


def save_config(cfg):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
