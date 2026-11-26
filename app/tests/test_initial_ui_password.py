import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend import app as backend, config

APP = Path(__file__).resolve().parents[1]
INITIAL_PASSWORD = "test-initial-password"


class InitialUiPasswordTests(unittest.TestCase):
    def setUp(self):
        temp_dir = TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        tmp_path = Path(temp_dir.name)
        config_path = tmp_path / "config.json"
        ready = tmp_path / "server-started"
        uvicorn = tmp_path / "uvicorn"
        uvicorn.write_text(
            '#!/bin/sh\n'
            'test "${BOLT12_PAY_INITIAL_PASSWORD+x}" != x || exit 78\n'
            'touch "$APP_DATA_DIR/server-started"\n'
        )
        uvicorn.chmod(0o700)
        env = {
            **os.environ,
            "APP_DATA_DIR": str(tmp_path),
            "APP_CONFIG_PATH": str(config_path),
            "PATH": os.pathsep.join([str(tmp_path), str(Path(sys.executable).parent), os.environ["PATH"]]),
        }
        env.pop("BOLT12_PAY_INITIAL_PASSWORD", None)
        env.pop("PAY_UI_PASSWORD", None)

        def run(**variables):
            ready.unlink(missing_ok=True)
            return subprocess.run(
                ["sh", str(APP / "entrypoint.sh")], cwd=APP, env=env | variables,
                text=True, capture_output=True, timeout=10,
            )

        self.config_path = config_path
        self.ready = ready
        self.run_entrypoint = run

    def test_initial_password_protects_first_setup_request_and_unlocks_nwc(self):
        config_path, ready = self.config_path, self.ready
        result = self.run_entrypoint(BOLT12_PAY_INITIAL_PASSWORD=INITIAL_PASSWORD)
        assert result.returncode == 0, result.stderr
        assert ready.exists()
        assert INITIAL_PASSWORD not in result.stdout + result.stderr
        assert INITIAL_PASSWORD not in config_path.read_text()
        assert json.loads(config_path.read_text())["ui_password_hash"] == hashlib.sha256(
            INITIAL_PASSWORD.encode()
        ).hexdigest()

        self.enterContext(patch.object(config, "CONFIG_PATH", str(config_path)))
        self.enterContext(patch.multiple(backend, PAY_UI_PASSWORD="", PAY_SESSIONS={}, NWC_SESSIONS={}))
        client = TestClient(backend.app, base_url="https://testserver")
        self.addCleanup(client.close)

        assert client.get("/api/setup/config").status_code == 401
        assert client.post("/api/setup/config", json={"password": "different-password"}).status_code == 401
        assert client.post("/api/auth/login", json={"password": INITIAL_PASSWORD}).status_code == 200
        assert client.get("/api/setup/config").status_code == 200
        csrf = {"X-CSRF-Token": client.cookies["csrf_token"]}
        assert client.post("/api/admin/nwc/unlock", json={"password": INITIAL_PASSWORD}).status_code == 403
        assert client.post("/api/admin/nwc/unlock", json={"password": INITIAL_PASSWORD}, headers=csrf).status_code == 200

    def test_restart_preserves_saved_password_and_config(self):
        config_path, ready = self.config_path, self.ready
        before = json.dumps({"ui_password_hash": config.hash_ui_password("owner-password"),
                             "aliases": {"example": {"backend_id": "lnd-default"}}})
        config_path.write_text(before)

        result = self.run_entrypoint(BOLT12_PAY_INITIAL_PASSWORD=INITIAL_PASSWORD)
        assert result.returncode == 0, result.stderr
        assert ready.exists()
        assert config_path.read_text() == before

    def test_enabling_bootstrap_preserves_legacy_environment_password(self):
        config_path, ready = self.config_path, self.ready
        result = self.run_entrypoint(BOLT12_PAY_INITIAL_PASSWORD=INITIAL_PASSWORD, PAY_UI_PASSWORD="legacy-password")
        assert result.returncode == 0, result.stderr
        assert ready.exists()
        assert json.loads(config_path.read_text())["ui_password_hash"] == config.hash_ui_password("legacy-password")

    def test_explicit_empty_password_stops_startup(self):
        ready = self.ready
        result = self.run_entrypoint(BOLT12_PAY_INITIAL_PASSWORD=" ")
        assert result.returncode != 0
        assert "initial BOLT12 Pay password is empty" in result.stderr
        assert not ready.exists()

    def test_standalone_install_keeps_normal_setup_without_opt_in(self):
        config_path, ready = self.config_path, self.ready
        config_path.write_text('{"ui_password_hash": ""}')
        result = self.run_entrypoint()
        assert result.returncode == 0, result.stderr
        assert ready.exists()
        assert json.loads(config_path.read_text())["ui_password_hash"] == ""
