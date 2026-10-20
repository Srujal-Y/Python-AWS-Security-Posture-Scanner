import json
from importlib.resources import files

import pytest

from posture_scanner.cli import load_inventory


@pytest.fixture
def demo():
    return load_inventory(files("posture_scanner").joinpath("data/demo.json"))


@pytest.fixture
def demo_raw():
    return json.loads(files("posture_scanner").joinpath("data/demo.json").read_text())


@pytest.fixture(autouse=True)
def no_credential_discovery(monkeypatch):
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
