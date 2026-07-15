import json
from pathlib import Path

import pytest

CONFORMANCE_DIR = Path(__file__).resolve().parents[2] / "conformance"


def load_vector(name: str) -> dict:
    path = CONFORMANCE_DIR / name
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def hex_decode(s: str) -> bytes:
    assert len(s) % 2 == 0, f"odd-length hex string: {s!r}"
    return bytes.fromhex(s)


@pytest.fixture(scope="session")
def keys():
    return load_vector("keys.json")


@pytest.fixture(scope="session")
def envelopes():
    return load_vector("envelopes.json")


@pytest.fixture(scope="session")
def callback_box():
    return load_vector("callback_box.json")


@pytest.fixture(scope="session")
def url_params():
    return load_vector("url_params.json")


@pytest.fixture(scope="session")
def dns_vectors():
    return load_vector("dns.json")


@pytest.fixture(scope="session")
def tickets():
    return load_vector("tickets.json")


@pytest.fixture(scope="session")
def expirations():
    return load_vector("expirations.json")
