"""Pytest configuration, fixtures, and FastAPI test client setup."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.api.app import app
from tests.fixtures.generate_synthetic_eml import (
    create_clean_eml,
    create_phishing_obfuscated_eml,
    create_quishing_eml,
)


@pytest.fixture(scope="session")
def client():
    """FastAPI TestClient instance."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def clean_eml_bytes() -> bytes:
    return create_clean_eml()


@pytest.fixture
def phishing_eml_bytes() -> bytes:
    return create_phishing_obfuscated_eml()


@pytest.fixture
def quishing_eml_bytes() -> bytes:
    return create_quishing_eml()


@pytest.fixture
def temp_storage(tmp_path) -> str:
    storage_dir = tmp_path / "cybertrace_test_data"
    storage_dir.mkdir(parents=True, exist_ok=True)
    return str(storage_dir)
