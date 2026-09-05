import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from contracts import ScanTarget  # noqa: E402


@pytest.fixture(autouse=True)
def _chdir_root(monkeypatch):
    """Relative paths in fixtures/scenario resolve from the package root."""
    monkeypatch.chdir(ROOT)


@pytest.fixture
def fixtures_dir():
    return os.path.join(ROOT, "tests", "fixtures")


@pytest.fixture
def demo_target():
    return ScanTarget.from_json(os.path.join(ROOT, "demo", "scenario.json"))
