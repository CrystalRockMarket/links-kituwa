"""Run the browser crypto test under Node, so the client contract is tested."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_browser_crypto_round_trip():
    result = subprocess.run(["node", str(ROOT / "tests" / "crypto.test.mjs")],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
