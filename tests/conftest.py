"""Shared fixtures for the GUE dissector tests."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DISSECTOR = REPO_ROOT / "gue.lua"
CAPTURES = REPO_ROOT / "captures"


@pytest.fixture(scope="session")
def tshark() -> str:
    """Path to a tshark built with Lua support."""
    path = os.environ.get("TSHARK") or shutil.which("tshark")
    if path is None:
        pytest.skip("tshark not found; set TSHARK to point at one")

    version = subprocess.run([path, "-v"], capture_output=True, text=True, check=True).stdout
    if "with Lua" not in version:
        pytest.skip(f"{path} was built without Lua support")
    return path


@pytest.fixture(scope="session")
def dissect(tshark):
    """Run the dissector over a capture and return the requested fields.

    Yields one list of field values per packet, in capture order.
    """

    def run(capture: str, fields, display_filter: str | None = None):
        args = [
            tshark,
            "-X",
            f"lua_script:{DISSECTOR}",
            "-r",
            str(CAPTURES / capture),
            "-Tfields",
        ]
        if display_filter is not None:
            args += ["-Y", display_filter]
        for field in fields:
            args += ["-e", field]

        stdout = subprocess.run(args, capture_output=True, text=True, check=True).stdout
        return [line.split("\t") for line in stdout.splitlines()]

    return run
