# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0
"""Small packaged contract shared by client guides, the hook and hosted setup."""

import json
import re
from importlib.resources import files


def _manifest() -> dict:
    return json.loads(files("vt_mcp").joinpath("client_contracts.json").read_text("utf-8"))


def claude_code_contract() -> dict:
    """Return independent setup data; this first segment does not describe every client."""
    return _manifest()["claude_code"]


def credential_filename_denied(name: str) -> bool:
    """Recognize credential basenames, including Windows names received on another OS.

    This is a short filename precaution, not a content scanner or permission grant.
    """
    if not isinstance(name, str):
        return False
    basename = name.rsplit("/", 1)[-1]
    pattern = re.compile(_manifest()["credential_filename_pattern"], re.I | re.S | re.ASCII)
    return any(pattern.search(value) for value in (basename, basename.rsplit("\\", 1)[-1]))
