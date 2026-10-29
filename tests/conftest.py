# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 packet-tracer-pkt-format contributors
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Shared fixtures: the JASDF enterprise artefacts.

``test_audit``, ``test_layout`` and ``test_power`` regression-test the two
JASDF-AEWC builds (enterprise, 290 devices; standard, 199 devices).  They used
to read them from a directory on the maintainer's machine, so in CI (and
anywhere else without that directory) they skipped.  The vendored generator
rebuilds both files byte-for-byte, so by default they are built once per
session into a temporary directory, and each build must match the SHA-256
pinned in ``generators/jasdf_aewc/build/final_sha256*.txt``.

Set ``ARTEFACT_DIR`` to test existing copies instead, e.g. the delivered files.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GENERATOR = REPO / "generators" / "jasdf_aewc" / "build_jasdf_aewc.py"
PINS = REPO / "generators" / "jasdf_aewc" / "build"

# artefact file name -> (generator profile, file pinning its SHA-256)
PROFILES = {
    "JASDF_AEWC_JADGE.pkt": ("enterprise", "final_sha256.txt"),
    "JASDF_AEWC_JADGE_standard.pkt": ("standard", "final_sha256_standard.txt"),
}


@pytest.fixture(scope="session")
def jasdf_artefact_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """``$ARTEFACT_DIR`` if set, else a session directory the generator fills."""
    override = os.environ.get("ARTEFACT_DIR")
    if override:
        return Path(override)
    if not GENERATOR.exists():
        pytest.skip("vendored JASDF generator not available")
    out_dir = tmp_path_factory.mktemp("jasdf_artefacts")
    # build with this checkout's pkt_core, not whichever one is installed
    pythonpath = os.pathsep.join(
        p for p in (str(REPO / "src"), os.environ.get("PYTHONPATH")) if p
    )
    env = dict(os.environ, PKT_TOOLKIT=str(REPO), PYTHONPATH=pythonpath)
    for name, (profile, pin) in PROFILES.items():
        out = out_dir / name
        # --report/--inventory default to tracked files under generators/,
        # so point them into the temp directory to keep the checkout clean
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), "--profile", profile,
             "--out", str(out), "--report", str(out.with_suffix(".json")),
             "--inventory", str(out.with_suffix(".csv"))],
            capture_output=True, text=True, env=env, timeout=600,
        )
        # pytest.fail, not assert: it still fires under `python -O`
        if proc.returncode != 0:
            pytest.fail(f"generator failed for profile {profile!r}:\n"
                        f"{proc.stderr}{proc.stdout}", pytrace=False)
        digest = hashlib.sha256(out.read_bytes()).hexdigest()
        # sha256sum format: "<digest>  out/<name>"
        pinned = (PINS / pin).read_text().split()[0]
        if digest != pinned:
            pytest.fail(f"{name}: built {digest}, pinned {pinned} "
                        f"(generators/jasdf_aewc/build/{pin})", pytrace=False)
    return out_dir


@pytest.fixture(scope="session")
def jasdf_artefact(jasdf_artefact_dir: Path) -> Callable[[str], Path]:
    """Resolve an artefact by file name; skip if it is not there."""
    def resolve(name: str) -> Path:
        path = jasdf_artefact_dir / name
        if not path.is_file():
            pytest.skip(f"artefact not present: {path}")
        return path
    return resolve
