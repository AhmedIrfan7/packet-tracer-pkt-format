# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 packet-tracer-pkt-format contributors
# This file is part of packet-tracer-pkt-format (GPL-3.0-or-later).
"""Shared fixtures: the JASDF enterprise artefacts.

``test_audit``, ``test_layout`` and ``test_power`` regression-test the two
JASDF-AEWC builds (enterprise, 290 devices; standard, 199 devices).  They used
to read them from a directory on the maintainer's machine, so everywhere else
-- CI included -- they skipped.  The vendored generator rebuilds both files
byte-for-byte (the hashes are pinned in ``generators/jasdf_aewc/build/``), so
by default they are built once per session into a temporary directory.

Set ``ARTEFACT_DIR`` to test existing copies instead, e.g. the delivered files.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GENERATOR = REPO / "generators" / "jasdf_aewc" / "build_jasdf_aewc.py"

# artefact file name -> generator profile
PROFILES = {
    "JASDF_AEWC_JADGE.pkt": "enterprise",
    "JASDF_AEWC_JADGE_standard.pkt": "standard",
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
    env = dict(os.environ, PKT_TOOLKIT=str(REPO))
    for name, profile in PROFILES.items():
        out = out_dir / name
        # --report/--inventory default to tracked files under generators/,
        # so point them into the temp directory to keep the checkout clean
        proc = subprocess.run(
            [sys.executable, str(GENERATOR), "--profile", profile,
             "--out", str(out), "--report", str(out.with_suffix(".json")),
             "--inventory", str(out.with_suffix(".csv"))],
            capture_output=True, text=True, env=env, timeout=600,
        )
        assert proc.returncode == 0, proc.stderr + proc.stdout
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
