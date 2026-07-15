# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import os
import subprocess

import pytest

BIN_ABS_DIR = os.path.join(os.path.dirname(__file__), "bin")


@pytest.fixture(scope="session", autouse=True)
def check_binaries_ready():
    """Ensure required binaries exist and are executable before any test runs.

    Runs once per session. On failure, pytest reports it as a session-scoped
    setup error (not a per-test failure) — check the top of the traceback
    if tests appear to "not run" at all.
    """

    missing = []

    for binname in ["gobgpd", "polad", "pola"]:
        path = os.path.join(BIN_ABS_DIR, binname)

        if not os.path.exists(path):
            missing.append(f"{path} does not exist")
        elif not os.access(path, os.X_OK):
            missing.append(f"{path} is not executable")

    if missing:
        pytest.fail(
            "Required binaries are not ready:\n" + "\n".join(missing),
            pytrace=False,
        )


@pytest.fixture(scope="function")
def clab_deploy():
    lab_dirs = []

    def deploy(lab_dir="."):
        lab_dirs.append(lab_dir)
        print("start containerlab")
        subprocess.run(
            ["clab", "deploy", "--reconfigure"],
            check=True,
            cwd=lab_dir,
        )

    yield deploy

    for lab_dir in lab_dirs:
        print("finish containerlab")
        subprocess.run(
            ["clab", "destroy", "--cleanup"],
            check=False,
            cwd=lab_dir,
        )
