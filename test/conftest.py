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
    """Ensure required binaries exist and are executable before any test runs."""

    for binname in ["gobgpd", "polad", "pola"]:
        path = os.path.join(BIN_ABS_DIR, binname)

        assert os.path.exists(path), f"{path} does not exist"
        assert os.access(path, os.X_OK), f"{path} is not executable"


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
