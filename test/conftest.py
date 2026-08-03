# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import contextlib
import fcntl
import os
import subprocess
import tempfile

import pytest

BIN_ABS_DIR = os.path.join(os.path.dirname(__file__), "bin")

CLAB_TIMEOUT = 900

# Serialize containerlab deploy/destroy to avoid Docker races during
# concurrent container creation ("failed to set IPv6 gateway: file exists").
CLAB_LOCK_PATH = os.path.join(tempfile.gettempdir(), "pola-clab.lock")


@contextlib.contextmanager
def clab_lock():
    with open(CLAB_LOCK_PATH, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


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


def _clab_deploy():
    lab_dirs = []

    def deploy(lab_dir="."):
        lab_dirs.append(lab_dir)
        print("start containerlab")
        with clab_lock():
            subprocess.run(
                ["clab", "deploy", "--reconfigure"],
                check=True,
                cwd=lab_dir,
                timeout=CLAB_TIMEOUT,
            )

    yield deploy

    for lab_dir in lab_dirs:
        print("finish containerlab")
        try:
            with clab_lock():
                subprocess.run(
                    ["clab", "destroy", "--cleanup"],
                    check=False,
                    cwd=lab_dir,
                    timeout=CLAB_TIMEOUT,
                )
        except subprocess.TimeoutExpired:
            print(f"WARNING: clab destroy timed out in {lab_dir}")


@pytest.fixture(scope="function")
def clab_deploy():
    yield from _clab_deploy()


@pytest.fixture(scope="module")
def clab_deploy_module():
    """Deploy a lab once per test module instead of once per test.

    Every test must keep its state independent of the others, for example by
    installing SR Policies with distinct colors.
    """

    yield from _clab_deploy()
