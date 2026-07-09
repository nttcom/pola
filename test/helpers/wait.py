# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import json
import subprocess
import time
from collections.abc import Callable

import paramiko
from deepdiff import DeepDiff


def run_command(cmd: str) -> subprocess.CompletedProcess:
    """Run shell command."""

    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
    )


def wait_for_ssh(
    hostname: str,
    username: str = "admin",
    password: str = "admin@123",
    timeout: int = 180,
    interval: int = 5,
) -> paramiko.SSHClient:
    """Wait until SSH is available."""

    start = time.time()
    last_error: Exception | None = None

    while True:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(
                hostname=hostname,
                username=username,
                password=password,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            return ssh

        except (paramiko.SSHException, OSError) as e:
            last_error = e
            ssh.close()

            if time.time() - start > timeout:
                raise TimeoutError(
                    f"Timeout waiting for SSH to {hostname}\n"
                    f"Last error: {repr(last_error)}"
                )

            print(f"Waiting for SSH to {hostname}... last error: {repr(last_error)}")
            time.sleep(interval)


def wait_until_command_success(
    cmd: str,
    timeout: int = 600,
    interval: int = 5,
) -> subprocess.CompletedProcess:
    """Wait until command exits successfully."""

    start = time.time()

    while True:
        result = run_command(cmd)

        if result.returncode == 0:
            return result

        if time.time() - start > timeout:
            raise TimeoutError(f"Timeout waiting for command:\n{cmd}")

        time.sleep(interval)


def get_ted(pola_container: str) -> dict:
    """Get current TED JSON. Raises RuntimeError/JSONDecodeError on failure."""

    cmd = f"docker exec {pola_container} /bin/pola -p 50052 ted -j"
    result = run_command(cmd)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to get TED:\n{result.stderr}")

    return json.loads(result.stdout)


def wait_until_ted(
    pola_container: str,
    predicate: Callable[[dict], bool],
    timeout: int = 600,
    interval: int = 5,
) -> dict:
    """Wait until predicate(ted_json) becomes True."""

    start = time.time()

    while True:
        try:
            ted = get_ted(pola_container)

            if predicate(ted):
                return ted

        except (RuntimeError, json.JSONDecodeError) as e:
            print(f"Waiting for TED (not ready yet): {e}")

        if time.time() - start > timeout:
            raise TimeoutError("Timeout waiting for TED state")

        time.sleep(interval)


def wait_until_ted_has_routers(
    pola_container: str,
    router_ids: list[str],
    timeout: int = 600,
    interval: int = 5,
) -> dict:
    """Wait until TED contains all router IDs."""

    router_ids = set(router_ids)

    def predicate(ted):

        present = {node.get("routerID") for node in ted.get("ted", [])}

        missing = router_ids - present

        if missing:
            print(f"Waiting for routers: {missing}")

        return not missing

    return wait_until_ted(
        pola_container,
        predicate,
        timeout,
        interval,
    )


def wait_until_ted_has_links(
    pola_container: str,
    expected_links: set[frozenset[str]],
    timeout: int = 600,
    interval: int = 5,
) -> dict:
    """Wait until TED contains all expected links."""

    def predicate(ted):
        found = set()

        for node in ted.get("ted", []):
            local = node.get("routerID")
            for link in node.get("links", []):
                remote = link.get("remoteNode")
                if local and remote:
                    found.add(frozenset((local, remote)))

        missing = expected_links - found

        if missing:
            print(f"Waiting for TED links: {missing}")

        return not missing

    return wait_until_ted(
        pola_container,
        predicate,
        timeout,
        interval,
    )


def wait_until_ted_matches(
    pola_container: str,
    expected: dict,
    timeout: int = 600,
    interval: int = 5,
) -> dict:
    """
    Wait until TED JSON matches expected.
    """

    def predicate(ted):

        diff = DeepDiff(
            ted,
            expected,
            ignore_order=True,
        )

        if diff:
            print(f"Waiting for TED update:\n{diff}")

        return diff == {}

    return wait_until_ted(
        pola_container,
        predicate,
        timeout,
        interval,
    )


def wait_until_lsp_up(
    ssh_client: paramiko.SSHClient,
    lsp_name: str,
    timeout: int = 300,
    interval: int = 5,
) -> str:
    """Wait until the named LSP becomes Up."""

    start = time.time()

    while True:
        _, stdout, _ = ssh_client.exec_command(
            f"show spring-traffic-engineering lsp name {lsp_name} detail"
        )
        output = stdout.read().decode()

        if lsp_name in output and "State: Up" in output:
            return output

        if time.time() - start > timeout:
            raise TimeoutError(f"Timeout waiting for LSP {lsp_name} to become Up")

        print(f"Waiting for LSP {lsp_name} to become Up...")
        time.sleep(interval)
