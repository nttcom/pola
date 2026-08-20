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
        check=False,
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
                    f"Timeout waiting for SSH to {hostname}\nLast error: {last_error!r}"
                )

            print(f"Waiting for SSH to {hostname}... last error: {last_error!r}")
            time.sleep(interval)


def wait_until_command_success(
    cmd: str,
    timeout: int = 1200,
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


def wait_until_command_output_contains(
    cmd: str,
    expected: str,
    timeout: int = 300,
    interval: int = 5,
) -> subprocess.CompletedProcess:
    """Wait until the stdout of a command contains the expected text."""

    start = time.time()

    while True:
        result = run_command(cmd)

        if expected in result.stdout:
            return result

        if time.time() - start > timeout:
            raise TimeoutError(
                f"Timeout waiting for {expected!r} in the output of {cmd!r}\n"
                f"Last output:\n{result.stdout}"
            )

        print(f"Waiting for {expected!r} in the output of {cmd!r}...")
        time.sleep(interval)


def get_ted(pola_container: str) -> list:
    """Get current TED JSON (a list of nodes). Raises RuntimeError/JSONDecodeError on failure."""

    cmd = f"docker exec {pola_container} /bin/pola -p 50052 ted -j"
    result = run_command(cmd)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to get TED:\n{result.stderr}")

    return json.loads(result.stdout)


def wait_until_ted(
    pola_container: str,
    predicate: Callable[[list], bool],
    timeout: int = 600,
    interval: int = 5,
) -> list:
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
        present = {node.get("routerId") for node in ted}
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

        for node in ted:
            local = node.get("routerId")
            for link in node.get("links", []):
                remote = link.get("remoteRouterId")
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
    """Wait until TED JSON matches expected."""

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


def wait_until_ssh_output_contains(
    ssh_client: paramiko.SSHClient,
    command: str,
    expected: str,
    timeout: int = 300,
    interval: int = 5,
) -> str:
    """Wait until the output of a command run over SSH contains the expected text."""

    start = time.time()
    last_output = ""

    while True:
        _, stdout, _ = ssh_client.exec_command(command)
        last_output = stdout.read().decode()

        if expected in last_output:
            return last_output

        if time.time() - start > timeout:
            raise TimeoutError(
                f"Timeout waiting for {expected!r} in the output of {command!r}\n"
                f"Last output:\n{last_output}"
            )

        print(f"Waiting for {expected!r} in the output of {command!r}...")
        time.sleep(interval)
