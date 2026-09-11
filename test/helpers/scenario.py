# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import ipaddress
import json
import os
import re
import subprocess

from helpers.wait import (
    run_command,
    wait_for_ssh,
    wait_until_command_output_contains,
    wait_until_command_success,
    wait_until_lsp_up,
    wait_until_ssh_output_contains,
    wait_until_ted_contains,
    wait_until_ted_has_links,
    wait_until_ted_has_routers,
)

GRPC_PORT = 50052


def lab_dir_of(test_file: str) -> str:
    """Return the absolute lab directory for a test file."""

    return os.path.abspath(os.path.dirname(test_file))


def load_expected(lab_dir: str) -> list:
    """Load the expected TED fixture for a lab."""

    with open(os.path.join(lab_dir, "expected", "ted.json")) as f:
        return json.load(f)


def wait_for_pcep_sessions(pola: str, addrs: list[str]) -> None:
    """Wait for all PCEP sessions to appear in `pola session`."""

    for addr in addrs:
        wait_until_command_success(
            f"docker exec {pola} /bin/pola session -p {GRPC_PORT} | grep '{addr}'"
        )


def deploy_lab(
    clab_deploy_module,
    lab_dir: str,
    pola: str,
    pcep_addrs: list[str],
    router_ids: list[str],
    links: set,
    expected=None,
) -> None:
    """Deploy a lab and wait until the expected TED entries are present."""

    clab_deploy_module(lab_dir)

    print("Waiting for PCEP sessions")
    wait_for_pcep_sessions(pola, pcep_addrs)

    if not router_ids:
        return

    wait_until_ted_has_routers(pola, router_ids)
    wait_until_ted_has_links(pola, links)
    wait_until_ted_contains(
        pola, expected if expected is not None else load_expected(lab_dir)
    )


def add_sr_policy(pola: str, policy_file: str, no_sid_validate: bool = False) -> None:
    """Install an SR Policy via `pola sr-policy add`."""

    cmd = f"docker exec {pola} /bin/pola sr-policy add -f {policy_file} -p {GRPC_PORT}"
    if no_sid_validate:
        cmd += " --no-sid-validate"

    result = run_command(cmd)

    assert "success" in result.stdout.lower(), (
        f"failed to add {policy_file}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    if no_sid_validate:
        assert "skipping SID validation" in result.stderr, (
            f"--no-sid-validate must always warn on stderr\nstderr: {result.stderr}"
        )


def add_sr_policy_expecting_error(
    pola: str, policy_file: str, expected_substrings: list[str]
) -> str:
    """Add an SR Policy expecting an error; return combined stdout and stderr."""

    result = run_command(
        f"docker exec {pola} /bin/pola sr-policy add -f {policy_file} -p {GRPC_PORT}"
    )

    assert result.returncode != 0, (
        f"expected {policy_file} to be refused\nstdout: {result.stdout}"
    )

    combined = result.stdout + result.stderr
    for substring in expected_substrings:
        assert substring in combined, combined

    return combined


def get_ted_text(pola: str) -> str:
    """Get the current TED from `pola ted`."""

    result = run_command(f"docker exec {pola} /bin/pola -p {GRPC_PORT} ted")

    assert result.returncode == 0, f"failed to get TED text\nstderr: {result.stderr}"

    return result.stdout


def assert_xrd_srmpls_segments(
    headend: str, command: str, expected_sids: list[str]
) -> None:
    """Verify the SR-MPLS label stack reported by an XRd headend."""

    ssh_client = wait_for_ssh(headend)
    try:
        output = wait_until_ssh_output_contains(
            ssh_client, command, "Operational: up", timeout=180
        )
    finally:
        ssh_client.close()

    assert "Path Type: SRMPLSv4" in output, output

    sids = re.findall(r"SID\[\d+\]:\s*(\d+)", output)
    assert sids == expected_sids, (
        f"SR-ERO label stack mismatch.\nExpected: {expected_sids}\nActual:   {sids}\n{output}"
    )


def assert_xrd_policy_installed(
    headend: str, policy_name: str, expected_sids: list[str]
) -> None:
    """Verify the SR Policy installed on an XRd PCC."""

    ssh_client = wait_for_ssh(headend)
    try:
        output = wait_until_ssh_output_contains(
            ssh_client, "show segment-routing traffic-eng policy", "Operational: up"
        )
    finally:
        ssh_client.close()

    assert policy_name in output, output

    sids = re.findall(r"SID\[\d+\]:\s*(\d+)", output)
    assert sids == expected_sids, (
        f"SR-ERO label stack mismatch.\nExpected: {expected_sids}\nActual:   {sids}\n{output}"
    )


def assert_xrd_srv6_segments(
    headend: str, command: str, expected_sids: list[str]
) -> None:
    """Verify the SRv6 segment list reported by an XRd headend."""

    ssh_client = wait_for_ssh(headend)
    try:
        output = wait_until_ssh_output_contains(
            ssh_client, command, "Operational: up", timeout=180
        )
    finally:
        ssh_client.close()

    assert "Path Type: SRv6" in output, output

    sids = re.findall(r"SID\[\d+\]:\s*([0-9a-fA-F:]+)", output)
    assert sids == expected_sids, (
        f"SR-ERO segment list mismatch.\nExpected: {expected_sids}\nActual:   {sids}\n{output}"
    )


def junos_lsp_detail(headend: str, lsp_name: str) -> str:
    """Return the Junos LSP detail output once the LSP is up."""

    ssh_client = wait_for_ssh(headend)
    try:
        return wait_until_lsp_up(ssh_client, lsp_name)
    finally:
        ssh_client.close()


def junos_srmpls_labels(lsp_output: str) -> list[str]:
    """Extract the SR-MPLS label stack from Junos LSP detail output."""

    return re.findall(r"SID type:\s*\d+-bit label,\s*Value:\s*(\d+)", lsp_output)


def junos_srv6_sids(lsp_output: str) -> list[str]:
    """Extract the SRv6 SID stack from Junos LSP detail output.

    Match "srv6" case-insensitively because Junos uses different SID-type
    wording for dynamic and explicit paths.
    """

    return re.findall(
        r"SID type:\s*[^,]*srv6[^,]*,\s*Value:\s*([0-9a-fA-F:]+)",
        lsp_output,
        re.IGNORECASE,
    )


def junos_nais(lsp_output: str) -> list[str]:
    """Extract the NAI of each SR-ERO hop from Junos LSP detail output."""

    return [nai.strip() for nai in re.findall(r"NAI:\s*(.*)", lsp_output)]


def assert_frr_policy_active(container: str, policy_name: str) -> None:
    """Verify the SR Policy installed on an FRRouting PCC.

    FRR does not report the resolved label stack, so verify only Active + Name.
    """

    result = wait_until_command_output_contains(
        f"docker exec {container} vtysh -c 'show sr-te policy detail'", "Status: Active"
    )

    assert f"Name: {policy_name}" in result.stdout, result.stdout


def srv6_node_sids(ted: list, router_id: str) -> list[str]:
    """Return the SRv6 SIDs advertised by a node in a TED snapshot."""

    for node in ted:
        if node.get("routerId") == router_id:
            return [s["sids"][0] for s in node.get("srv6Sids", []) if s.get("sids")]

    raise AssertionError(f"router {router_id} not found in TED: {ted}")


def assert_sids_in_locators(
    actual_sids: list[str], expected_locators: list[str]
) -> None:
    """Verify each SID is within the corresponding locator."""

    assert len(actual_sids) == len(expected_locators), (
        f"SID count mismatch.\nActual SIDs:  {actual_sids}\nExpected locators: {expected_locators}"
    )

    for sid, locator in zip(actual_sids, expected_locators):
        assert ipaddress.ip_address(sid) in ipaddress.ip_network(locator), (
            f"SID {sid} is not in locator {locator}\n"
            f"Actual SIDs:  {actual_sids}\nExpected locators: {expected_locators}"
        )


def write_policy_file(container: str, path: str, text: str) -> None:
    """Write a runtime-generated SR Policy YAML file into a container."""

    result = subprocess.run(
        ["docker", "exec", "-i", container, "sh", "-c", f"cat > {path}"],
        input=text,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, (
        f"failed to write {path} in {container}\nstderr: {result.stderr}"
    )
