# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import os
import re

import pytest
from helpers.wait import (
    run_command,
    wait_for_ssh,
    wait_until_command_output_contains,
    wait_until_command_success,
    wait_until_lsp_up,
    wait_until_ssh_output_contains,
)

LAB = "explicit-path-sr-mpls"
POLA = f"clab-{LAB}-pola"
GRPC_PORT = 50052

pytestmark = pytest.mark.xdist_group(LAB)


def add_sr_policy(policy_file: str) -> None:
    """Install an SR Policy without TED (explicit path)."""

    result = run_command(
        f"docker exec {POLA} /bin/pola sr-policy add "
        f"-f {policy_file} -p {GRPC_PORT} --no-sid-validate"
    )

    assert "success" in result.stdout.lower(), (
        f"failed to add {policy_file}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "skipping SID validation" in result.stderr, (
        f"--no-sid-validate must always warn on stderr\nstderr: {result.stderr}"
    )


def add_sr_policy_expecting_ted_error(policy_file: str) -> None:
    """Installing without --no-sid-validate must be refused when there is no TED."""

    result = run_command(
        f"docker exec {POLA} /bin/pola sr-policy add -f {policy_file} -p {GRPC_PORT}"
    )

    assert result.returncode != 0, (
        f"expected {policy_file} to be refused\nstdout: {result.stdout}"
    )
    combined = result.stdout + result.stderr
    assert "TED is not enabled" in combined, combined
    assert "--no-sid-validate" in combined, combined


class TestExplicitPathSRMPLS:
    """Test SR-MPLS explicit path scenarios.

    This test suite verifies:
    - PCEP session establishment with three PCC implementations
    - Explicit-path SR Policy installation via Pola, without TED
    - The Node/Adjacency Identifier (NAI) built from the `localAddr` of each SID
      (RFC8664 4.3.1) is accepted by the PCC and shown in the installed SR-ERO
    - Segment lists without `localAddr` still install with the NAI absent
    - Installing without --no-sid-validate is refused when there is no TED
    """

    TEST_EXPLICIT_PATH_DIR = os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        "sr-mpls",
    )

    def test__sr_mpls_explicit_path_with_nai(self, clab_deploy):
        """Verify explicit-path policies with a per-SID localAddr install on every PCC."""

        clab_deploy(self.TEST_EXPLICIT_PATH_DIR)

        # pe01 is XRd, pe02 is vJunos-router and pe03 is FRRouting.
        print("Waiting for PCEP sessions")
        for pcc_addr in ["10.0.255.1", "10.0.255.2", "10.0.255.3"]:
            wait_until_command_success(
                f"docker exec {POLA} /bin/pola session -p {GRPC_PORT} "
                f"| grep '{pcc_addr}'"
            )

        add_sr_policy_expecting_ted_error("/pe01-policy1.yaml")

        add_sr_policy("/pe01-policy1.yaml")
        add_sr_policy("/pe02-policy1.yaml")
        add_sr_policy("/pe02-policy2.yaml")
        add_sr_policy("/pe03-policy1.yaml")

        self._assert_vjunos_ero(f"clab-{LAB}-pe02")
        self._assert_xrd_policy(f"clab-{LAB}-pe01")
        self._assert_frr_policy()

    def _assert_vjunos_ero(self, hostname):
        """Verify the SR-ERO installed on the vJunos-router PCC, including its NAI."""

        ssh_client = wait_for_ssh(hostname)
        try:
            with_nai = wait_until_lsp_up(ssh_client, "pe02-policy1")
            without_nai = wait_until_lsp_up(ssh_client, "pe02-policy2")
        finally:
            ssh_client.close()

        # The expected values are the localAddr of each SID in pe02-policy1.yaml.
        assert "SR-ERO hop count: 2" in with_nai, with_nai

        labels = re.findall(r"SID type:\s*20-bit label,\s*Value:\s*(\d+)", with_nai)
        assert labels == ["16001", "16003"], (
            f"SR-ERO label stack mismatch.\nExpected: ['16001', '16003']\n"
            f"Actual:   {labels}\n{with_nai}"
        )

        nais = [nai.strip() for nai in re.findall(r"NAI:\s*(.*)", with_nai)]
        assert nais == [
            "IPv4 Node ID, Node address: 10.255.0.1",
            "IPv4 Node ID, Node address: 10.255.0.3",
        ], f"SR-ERO NAI mismatch.\nActual: {nais}\n{with_nai}"

        # pe02-policy2 has the same segment list without localAddr, so the NAI
        # must stay absent.
        nais = [nai.strip() for nai in re.findall(r"NAI:\s*(.*)", without_nai)]
        assert nais == ["None", "None"], (
            f"expected no NAI without localAddr, got {nais}\n{without_nai}"
        )

    def _assert_xrd_policy(self, hostname):
        """Verify the SR Policy installed on the XRd PCC."""

        ssh_client = wait_for_ssh(hostname)
        try:
            output = wait_until_ssh_output_contains(
                ssh_client,
                "show segment-routing traffic-eng policy",
                "Operational: up",
            )
        finally:
            ssh_client.close()

        assert "pe01-policy1" in output, output

        sids = re.findall(r"SID\[\d+\]:\s*(\d+)", output)
        assert sids == ["16002", "16003"], (
            f"SR-ERO label stack mismatch.\nExpected: ['16002', '16003']\n"
            f"Actual:   {sids}\n{output}"
        )

    def _assert_frr_policy(self):
        """Verify the SR Policy installed on the FRRouting PCC."""

        result = wait_until_command_output_contains(
            f"docker exec clab-{LAB}-pe03 vtysh -c 'show sr-te policy detail'",
            "Status: Active",
        )

        assert "Name: pe03-policy1" in result.stdout, result.stdout
