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
    wait_until_command_success,
    wait_until_lsp_up,
    wait_until_ted_has_links,
    wait_until_ted_has_routers,
)

LAB = "dynamic-path-srv6-usid"
LAB_DIR = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "srv6_usid",
)
POLA = f"clab-{LAB}-pola"
HEADEND = f"clab-{LAB}-pe02"
GRPC_PORT = 50052

pytestmark = pytest.mark.xdist_group(LAB)

ROUTER_IDS = [
    "0000.0001.0001",
    "0000.0001.0002",
    "0000.0001.0003",
    "0000.0001.0004",
]

LINKS = {
    frozenset(("0000.0001.0001", "0000.0001.0003")),
    frozenset(("0000.0001.0001", "0000.0001.0004")),
    frozenset(("0000.0001.0002", "0000.0001.0003")),
    frozenset(("0000.0001.0002", "0000.0001.0004")),
    frozenset(("0000.0001.0003", "0000.0001.0004")),
}


@pytest.fixture(scope="module")
def srv6_usid_lab(clab_deploy_module):
    """Deploy the SRv6 uSID lab once and wait until the PCE holds the full TED."""

    clab_deploy_module(LAB_DIR)

    print("Waiting for PCEP session")
    wait_until_command_success(
        f"docker exec {POLA} /bin/pola session -p {GRPC_PORT} "
        "| grep 'sessionAddr(0): fd00::2'"
    )

    wait_until_ted_has_routers(POLA, ROUTER_IDS)
    wait_until_ted_has_links(POLA, LINKS)


class TestDynamicPath:
    """Test SRv6 uSID dynamic path scenarios.

    This test suite verifies:
    - PCEP session establishment
    - TED population (nodes and links)
    - SR policy installation via Pola
    - Resulting SRv6 segment list on the router
    """

    def _assert_segments(self, policy_file, lsp_name, color, expected_segments):
        """Inject an SR policy and verify the SRv6 segment list it produces."""

        result = run_command(
            f"docker exec {POLA} "
            f"/bin/pola sr-policy add -f {policy_file} -p {GRPC_PORT}"
        )
        assert "success" in result.stdout.lower(), (
            f"failed to add {policy_file}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

        ssh_client = wait_for_ssh(HEADEND)
        try:
            lsp_output = wait_until_lsp_up(ssh_client, lsp_name)
        finally:
            ssh_client.close()

        assert f"fd00:ffff::1-{color}" in lsp_output
        assert "SID type: Micro SRv6 SID" in lsp_output

        actual_segments = re.findall(
            r"SID type:\s*Micro SRv6 SID,\s*Value:\s*([0-9a-fA-F:]+)",
            lsp_output,
        )

        assert actual_segments == expected_segments, (
            f"SR-ERO segment list mismatch.\n"
            f"Expected: {expected_segments}\n"
            f"Actual:   {actual_segments}"
        )

    def test__srv6_usid_dynamic_path(self, srv6_usid_lab):
        """Verify SRv6 uSID dynamic path produces the expected segment list."""

        self._assert_segments(
            "/pe02-policy1.yaml",
            "DYNAMIC-POLICY",
            100,
            [
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1001::",
            ],
        )

    def test__srv6_usid_loose_source_routing(self, srv6_usid_lab):
        """Verify SRv6 uSID loose source routing produces the expected segment list with repeated segments."""

        self._assert_segments(
            "/pe02-policy-loose-source-routing.yaml",
            "LOOSE-SOURCE-ROUTING-POLICY",
            200,
            [
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1001::",
            ],
        )
