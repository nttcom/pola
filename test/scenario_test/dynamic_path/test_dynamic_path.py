# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import os
import re

from helpers.wait import (
    run_command,
    wait_for_ssh,
    wait_until_command_success,
    wait_until_lsp_up,
    wait_until_ted_has_links,
    wait_until_ted_has_routers,
)


class TestDynamicPath:
    """Test SRv6 uSID dynamic path scenarios.

    This test suite verifies:
    - PCEP session establishment
    - TED population (nodes and links)
    - SR policy installation via Pola
    - Resulting SRv6 segment list on the router
    """

    TEST_ABS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    TEST_DYNAMIC_PATH_DIR = os.path.join(
        TEST_ABS_DIR, "scenario_test", "dynamic_path", "srv6_usid"
    )

    def _deploy_and_assert_segments(self, clab_deploy, policy_file, expected_segments):
        """Deploy topology, wait for readiness, inject SR policy, and verify SRv6 segments."""

        clab_deploy(self.TEST_DYNAMIC_PATH_DIR)

        print("Waiting for PCEP session")
        wait_until_command_success(
            "docker exec clab-srv6-usid-pola /bin/pola session -p 50052 "
            "| grep 'sessionAddr(0): fd00::2'"
        )

        wait_until_ted_has_routers(
            "clab-srv6-usid-pola",
            [
                "0000.0001.0001",
                "0000.0001.0002",
                "0000.0001.0003",
                "0000.0001.0004",
            ],
        )

        expected_links = {
            frozenset(("0000.0001.0001", "0000.0001.0003")),
            frozenset(("0000.0001.0001", "0000.0001.0004")),
            frozenset(("0000.0001.0002", "0000.0001.0003")),
            frozenset(("0000.0001.0002", "0000.0001.0004")),
            frozenset(("0000.0001.0003", "0000.0001.0004")),
        }

        wait_until_ted_has_links(
            "clab-srv6-usid-pola",
            expected_links,
        )

        result = run_command(
            f"docker exec clab-srv6-usid-pola "
            f"/bin/pola sr-policy add -f {policy_file} -p 50052"
        )
        assert "success" in result.stdout.lower()

        ssh_client = None
        try:
            ssh_client = wait_for_ssh("clab-srv6-usid-pe02")
            wait_until_lsp_up(ssh_client, "DYNAMIC-POLICY")

            _, stdout, _ = ssh_client.exec_command(
                "show spring-traffic-engineering lsp name DYNAMIC-POLICY detail"
            )
            lsp_output = stdout.read().decode()

            assert "DYNAMIC-POLICY" in lsp_output
            assert "fd00:ffff::1-100" in lsp_output
            assert "State: Up" in lsp_output
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

        finally:
            if ssh_client is not None:
                ssh_client.close()

    def test__srv6_usid_dynamic_path(self, clab_deploy):
        """Verify SRv6 uSID dynamic path produces the expected segment list."""

        self._deploy_and_assert_segments(
            clab_deploy,
            "/pe02-policy1.yaml",
            [
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1001::",
            ],
        )

    def test__srv6_usid_loose_source_routing(self, clab_deploy):
        """Verify SRv6 uSID loose source routing produces the expected segment list with repeated segments."""

        self._deploy_and_assert_segments(
            clab_deploy,
            "/pe02-policy-loose-source-routing.yaml",
            [
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1001::",
            ],
        )
