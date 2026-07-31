# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import json
import os

import pytest

from helpers.wait import (
    wait_for_ssh,
    wait_until_command_success,
    wait_until_ted_matches,
)


class TestShowTed:
    """Test TED (Traffic Engineering Database) synchronization scenarios.

    This test suite verifies:
    - TED population matches expected topology (nodes and links)
    - TED updates correctly when a link goes down
    """

    TEST_SHOW_TED_DIR = os.path.abspath(os.path.dirname(__file__))

    def _verify_ted_sync(
        self,
        clab_deploy,
        topology_dir,
        pola_container,
        router_hostname,
        ping_command,
        expected_initial,
        expected_after_update,
    ):
        """Verify TED synchronization and link-state update."""

        clab_deploy(topology_dir)

        wait_until_command_success(ping_command)

        with open(expected_initial) as f:
            expected_output = json.load(f)

        wait_until_ted_matches(
            pola_container,
            expected_output,
        )

        print(f"Disable interface ge-0/0/0 on {router_hostname}")

        ssh_client = wait_for_ssh(router_hostname)

        try:
            _, stdout, stderr = ssh_client.exec_command(
                "configure; set interfaces ge-0/0/0 disable; commit"
            )

            print(stdout.read().decode())
            print(stderr.read().decode())

        finally:
            ssh_client.close()

        with open(expected_after_update) as f:
            expected_output2 = json.load(f)

        wait_until_ted_matches(
            pola_container,
            expected_output2,
        )

    @pytest.mark.xdist_group("show-ted-srmpls")
    def test__srmpls(self, clab_deploy):
        """Verify TED sync for SR-MPLS topology, including update after link-down."""

        test_dir = os.path.join(
            self.TEST_SHOW_TED_DIR,
            "srmpls",
        )

        self._verify_ted_sync(
            clab_deploy,
            test_dir,
            "clab-show-ted-srmpls-pola",
            "clab-show-ted-srmpls-jun-rt1",
            "docker exec clab-show-ted-srmpls-gobgp ping 10.255.0.2 -c 1",
            os.path.join(test_dir, "expected", "srmpls.json"),
            os.path.join(test_dir, "expected", "srmpls2.json"),
        )

    @pytest.mark.xdist_group("show-ted-srv6-usid")
    def test__srv6_usid(self, clab_deploy):
        """Verify TED sync for SRv6 uSID topology, including update after link-down."""

        test_dir = os.path.join(
            self.TEST_SHOW_TED_DIR,
            "srv6_usid",
        )

        self._verify_ted_sync(
            clab_deploy,
            test_dir,
            "clab-show-ted-srv6-usid-pola",
            "clab-show-ted-srv6-usid-jun-rt1",
            "docker exec clab-show-ted-srv6-usid-gobgp ping fd00:ffff::2 -c 1",
            os.path.join(test_dir, "expected", "srv6_usid.json"),
            os.path.join(test_dir, "expected", "srv6_usid2.json"),
        )
