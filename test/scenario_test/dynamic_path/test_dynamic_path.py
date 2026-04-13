# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import pytest
import os
import time
import subprocess
import json
import paramiko
import re


class TestDynamicPath:
    """Test SRv6 uSID dynamic path scenarios.

    This test suite verifies:
    - PCEP session establishment
    - TED population (nodes and links)
    - SR policy installation via Pola
    - Resulting SRv6 segment list on the router
    """

    TEST_ABS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    BIN_ABS_DIR = os.path.join(TEST_ABS_DIR, "bin")
    TEST_DYNAMIC_PATH_DIR = os.path.join(
        TEST_ABS_DIR, "scenario_test", "dynamic_path", "srv6-usid"
    )

    def _run(self, cmd: str) -> subprocess.CompletedProcess:
        """Run a shell command and return CompletedProcess."""
        return subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
        )

    def _wait_until_pcep_success(self, cmd, interval=10, timeout=600):
        start = time.time()
        while True:
            result = self._run(cmd)
            if result.returncode == 0:
                return
            if time.time() - start > timeout:
                pytest.fail(f"Timeout waiting for command to succeed: {cmd}")
            time.sleep(interval)

    def _wait_until_ted_has_routers(self, router_ids, interval=10, timeout=600):
        """Wait until pola TED contains all given router_ids."""

        cmd = "docker exec clab-srv6-usid-pola /bin/pola ted -j -p 50052"
        start = time.time()
        router_ids = set(router_ids)

        while True:
            result = self._run(cmd)
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    present = {node.get("routerID") for node in data.get("ted", [])}
                    missing = router_ids - present
                    if not missing:
                        print(f"TED contains routers: {router_ids}")
                        return
                except json.JSONDecodeError:
                    pass

            if time.time() - start > timeout:
                pytest.fail(f"Timeout waiting for routers {router_ids} in TED")

            print(f"Waiting for routers {router_ids} in TED...")
            time.sleep(interval)

    def _wait_until_ted_has_all_links(self, expected_links, interval=10, timeout=600):
        """Wait until pola TED contains all expected links."""

        cmd = "docker exec clab-srv6-usid-pola /bin/pola ted -j -p 50052"
        start = time.time()

        while True:
            result = self._run(cmd)
            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    found_links = set()

                    for node in data.get("ted", []):
                        local = node.get("routerID")
                        for link in node.get("links", []):
                            remote = link.get("remoteNode")
                            if local and remote:
                                found_links.add(frozenset((local, remote)))

                    missing = expected_links - found_links
                    if not missing:
                        print("TED contains all expected links")
                        return
                except json.JSONDecodeError:
                    pass

            if time.time() - start > timeout:
                pytest.fail(f"Timeout waiting for links in TED. Missing: {missing}")

            print(f"Waiting for links in TED. Missing: {missing}")
            time.sleep(interval)

    def _deploy_and_assert_segments(self, clab_deploy, policy_file, expected_segments):
        """Deploy topology, wait for readiness, inject SR policy, and verify SRv6 segments."""

        TEST_DIR = self.TEST_DYNAMIC_PATH_DIR

        # Deploy
        clab_deploy(TEST_DIR)

        # Wait for readiness (replace fixed sleep)
        print("Waiting for PCEP session to become available")
        self._wait_until_pcep_success(
            "docker exec clab-srv6-usid-pola "
            "/bin/pola session -p 50052 | grep 'sessionAddr(0): fd00::2'"
        )

        # Wait for TED routers
        self._wait_until_ted_has_routers(
            [
                "0000.0001.0001",
                "0000.0001.0002",
                "0000.0001.0003",
                "0000.0001.0004",
            ]
        )

        # Wait for links
        expected_links = {
            frozenset(("0000.0001.0001", "0000.0001.0003")),
            frozenset(("0000.0001.0001", "0000.0001.0004")),
            frozenset(("0000.0001.0002", "0000.0001.0003")),
            frozenset(("0000.0001.0002", "0000.0001.0004")),
            frozenset(("0000.0001.0003", "0000.0001.0004")),
        }
        self._wait_until_ted_has_all_links(expected_links)

        # Inject SR Policy
        result = self._run(
            f"docker exec clab-srv6-usid-pola /bin/pola "
            f"sr-policy add -f {policy_file} -p 50052"
        )
        assert "success" in result.stdout.lower()

        time.sleep(10)  # TODO: replace with readiness check

        # SSH to PE02
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname="clab-srv6-usid-pe02",
            username="admin",
            password="admin@123",
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
            look_for_keys=False,
        )

        _, stdout, _ = ssh_client.exec_command(
            "show spring-traffic-engineering lsp name DYNAMIC-POLICY detail"
        )
        lsp_output = stdout.read().decode()
        ssh_client.close()

        # Basic checks
        assert "DYNAMIC-POLICY" in lsp_output
        assert "fd00:ffff::1-100" in lsp_output
        assert "State: Up" in lsp_output
        assert "SID type: Micro SRv6 SID" in lsp_output

        # Extract and verify segments
        actual_segments = re.findall(
            r"SID type:\s*Micro SRv6 SID,\s*Value:\s*([0-9a-fA-F:]+)",
            lsp_output,
        )

        assert actual_segments == expected_segments, (
            f"SR-ERO segment list mismatch.\n"
            f"Expected: {expected_segments}\n"
            f"Actual:   {actual_segments}"
        )

    def test__bin_ready(self):
        """Ensure required binaries exist and are executable."""

        for binname in ["gobgpd", "polad", "pola"]:
            path = f"{self.BIN_ABS_DIR}/{binname}"
            assert os.path.exists(path)
            assert os.access(path, os.X_OK)

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
