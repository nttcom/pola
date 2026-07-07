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
        TEST_ABS_DIR, "scenario_test", "dynamic_path", "srv6_usid"
    )

    def _run(self, cmd: str) -> subprocess.CompletedProcess:
        """Run a shell command and return CompletedProcess."""
        return subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
        )

    def _connect_pe02(self, timeout=120, interval=5):
        """Wait until SSH is available and connect."""

        start = time.time()
        last_error = None
        hostname = "clab-srv6_usid-pe02"

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        while True:
            try:
                ssh.connect(
                    hostname=hostname,
                    username="admin",
                    password="admin@123",
                    timeout=10,
                    banner_timeout=10,
                    auth_timeout=10,
                    look_for_keys=False,
                )
                return ssh

            except (paramiko.SSHException, OSError) as e:
                last_error = e
                ssh.close()

                if time.time() - start > timeout:
                    pytest.fail(
                        f"Timeout waiting for SSH to {hostname}. "
                        f"Last error: {repr(last_error)}"
                    )

                print(f"Waiting for SSH... last error: {repr(last_error)}")
                time.sleep(interval)

    def _wait_until_pcep_success(self, cmd, interval=10, timeout=600):
        """Wait until the given command succeeds (return code 0)."""

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

        cmd = "docker exec clab-srv6_usid-pola /bin/pola ted -j -p 50052"
        start = time.time()
        router_ids = set(router_ids)

        while True:
            result = self._run(cmd)

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    present = {n.get("routerID") for n in data.get("ted", [])}

                    missing = router_ids - present
                    if not missing:
                        print(f"TED ready: {router_ids}")
                        return

                    print(f"Waiting TED routers. missing={missing}")

                except json.JSONDecodeError:
                    pass

            if time.time() - start > timeout:
                pytest.fail(f"Timeout waiting for routers {router_ids} in TED")

            time.sleep(interval)

    def _wait_until_ted_has_all_links(self, expected_links, interval=10, timeout=600):
        """Wait until pola TED contains all expected links."""

        cmd = "docker exec clab-srv6_usid-pola /bin/pola ted -j -p 50052"
        start = time.time()
        found = set()

        while True:
            result = self._run(cmd)

            if result.returncode == 0:
                try:
                    data = json.loads(result.stdout)
                    found = set()

                    for node in data.get("ted", []):
                        local = node.get("routerID")
                        for link in node.get("links", []):
                            remote = link.get("remoteNode")
                            if local and remote:
                                found.add(frozenset((local, remote)))

                    missing = expected_links - found
                    if not missing:
                        print("TED links ready")
                        return

                    print(f"Waiting TED links. missing={missing}")

                except json.JSONDecodeError:
                    pass

            if time.time() - start > timeout:
                pytest.fail(
                    f"Timeout waiting for TED links. missing={expected_links - found}"
                )

            time.sleep(interval)

    def _wait_until_lsp_up(self, ssh_client, timeout=300, interval=5):
        """Wait until SRv6 LSP becomes Up."""

        start = time.time()

        while True:
            _, stdout, _ = ssh_client.exec_command(
                "show spring-traffic-engineering lsp name DYNAMIC-POLICY detail"
            )
            output = stdout.read().decode()

            if "DYNAMIC-POLICY" in output and "State: Up" in output:
                return output

            if time.time() - start > timeout:
                pytest.fail("Timeout waiting for LSP to become Up")

            print("Waiting for LSP DYNAMIC-POLICY to become Up...")
            time.sleep(interval)

    def _deploy_and_assert_segments(self, clab_deploy, policy_file, expected_segments):
        """Deploy topology, wait for readiness, inject SR policy, and verify SRv6 segments."""

        clab_deploy(self.TEST_DYNAMIC_PATH_DIR)

        print("Waiting for PCEP session")
        self._wait_until_pcep_success(
            "docker exec clab-srv6_usid-pola /bin/pola session -p 50052 "
            "| grep 'sessionAddr(0): fd00::2'"
        )

        self._wait_until_ted_has_routers(
            [
                "0000.0001.0001",
                "0000.0001.0002",
                "0000.0001.0003",
                "0000.0001.0004",
            ]
        )

        expected_links = {
            frozenset(("0000.0001.0001", "0000.0001.0003")),
            frozenset(("0000.0001.0001", "0000.0001.0004")),
            frozenset(("0000.0001.0002", "0000.0001.0003")),
            frozenset(("0000.0001.0002", "0000.0001.0004")),
            frozenset(("0000.0001.0003", "0000.0001.0004")),
        }

        self._wait_until_ted_has_all_links(expected_links)

        result = self._run(
            f"docker exec clab-srv6_usid-pola /bin/pola "
            f"sr-policy add -f {policy_file} -p 50052"
        )
        assert "success" in result.stdout.lower()

        ssh_client = None
        try:
            ssh_client = self._connect_pe02()
            self._wait_until_lsp_up(ssh_client)

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
