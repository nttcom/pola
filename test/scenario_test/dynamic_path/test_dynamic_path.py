import pytest
import os
import time
import subprocess
import json
import paramiko
import re


class TestDynamicPath:
    TEST_ABS_DIR = os.getcwd()[: os.getcwd().rfind("/test")] + "/test"
    BIN_ABS_DIR = TEST_ABS_DIR + "/bin"

    TEST_DYNAMIC_PATH_DIR = TEST_ABS_DIR + "/scenario_test/dynamic_path/srv6-usid"
    EXPECTED_LSP_FILE = TEST_DYNAMIC_PATH_DIR + "/expected/sr-policy_output.txt"

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
        """
        Wait until pola TED contains all given router_ids.
        """
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
        """
        Wait until pola TED contains all expected links.
        """
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

    def test__bin_ready(self):
        """Ensure required binaries exist and are executable."""
        for binname in ["gobgpd", "polad", "pola"]:
            path = f"{self.BIN_ABS_DIR}/{binname}"
            assert os.path.exists(path)
            assert os.access(path, os.X_OK)

    def test__srv6_usid_dynamic_path(self, clab_deploy):
        TEST_DIR = self.TEST_DYNAMIC_PATH_DIR

        # Deploy containerlab topology
        clab_deploy(TEST_DIR)

        # Wait for routers to boot
        print("Waiting for vJunos boot (120s)")
        time.sleep(120)

        # Wait until PCEP session is up (POLA <-> PE02)
        self._wait_until_pcep_success(
            "docker exec clab-srv6-usid-pola "
            "/bin/pola session -p 50052 | grep 'sessionAddr(0): fd00::2'"
        )

        # Wait until TED is populated
        self._wait_until_ted_has_routers(
            [
                "0000.0001.0001",
                "0000.0001.0002",
                "0000.0001.0003",
                "0000.0001.0004",
            ]
        )

        # Wait until all expected links are present
        expected_links = {
            frozenset(("0000.0001.0001", "0000.0001.0003")),
            frozenset(("0000.0001.0001", "0000.0001.0004")),
            frozenset(("0000.0001.0002", "0000.0001.0003")),
            frozenset(("0000.0001.0002", "0000.0001.0004")),
            frozenset(("0000.0001.0003", "0000.0001.0004")),
        }
        self._wait_until_ted_has_all_links(expected_links)

        # Inject SR Policy via Pola CLI (PCEP)
        result = self._run(
            "docker exec clab-srv6-usid-pola /bin/pola "
            "sr-policy add -f /pe02-policy1.yaml -p 50052"
        )
        assert "success" in result.stdout.lower()
        time.sleep(10)  # wait for SR Policy propagation

        # SSH to PE02 and capture LSP detail output
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            hostname="clab-srv6-usid-pe02",
            username="admin",
            password="admin@123",
        )

        stdin, stdout, stderr = ssh_client.exec_command(
            "show spring-traffic-engineering lsp name DYNAMIC-POLICY detail"
        )
        lsp_output = stdout.read().decode()
        ssh_client.close()

        assert "DYNAMIC-POLICY" in lsp_output
        assert "fd00:ffff::1-100" in lsp_output
        assert "State: Up" in lsp_output
        assert "SID type: Micro SRv6 SID" in lsp_output

        # Verify SR-ERO content and order by comparing the exact SRv6 segment list
        expected_segments = [
            "fcbb:bb00:1004::",
            "fcbb:bb00:1003::",
            "fcbb:bb00:1001::",
        ]
        actual_segments = re.findall(
            r"SID type:\s*Micro SRv6 SID,\s*Value:\s*([0-9a-fA-F:]+)",
            lsp_output,
        )
        assert actual_segments == expected_segments, (
            f"SR-ERO segment list mismatch.\n"
            f"Expected: {expected_segments}\n"
            f"Actual:   {actual_segments}"
        )
