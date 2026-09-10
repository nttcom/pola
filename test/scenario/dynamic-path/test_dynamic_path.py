# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import os
import re

import pytest
from helpers.wait import (
    get_ted,
    run_command,
    wait_for_ssh,
    wait_until_command_success,
    wait_until_lsp_up,
    wait_until_ssh_output_contains,
    wait_until_ted_has_links,
    wait_until_ted_has_routers,
)

LAB = "dynamic-path-srv6-usid"
LAB_DIR = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "srv6-usid",
)
POLA = f"clab-{LAB}-pola"
HEADEND = f"clab-{LAB}-pe02"
GRPC_PORT = 50052

# Keep xdist_group on each class: pytest-xdist combines marks from the module
# and class instead of letting the class-level mark override the module mark.

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

DUAL_STACK_LAB = "dynamic-path-dual-stack"
DUAL_STACK_LAB_DIR = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "dual-stack",
)
DUAL_STACK_POLA = f"clab-{DUAL_STACK_LAB}-pola"
DUAL_STACK_PE01 = f"clab-{DUAL_STACK_LAB}-pe01"  # xrd headend
DUAL_STACK_PE02 = f"clab-{DUAL_STACK_LAB}-pe02"  # Junos headend

DUAL_STACK_ROUTER_IDS = [
    "0000.0002.0001",  # pe01 (IPv4-only loopback identity)
    "0000.0002.0002",  # p01 (dual-stack transit, IPv4-cheap / IPv6-expensive)
    "0000.0002.0003",  # p02 (dual-stack transit, IPv4-expensive / IPv6-cheap)
    "0000.0002.0004",  # pe02 (IPv4-only loopback identity, PCEP headend)
]

DUAL_STACK_LINKS = {
    frozenset(("0000.0002.0001", "0000.0002.0002")),
    frozenset(("0000.0002.0001", "0000.0002.0003")),
    frozenset(("0000.0002.0002", "0000.0002.0004")),
    frozenset(("0000.0002.0003", "0000.0002.0004")),
}


@pytest.fixture(scope="module")
def srv6_usid_lab(clab_deploy_module):
    """Deploy the SRv6 uSID lab once and wait until the PCE holds the full TED."""

    clab_deploy_module(LAB_DIR)

    print("Waiting for PCEP session")
    wait_until_command_success(
        f"docker exec {POLA} /bin/pola session -p {GRPC_PORT} "
        "| grep 'Session #0: fd00::2'"
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

    pytestmark = pytest.mark.xdist_group(LAB)

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


@pytest.fixture(scope="module")
def dual_stack_lab(clab_deploy_module):
    """Deploy the dual-stack lab once and wait until the PCE holds the full TED."""

    clab_deploy_module(DUAL_STACK_LAB_DIR)

    print("Waiting for PCEP sessions")
    wait_until_command_success(
        f"docker exec {DUAL_STACK_POLA} /bin/pola session -p {GRPC_PORT} "
        "| grep '10.0.30.1'"
    )
    wait_until_command_success(
        f"docker exec {DUAL_STACK_POLA} /bin/pola session -p {GRPC_PORT} "
        "| grep '10.0.30.2'"
    )

    wait_until_ted_has_routers(DUAL_STACK_POLA, DUAL_STACK_ROUTER_IDS)
    wait_until_ted_has_links(DUAL_STACK_POLA, DUAL_STACK_LINKS)


class TestDynamicPathDualStack:
    """Test dual-stack TED contents and underlay path selection."""

    pytestmark = pytest.mark.xdist_group(DUAL_STACK_LAB)

    def _add_policy(self, policy_file):
        result = run_command(
            f"docker exec {DUAL_STACK_POLA} "
            f"/bin/pola sr-policy add -f {policy_file} -p {GRPC_PORT}"
        )
        assert "success" in result.stdout.lower(), (
            f"failed to add {policy_file}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def _assert_xrd_segments(self, headend, command, expected_sids):
        """Verify the SR-MPLS label stack reported by an xrd (IOS-XR) headend."""

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
            f"SR-ERO label stack mismatch.\n"
            f"Expected: {expected_sids}\n"
            f"Actual:   {sids}\n{output}"
        )

    def _assert_junos_segments(self, lsp_name, expected_labels):
        """Verify the SR-MPLS label stack reported by the Junos headend."""

        ssh_client = wait_for_ssh(DUAL_STACK_PE02)
        try:
            lsp_output = wait_until_lsp_up(ssh_client, lsp_name)
        finally:
            ssh_client.close()

        labels = re.findall(
            r"SID type:\s*\d+-bit label,\s*Value:\s*(\d+)",
            lsp_output,
        )
        assert labels == expected_labels, (
            f"SR-ERO label stack mismatch.\n"
            f"Expected: {expected_labels}\n"
            f"Actual:   {labels}\n{lsp_output}"
        )

    def test__dual_stack_links_expose_both_address_families(self, dual_stack_lab):
        """Verify that dual-stack links expose both IPv4 and IPv6 addresses in the TED."""

        ted = get_ted(DUAL_STACK_POLA)

        families_seen = set()
        for node in ted:
            for link in node.get("links", []):
                local = link.get("local", {})
                if "ipv4" in local:
                    families_seen.add("ipv4")
                if "ipv6" in local:
                    families_seen.add("ipv6")

        assert families_seen == {"ipv4", "ipv6"}, (
            "expected both address families on dual-stack links, "
            f"got {families_seen}\nfull TED: {ted}"
        )

    def test__pe02_ipv6_loopback_is_advertised_as_a_128_prefix(self, dual_stack_lab):
        """Verify pe02 advertises its IPv6 loopback as a /128 prefix."""

        ted = get_ted(DUAL_STACK_POLA)
        nodes_by_router_id = {node.get("routerId"): node for node in ted}

        prefixes = {
            p.get("prefix")
            for p in nodes_by_router_id["0000.0002.0004"].get("prefixes", [])
        }
        assert "2001:db8:200:4::1/128" in prefixes, (
            f"pe02 did not advertise its IPv6 loopback as a /128 prefix\nfull TED: {ted}"
        )

    def test__pe02_ipv4_underlay_computes_the_ipv4_cheap_path(self, dual_stack_lab):
        """Verify pe02, as headend, selects the IPv4-cheap path via p01."""

        self._add_policy("/pe02-ipv4.yaml")

        self._assert_junos_segments(
            "DUAL-STACK-IPV4-POLICY",
            ["16022", "16021"],
        )

    @pytest.mark.xfail(
        reason=(
            "Junos 25.2R1.9 pccd rejects PCE-initiated SR-MPLS policies with "
            "an IPv6-typed SRPAG association object: "
            "'IPv6 SRPAG received for non SRv6 LSP'."
        ),
        strict=False,
    )
    def test__pe02_ipv6_underlay_computes_the_ipv6_cheap_path(self, dual_stack_lab):
        """Verify pe02, as headend, selects the IPv6-cheap path via p02."""

        self._add_policy("/pe02-ipv6.yaml")

        self._assert_junos_segments(
            "DUAL-STACK-IPV6-POLICY",
            ["16123", "16121"],
        )

    def test__pe01_ipv4_underlay_computes_the_ipv4_cheap_path(self, dual_stack_lab):
        """Verify pe01, as headend, selects the IPv4-cheap path via p01."""

        self._add_policy("/pe01-ipv4.yaml")

        self._assert_xrd_segments(
            DUAL_STACK_PE01,
            "show segment-routing traffic-eng policy color 401 endpoint ipv4 10.255.2.4",
            ["16022", "16024"],
        )

    @pytest.mark.xfail(
        reason=(
            "IOS-XR 24.4.1 rejects PCE-initiated SR-MPLS policies with IPv6 "
            "endpoints, reporting 'pcinitiate: bad sock info'."
        ),
        strict=False,
    )
    def test__pe01_ipv6_underlay_computes_the_ipv6_cheap_path(self, dual_stack_lab):
        """Verify pe01, as headend, selects the IPv6-cheap path via p02."""

        self._add_policy("/pe01-ipv6.yaml")

        self._assert_xrd_segments(
            DUAL_STACK_PE01,
            "show segment-routing traffic-eng policy color 601 endpoint ipv6 2001:db8:200:4::1",
            ["16123", "16124"],
        )
