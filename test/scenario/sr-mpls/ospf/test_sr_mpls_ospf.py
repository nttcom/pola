# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import pytest
from helpers.scenario import (
    add_sr_policy,
    assert_frr_policy_active,
    assert_xrd_policy_installed,
    assert_xrd_srmpls_segments,
    deploy_lab,
    get_ted_text,
    lab_dir_of,
)
from helpers.wait import run_command

LAB = "sr-mpls-ospf"
LAB_DIR = lab_dir_of(__file__)
POLA = f"clab-{LAB}-pola"
PE01 = f"clab-{LAB}-pe01"  # XRd, BGP-LS exporter
PE02 = f"clab-{LAB}-pe02"  # FRRouting, OSPFv2 only
GRPC_PORT = 50052

pytestmark = pytest.mark.xdist_group(LAB)

ROUTER_IDS = ["10.255.4.1", "10.255.4.2", "10.255.4.3", "10.255.4.5"]
LINKS = {
    frozenset(("10.255.4.1", "10.255.4.2")),
    frozenset(("10.255.4.1", "10.255.4.3")),
    frozenset(("10.255.4.5", "10.255.4.2")),
    frozenset(("10.255.4.5", "10.255.4.3")),
}
PCEP_ADDRS = ["10.0.50.1", "10.0.50.5"]


@pytest.fixture(scope="module")
def lab(clab_deploy_module):
    deploy_lab(clab_deploy_module, LAB_DIR, POLA, PCEP_ADDRS, ROUTER_IDS, LINKS)


class TestSRMPLSOSPF:
    """Test OSPFv2/OSPFv3 SR-MPLS scenarios.

    OSPFv3 BGP-LS export is unavailable on IOS-XR 24.4.1, so only OSPFv2
    (IPv4) paths can be tested; see README for details.
    """

    def test__show_ted_contains_ospfv2_nodes_and_prefix_sids(self, lab):
        """Verify every OSPFv2 node and its Prefix-SID index appear in the TED."""

        ted_text = get_ted_text(POLA)

        for router_id in ROUTER_IDS:
            assert router_id in ted_text, ted_text

        for index in ["41", "42", "43", "45"]:
            assert f"index: {index}" in ted_text, ted_text

    def test__explicit_path_from_xrd_headend(self, lab):
        """Verify an explicit-path policy installs on the XRd headend."""

        add_sr_policy(POLA, "/pe01-explicit.yaml")

        assert_xrd_policy_installed(PE01, "pe01-explicit", ["16042", "16045"])

    def test__dynamic_path_ipv4_from_xrd_headend(self, lab):
        """Verify the expected OSPFv2/IPv4 path to pe02."""

        add_sr_policy(POLA, "/pe01-ipv4.yaml")

        assert_xrd_srmpls_segments(
            PE01,
            "show segment-routing traffic-eng policy color 800 endpoint ipv4 10.255.4.5",
            ["16042", "16045"],
        )

    def test__dynamic_path_ipv4_from_frr_headend(self, lab):
        """Verify the expected OSPFv2/IPv4 path to pe01."""

        add_sr_policy(POLA, "/pe02-dynamic-ipv4.yaml")

        assert_frr_policy_active(PE02, "pe02-dynamic")

    def test__dynamic_path_ipv6_is_rejected_for_lack_of_topology(self, lab):
        """Verify an OSPFv3/IPv6 policy is rejected when no IPv6 topology is available."""

        result = run_command(
            f"docker exec {POLA} /bin/pola sr-policy add -f /pe01-ipv6.yaml -p {GRPC_PORT}"
        )
        assert result.returncode != 0, result.stdout
        assert "doesn't have a ipv6 Prefix-SID" in result.stderr, result.stderr
