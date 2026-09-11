# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import pytest
from helpers.scenario import (
    add_sr_policy,
    add_sr_policy_expecting_error,
    assert_frr_policy_active,
    assert_xrd_policy_installed,
    assert_xrd_srmpls_segments,
    deploy_lab,
    get_ted_text,
    junos_lsp_detail,
    junos_nais,
    junos_srmpls_labels,
    lab_dir_of,
)
from helpers.wait import get_ted

LAB = "sr-mpls-isis"
LAB_DIR = lab_dir_of(__file__)
POLA = f"clab-{LAB}-pola"
PE01 = f"clab-{LAB}-pe01"  # XRd
PE02 = f"clab-{LAB}-pe02"  # vJunos
PE03 = f"clab-{LAB}-pe03"  # FRRouting

pytestmark = pytest.mark.xdist_group(LAB)

ROUTER_IDS = [
    "0000.0003.0001",
    "0000.0003.0002",
    "0000.0003.0003",
    "0000.0003.0004",
    "0000.0003.0005",
]

LINKS = {
    frozenset(("0000.0003.0001", "0000.0003.0004")),
    frozenset(("0000.0003.0002", "0000.0003.0004")),
    frozenset(("0000.0003.0003", "0000.0003.0004")),
    frozenset(("0000.0003.0001", "0000.0003.0005")),
    frozenset(("0000.0003.0002", "0000.0003.0005")),
    frozenset(("0000.0003.0003", "0000.0003.0005")),
}

PCEP_ADDRS = ["10.0.60.1", "10.0.60.2", "10.0.60.5"]


@pytest.fixture(scope="module")
def lab(clab_deploy_module):
    deploy_lab(clab_deploy_module, LAB_DIR, POLA, PCEP_ADDRS, ROUTER_IDS, LINKS)


class TestSRMPLSIsis:
    def test__show_ted_contains_every_node_with_prefix_sids(self, lab):
        """Verify every node and its Prefix-SID index appear in the TED."""

        ted_text = get_ted_text(POLA)

        assert "Node #" in ted_text, ted_text
        assert "SRGB: 16000 - 24000" in ted_text, ted_text

        for router_id, ip, index in [
            ("0000.0003.0001", "10.255.3.1", "31"),
            ("0000.0003.0002", "10.255.3.2", "32"),
            ("0000.0003.0003", "10.255.3.3", "33"),
            ("0000.0003.0004", "10.255.3.4", "34"),
            ("0000.0003.0005", "10.255.3.5", "35"),
        ]:
            assert router_id in ted_text, ted_text
            assert f"{ip}/32" in ted_text, ted_text
            assert f"index: {index}" in ted_text, ted_text

    @pytest.mark.xfail(
        reason=(
            "Scenario gobgpd uses upstream GoBGP v4.9.0, where "
            "lsAttrLink.GetSrAdjacencySids() is unavailable, so adjSids is always empty."
        ),
        strict=True,
    )
    def test__show_ted_exposes_adjacency_sids(self, lab):
        """Verify every link exposes a non-empty Adjacency-SID list."""

        ted = get_ted(POLA)

        for node in ted:
            for link in node.get("links", []):
                assert link.get("adjSids"), (
                    f"node {node.get('routerId')}: link {link} has no adjSids"
                )

    def test__explicit_path_with_nai_installs_on_every_pcc(self, lab):
        """Verify explicit-path policies with and without per-SID localAddr."""

        add_sr_policy(POLA, "/pe01-explicit.yaml")
        add_sr_policy(POLA, "/pe02-explicit-nai.yaml")
        add_sr_policy(POLA, "/pe03-explicit.yaml")
        add_sr_policy(POLA, "/pe02-explicit-no-nai.yaml", no_sid_validate=True)

        with_nai = junos_lsp_detail(PE02, "pe02-explicit-nai")
        assert junos_nais(with_nai) == [
            "IPv4 Node ID, Node address: 10.255.3.4",
            "IPv4 Node ID, Node address: 10.255.3.1",
        ], f"SR-ERO NAI mismatch.\n{with_nai}"
        assert junos_srmpls_labels(with_nai) == ["16034", "16031"], with_nai

        without_nai = junos_lsp_detail(PE02, "pe02-explicit-no-nai")
        assert junos_nais(without_nai) == ["None", "None"], (
            f"expected no NAI without localAddr\n{without_nai}"
        )

        assert_xrd_policy_installed(PE01, "pe01-explicit", ["16034", "16032"])
        assert_frr_policy_active(PE03, "pe03-explicit")

    def test__explicit_path_rejects_a_sid_absent_from_the_ted(self, lab):
        """Verify a SID absent from the TED is refused by SID validation."""

        add_sr_policy_expecting_error(
            POLA, "/pe01-explicit-unknown-sid.yaml", ["SID validation failed", "16999"]
        )

    def test__dynamic_path_from_xrd_headend(self, lab):
        """Verify XRd resolves the expected SR-MPLS path to pe03."""

        add_sr_policy(POLA, "/pe01-dynamic.yaml")

        assert_xrd_srmpls_segments(
            PE01,
            "show segment-routing traffic-eng policy color 101 endpoint ipv4 10.255.3.3",
            ["16034", "16033"],
        )

    def test__dynamic_path_from_junos_headend(self, lab):
        """Verify vJunos resolves the expected SR-MPLS path to pe01."""

        add_sr_policy(POLA, "/pe02-dynamic.yaml")

        labels = junos_srmpls_labels(junos_lsp_detail(PE02, "pe02-dynamic"))
        assert labels == ["16034", "16031"], labels

    def test__dynamic_path_from_frr_headend(self, lab):
        """Verify FRRouting resolves the expected SR-MPLS path to pe01."""

        add_sr_policy(POLA, "/pe03-dynamic.yaml")

        assert_frr_policy_active(PE03, "pe03-dynamic")
