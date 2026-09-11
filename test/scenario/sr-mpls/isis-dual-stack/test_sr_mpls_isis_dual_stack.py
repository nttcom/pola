# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import pytest
from helpers.scenario import (
    add_sr_policy,
    assert_frr_policy_active,
    assert_xrd_srmpls_segments,
    deploy_lab,
    junos_lsp_detail,
    junos_srmpls_labels,
    lab_dir_of,
)
from helpers.wait import get_ted, wait_for_ssh, wait_until_ted, wait_until_ted_has_links

LAB = "sr-mpls-isis-dual-stack"
LAB_DIR = lab_dir_of(__file__)
POLA = f"clab-{LAB}-pola"
PE01 = f"clab-{LAB}-pe01"  # XRd headend
PE02 = f"clab-{LAB}-pe02"  # vJunos headend
PE03 = f"clab-{LAB}-pe03"  # FRRouting headend (IPv4-only)

ROUTER_IDS = [
    "0000.0002.0001",  # pe01 (IPv4-only loopback identity)
    "0000.0002.0002",  # p01 (dual-stack transit, IPv4-cheap / IPv6-expensive)
    "0000.0002.0003",  # p02 (dual-stack transit, IPv4-expensive / IPv6-cheap)
    "0000.0002.0004",  # pe02 (IPv4-only loopback identity, PCEP headend)
    "0000.0002.0005",  # pe03 (FRRouting, IPv4-only headend)
]

LINKS = {
    frozenset(("0000.0002.0001", "0000.0002.0002")),
    frozenset(("0000.0002.0001", "0000.0002.0003")),
    frozenset(("0000.0002.0002", "0000.0002.0004")),
    frozenset(("0000.0002.0003", "0000.0002.0004")),
    frozenset(("0000.0002.0002", "0000.0002.0005")),
    frozenset(("0000.0002.0003", "0000.0002.0005")),
}

PCEP_ADDRS = ["10.0.30.1", "10.0.30.2", "10.0.30.5"]

pytestmark = pytest.mark.xdist_group(LAB)


@pytest.fixture(scope="module")
def lab(clab_deploy_module):
    deploy_lab(clab_deploy_module, LAB_DIR, POLA, PCEP_ADDRS, ROUTER_IDS, LINKS)


class TestSRMPLSISISDualStack:
    """Test dual-stack TED contents and underlay path selection."""

    def test__show_ted_exposes_per_family_topology_details(self, lab):
        """Verify IPv4/IPv6 topology details in the dual-stack TED."""

        ted = get_ted(POLA)

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

        nodes_by_router_id = {node.get("routerId"): node for node in ted}
        prefixes = {
            p.get("prefix")
            for p in nodes_by_router_id["0000.0002.0004"].get("prefixes", [])
        }
        assert "2001:db8:200:4::1/128" in prefixes, (
            f"pe02 did not advertise its IPv6 loopback as a /128 prefix\nfull TED: {ted}"
        )

    @pytest.mark.xfail(
        reason=(
            "Scenario gobgpd uses upstream GoBGP v4.9.0, where "
            "lsAttrLink.GetSrAdjacencySids() is unavailable, so adjSids is always empty."
        ),
        strict=True,
    )
    def test__show_ted_distinguishes_adjacency_sids_by_family(self, lab):
        """Verify IPv4 and IPv6 Adjacency-SIDs are distinguished by family."""

        ted = get_ted(POLA)

        families_by_link = [
            {adj_sid["family"] for adj_sid in link.get("adjSids", [])}
            for node in ted
            for link in node.get("links", [])
            if len(link.get("adjSids", [])) >= 2
        ]

        assert any(families == {"ipv4", "ipv6"} for families in families_by_link), (
            "expected a dual-stack link to expose distinct IPv4 and IPv6 "
            f"Adjacency-SIDs, got: {families_by_link}\nfull TED: {ted}"
        )

    def test__explicit_path_from_junos_headend_via_p01(self, lab):
        """Verify the expected explicit SR-MPLS label stack."""

        add_sr_policy(POLA, "/pe02-explicit.yaml")

        lsp_output = junos_lsp_detail(PE02, "pe02-explicit")
        labels = junos_srmpls_labels(lsp_output)

        assert labels == ["16022", "16021"], (
            f"SR-ERO label stack mismatch.\nExpected: ['16022', '16021']\n"
            f"Actual:   {labels}\n{lsp_output}"
        )

    @pytest.mark.xfail(
        reason=(
            "Scenario gobgpd uses upstream GoBGP v4.9.0, where "
            "lsAttrLink.GetSrAdjacencySids() is unavailable, so adjSids is always empty."
        ),
        strict=True,
    )
    def test__dynamic_path_ipv4_from_junos_headend(self, lab):
        """Verify the expected IPv4 path via p01 is selected."""

        add_sr_policy(POLA, "/pe02-ipv4.yaml")

        lsp_output = junos_lsp_detail(PE02, "DUAL-STACK-IPV4-POLICY")
        labels = junos_srmpls_labels(lsp_output)
        assert labels == ["16022", "16021"], (
            f"SR-ERO label stack mismatch.\nExpected: ['16022', '16021']\n"
            f"Actual:   {labels}\n{lsp_output}"
        )

    @pytest.mark.xfail(
        reason=(
            "Scenario gobgpd uses upstream GoBGP v4.9.0, where "
            "lsAttrLink.GetSrAdjacencySids() is unavailable, so adjSids is always empty."
        ),
        strict=True,
    )
    def test__dynamic_path_ipv6_from_junos_headend(self, lab):
        """Verify the expected IPv6 path via p02 is selected."""

        add_sr_policy(POLA, "/pe02-ipv6.yaml")

        lsp_output = junos_lsp_detail(PE02, "DUAL-STACK-IPV6-POLICY")
        labels = junos_srmpls_labels(lsp_output)
        assert labels == ["16123", "16121"], (
            f"SR-ERO label stack mismatch.\nExpected: ['16123', '16121']\n"
            f"Actual:   {labels}\n{lsp_output}"
        )

    def test__dynamic_path_ipv4_from_xrd_headend(self, lab):
        """Verify the expected IPv4 path via p01 is selected."""

        add_sr_policy(POLA, "/pe01-ipv4.yaml")

        assert_xrd_srmpls_segments(
            PE01,
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
    def test__dynamic_path_ipv6_from_xrd_headend(self, lab):
        """Verify the expected IPv6 path via p02 is selected."""

        add_sr_policy(POLA, "/pe01-ipv6.yaml")

        assert_xrd_srmpls_segments(
            PE01,
            "show segment-routing traffic-eng policy color 601 endpoint ipv6 2001:db8:200:4::1",
            ["16123", "16124"],
        )

    def test__dynamic_path_ipv4_from_frr_headend(self, lab):
        """Verify the expected IPv4 path via p01 is selected."""

        add_sr_policy(POLA, "/pe03-ipv4.yaml")

        assert_frr_policy_active(PE03, "pe03-ipv4")


class TestSRMPLSISISDualStackTedUpdate:
    """Verify TED updates after a link-down event; runs last because it mutates shared lab state."""

    def test__show_ted_drops_a_link_when_the_interface_goes_down(self, lab):
        """Verify the pe02-p01 link disappears from the TED when disabled and reappears after recovery."""

        dropped_link = frozenset(("0000.0002.0004", "0000.0002.0002"))

        def link_is_absent(ted):
            found = set()
            for node in ted:
                local = node.get("routerId")
                for link in node.get("links", []):
                    remote = link.get("remote", {}).get("routerId")
                    if local and remote:
                        found.add(frozenset((local, remote)))
            return dropped_link not in found

        ssh_client = wait_for_ssh(PE02)
        try:
            _, stdout, stderr = ssh_client.exec_command(
                "configure; set interfaces ge-0/0/0 disable; commit"
            )
            print(stdout.read().decode())
            print(stderr.read().decode())

            wait_until_ted(POLA, link_is_absent)
        finally:
            _, stdout, stderr = ssh_client.exec_command(
                "configure; delete interfaces ge-0/0/0 disable; commit"
            )
            print(stdout.read().decode())
            print(stderr.read().decode())
            ssh_client.close()

        wait_until_ted_has_links(POLA, LINKS)
