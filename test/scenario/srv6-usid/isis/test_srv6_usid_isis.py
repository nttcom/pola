# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import pytest
from helpers.scenario import (
    add_sr_policy,
    assert_xrd_srv6_segments,
    deploy_lab,
    get_ted_text,
    junos_lsp_detail,
    junos_srv6_sids,
    lab_dir_of,
)
from helpers.wait import get_ted, run_command

LAB = "srv6-usid-isis"
LAB_DIR = lab_dir_of(__file__)
POLA = f"clab-{LAB}-pola"
PE01 = f"clab-{LAB}-pe01"  # XRd
PE02 = f"clab-{LAB}-pe02"  # vJunos
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

PCEP_ADDRS = ["fd00::1", "fd00::2"]

# uN: 0x002B-0x0032, uA: 0x0034-0x003B.
USID_RANGES = ((0x002B, 0x0032), (0x0034, 0x003B))

NODE_SIDS = {
    "0000.0001.0001": "fcbb:bb00:1001::",
    "0000.0001.0002": "fcbb:bb00:1002::",
    "0000.0001.0003": "fcbb:bb00:1003::",
    "0000.0001.0004": "fcbb:bb00:1004::",
}


@pytest.fixture(scope="module")
def lab(clab_deploy_module):
    deploy_lab(clab_deploy_module, LAB_DIR, POLA, PCEP_ADDRS, ROUTER_IDS, LINKS)


def _is_usid_behavior(behavior: int) -> bool:
    return any(lo <= behavior <= hi for lo, hi in USID_RANGES)


def _assert_usid_dynamic_segments(policy_file, lsp_name, color, expected_segments):
    add_sr_policy(POLA, policy_file)

    lsp_output = junos_lsp_detail(PE02, lsp_name)

    assert f"fd00:ffff::1-{color}" in lsp_output
    assert "SID type: Micro SRv6 SID" in lsp_output

    actual_segments = junos_srv6_sids(lsp_output)
    assert actual_segments == expected_segments, (
        f"SR-ERO segment list mismatch.\n"
        f"Expected: {expected_segments}\nActual:   {actual_segments}"
    )


class TestSRv6UsidIsis:
    def test__show_ted_advertises_usid_locators_and_endx_sids(self, lab):
        """Verify every node advertises its uSID locator and End.X behaviors."""

        ted = get_ted(POLA)
        nodes_by_id = {node.get("routerId"): node for node in ted}

        for router_id, expected_sid in NODE_SIDS.items():
            node = nodes_by_id[router_id]
            sids = [s["sids"][0] for s in node.get("srv6Sids", []) if s.get("sids")]
            assert sids == [expected_sid], (
                f"node {router_id}: srv6Sids mismatch: {sids}"
            )

            for link in node.get("links", []):
                behaviors = [
                    sid.get("endpointBehavior", {}).get("behavior")
                    for sid in link.get("srv6EndXSids", [])
                ]
                assert behaviors, f"node {router_id}: link {link} has no srv6EndXSids"
                assert all(_is_usid_behavior(b) for b in behaviors), (
                    f"node {router_id}: expected only uSID behaviors, got {behaviors}"
                )

        ted_text = get_ted_text(POLA)
        assert "fcbb:bb00:1001::" in ted_text, ted_text

    def test__explicit_path_usid_from_junos_headend(self, lab):
        """Verify the expected explicit uSID segment list is installed."""

        add_sr_policy(POLA, "/pe02-explicit.yaml")

        lsp_output = junos_lsp_detail(PE02, "pe02-explicit")
        actual_segments = junos_srv6_sids(lsp_output)

        assert actual_segments == [
            "fcbb:bb00:1004::",
            "fcbb:bb00:1003::",
            "fcbb:bb00:1001::",
        ], f"SR-ERO segment list mismatch.\nActual: {actual_segments}\n{lsp_output}"

    def test__dynamic_path_usid_from_junos_headend(self, lab):
        """Verify the expected dynamic uSID segment list is installed."""

        _assert_usid_dynamic_segments(
            "/pe02-policy1.yaml",
            "DYNAMIC-POLICY",
            100,
            [
                "fcbb:bb00:1004::",
                "fcbb:bb00:1003::",
                "fcbb:bb00:1001::",
            ],
        )

    def test__dynamic_path_usid_loose_source_routing(self, lab):
        """Verify the expected dynamic uSID segment list with loose source routing."""

        _assert_usid_dynamic_segments(
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

    @pytest.mark.xfail(
        reason=(
            "IOS-XR 24.4.1 drops PCE-initiated SRv6 candidate paths: "
            "no PCRpt is sent and the policy is not installed."
        ),
        strict=False,
    )
    def test__dynamic_path_usid_from_xrd_headend(self, lab):
        """Verify XRd resolves the expected dynamic uSID segment list."""

        result = run_command(
            f"docker exec {POLA} /bin/pola sr-policy add -f /pe01-policy1.yaml -p {GRPC_PORT}"
        )
        assert "success" in result.stdout.lower(), (
            f"failed to add /pe01-policy1.yaml\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )

        assert_xrd_srv6_segments(
            PE01,
            "show segment-routing traffic-eng policy color 300 endpoint ipv6 fd00:ffff::2",
            ["fcbb:bb00:1003::", "fcbb:bb00:1004::", "fcbb:bb00:1002::"],
        )
