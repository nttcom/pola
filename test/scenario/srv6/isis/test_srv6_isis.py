# Copyright (c) 2022 NTT Communications Corporation
#
# This software is released under the MIT License.
# see https://github.com/nttcom/pola/blob/main/LICENSE

import pytest
from helpers.scenario import (
    add_sr_policy,
    assert_sids_in_locators,
    deploy_lab,
    get_ted_text,
    junos_lsp_detail,
    junos_srv6_sids,
    lab_dir_of,
    srv6_node_sids,
    write_policy_file,
)
from helpers.wait import get_ted

LAB = "srv6-isis"
LAB_DIR = lab_dir_of(__file__)
POLA = f"clab-{LAB}-pola"
PE01 = f"clab-{LAB}-pe01"  # XRd
PE02 = f"clab-{LAB}-pe02"  # vJunos

pytestmark = pytest.mark.xdist_group(LAB)

ROUTER_IDS = [
    "0000.0005.0001",
    "0000.0005.0002",
    "0000.0005.0003",
    "0000.0005.0004",
]

LINKS = {
    frozenset(("0000.0005.0001", "0000.0005.0003")),
    frozenset(("0000.0005.0001", "0000.0005.0004")),
    frozenset(("0000.0005.0002", "0000.0005.0003")),
    frozenset(("0000.0005.0002", "0000.0005.0004")),
    frozenset(("0000.0005.0003", "0000.0005.0004")),
}

PCEP_ADDRS = ["fd00:5::1", "fd00:5::2"]

LOCATORS = {
    "0000.0005.0001": "2001:db8:0:a1::/64",
    "0000.0005.0002": "2001:db8:0:a2::/64",
    "0000.0005.0003": "2001:db8:0:a3::/64",
    "0000.0005.0004": "2001:db8:0:a4::/64",
}

# uN: 0x002B-0x0032, uA: 0x0034-0x003B.
USID_RANGES = ((0x002B, 0x0032), (0x0034, 0x003B))


@pytest.fixture(scope="module")
def lab(clab_deploy_module):
    deploy_lab(clab_deploy_module, LAB_DIR, POLA, PCEP_ADDRS, ROUTER_IDS, LINKS)


def _is_usid_behavior(behavior: int) -> bool:
    return any(lo <= behavior <= hi for lo, hi in USID_RANGES)


class TestSRv6Isis:
    def test__show_ted_advertises_full_sid_locators_and_endx_sids(self, lab):
        """Verify every node advertises its full-SID SRv6 locator and End.X behaviors."""

        ted = get_ted(POLA)
        nodes_by_id = {node.get("routerId"): node for node in ted}

        for router_id, locator in LOCATORS.items():
            node = nodes_by_id[router_id]

            sids = [s["sids"][0] for s in node.get("srv6Sids", []) if s.get("sids")]
            assert_sids_in_locators(sids, [locator])

            for link in node.get("links", []):
                end_x_sids = link.get("srv6EndXSids", [])
                assert end_x_sids, f"node {router_id}: link {link} has no srv6EndXSids"

                for end_x_sid in end_x_sids:
                    behavior = end_x_sid.get("endpointBehavior", {}).get("behavior")
                    assert not _is_usid_behavior(behavior), (
                        f"node {router_id}: expected a full-SID End.X behavior, got uSID behavior {behavior}"
                    )

                    for sid in end_x_sid.get("sids", []):
                        assert_sids_in_locators([sid], [locator])

        ted_text = get_ted_text(POLA)
        assert "2001:db8:0:a1:" in ted_text, ted_text

    def test__explicit_path_srv6_from_junos_headend(self, lab):
        """Verify the explicit full-SID SRv6 segment list is installed."""

        ted = get_ted(POLA)

        p02_sid = srv6_node_sids(ted, "0000.0005.0004")[0]
        p01_sid = srv6_node_sids(ted, "0000.0005.0003")[0]
        pe01_sid = srv6_node_sids(ted, "0000.0005.0001")[0]

        policy_yaml = f"""asn: 65000
srPolicy:
  pcepSessionAddr: "fd00:5::2"
  headend: "fd00:ffff:5::2"
  endpoint: "fd00:ffff:5::1"
  name: pe02-explicit
  color: 501
  candidatePath:
    explicit:
      segmentList:
        - sid: "{p02_sid}"
        - sid: "{p01_sid}"
        - sid: "{pe01_sid}"
"""
        write_policy_file(POLA, "/pe02-explicit.yaml", policy_yaml)
        add_sr_policy(POLA, "/pe02-explicit.yaml")

        lsp_output = junos_lsp_detail(PE02, "pe02-explicit")
        assert_sids_in_locators(
            junos_srv6_sids(lsp_output),
            [
                LOCATORS["0000.0005.0004"],
                LOCATORS["0000.0005.0003"],
                LOCATORS["0000.0005.0001"],
            ],
        )

    def test__dynamic_path_srv6_from_junos_headend(self, lab):
        """Verify the expected SRv6 path via p02 and p01 is selected."""

        add_sr_policy(POLA, "/pe02-dynamic.yaml")

        lsp_output = junos_lsp_detail(PE02, "pe02-dynamic")
        assert_sids_in_locators(
            junos_srv6_sids(lsp_output),
            [
                LOCATORS["0000.0005.0004"],
                LOCATORS["0000.0005.0003"],
                LOCATORS["0000.0005.0001"],
            ],
        )
