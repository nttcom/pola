# OSPF SR-MPLS Scenario Tests

End-to-end scenario tests for OSPF dynamic and explicit path computation
using Pola PCE, GoBGP, and Containerlab.

## Topology

```text
                  +------+
         +--------| p01  |--------+
         |        | XRd  |        |
         |        +------+        |
     +------+                +------+
     | pe01 |                | pe02 |
     | XRd  |                | FRR  |
     +------+                +------+
         |        +------+        |
         +--------| p02  |--------+
                  | XRd  |
                  +------+
```

- `pe01`: PE, PCC, SR Policy headend, BGP-LS exporter (XRd)
- `pe02`: PE, PCC, SR Policy headend (FRR, OSPFv2 only)
- `p01` / `p02`: Core routers
- `pola`: Pola PCE
- `gobgp`: BGP-LS speaker

`pe01`, `p01`, `p02` run OSPFv2 and OSPFv3 (area 0, SR-MPLS on v2 only).
Link costs: 5 on `pe01`–`p01`, 10 on others. `pe02` is OSPFv2-only.

> [!IMPORTANT]
> IOS-XR 24.4.1's OSPFv3 has no BGP-LS export or SR-MPLS support, so IPv6
> topology is invisible to Pola. OSPFv3 runs for realism but cannot be a
> dynamic-path underlay. See `test__dynamic_path_ipv6_is_rejected_for_lack_of_topology`.

> [!NOTE]
> vJunos-router is excluded (5 GiB memory per run). Junos headend behavior
> is covered by `sr-mpls/isis` and `sr-mpls/isis-dual-stack`.
> This lab uniquely exercises Pola's OSPF BGP-LS ingestion.

## Test Cases

### `test__show_ted_contains_ospfv2_nodes_and_prefix_sids`

Verifies `pola ted` (text output) contains every OSPFv2 router ID and its
Prefix-SID index. This is part of this lab's coverage of `cmd/pola/ted_text.go`.

### `test__explicit_path_from_xrd_headend`

Installs `pe01-explicit`, an explicit path from `pe01` to `pe02` via `p01`,
and verifies it becomes operational on the XRd headend.

### `test__dynamic_path_ipv4_from_xrd_headend`

Installs `OSPFV2-IPV4-POLICY` (color 800) from `pe01` to `pe02`.
The lower cost via `p01` makes the expected segment list deterministic.

### `test__dynamic_path_ipv4_from_frr_headend`

Installs `pe02-dynamic` (color 803) from `pe02` to `pe01`.
FRR reports only `Status: Active`, so the resolved segment list is not asserted.

### `test__dynamic_path_ipv6_is_rejected_for_lack_of_topology`

Verifies `pola sr-policy add` for `OSPFV3-IPV6-POLICY` (color 801, endpoint
`p02`) fails cleanly with `node doesn't have a ipv6 Prefix-SID`, since
OSPFv3's IPv6 topology is invisible to `pola` on this platform (see the
`[!IMPORTANT]` note above).
