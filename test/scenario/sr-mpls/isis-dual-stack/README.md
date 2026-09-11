# SR-MPLS IS-IS Dual-Stack Scenario Tests

End-to-end scenario tests for dual-stack (IPv4 + IPv6) IS-IS SR-MPLS path
computation using Pola PCE, GoBGP, and Containerlab.

## Topology

```text
                  +------+
         +--------| p01  |--------+     IPv4 metric: cheap
         |        | XRd  |--------+---+ IPv6 metric: expensive
         |        +------+        |   |
     +------+                +------+ |
     | pe01 |                | pe02 | |
     | XRd  |                | Junos| |
     +------+                +------+ |
         |        +------+        |   |
         +--------| p02  |--------+   |
                  | XRd  |--------+---+
                  +------+        |
                              +------+
                              | pe03 |
                              | FRR  |
                              +------+
```

* `pe01`: PE, PCEP PCC, SR Policy headend (XRd)
* `pe02`: PE, PCEP PCC, SR Policy headend (vJunos)
* `pe03`: PE, PCEP PCC, SR Policy headend (FRR, IPv4-only)
* `p01` / `p02`: Core routers
* `pola`: Pola PCE
* `gobgp`: BGP-LS speaker

PE-P links are dual-stack with independent IS-IS metrics:
IPv4 prefers `p01`, while IPv6 prefers `p02`.

> [!IMPORTANT]
> Never send an IPv6-endpoint policy to `pe03` (FRR). FRR 10.7's `pathd`
> aborts on PCInitiate with IPv6 ENDPOINTS (FRRouting/frr#22840).

## Test Cases

### `test__show_ted_exposes_per_family_topology_details`

Verifies that dual-stack links expose both address families in the TED and
that `pe02` advertises its IPv6 loopback as a `/128` prefix.

### `test__show_ted_distinguishes_adjacency_sids_by_family`

Verifies that IPv4 and IPv6 Adjacency-SIDs on the same link are exposed as
separate, family-tagged TED entries.

> [!NOTE]
> Currently `xfail` (`strict=True`): upstream GoBGP v4.9.0 does not expose
> the Adjacency-SID information needed to distinguish the two address
> families, so `adjSids` is empty.

### `test__explicit_path_from_junos_headend_via_p01`

Installs `pe02-explicit`, an explicit SR-MPLS path from `pe02` to `pe01` via
`p01` (segment list `16022` -> `16021`).

### `test__dynamic_path_ipv4_from_junos_headend`

The IPv4 underlay selects the path via `p01`.

> [!NOTE]
> Currently `xfail` (`strict=True`): upstream GoBGP v4.9.0 does not preserve
> the Multi-Topology information needed for the dual-stack topology, causing
> Pola to compute the wrong IPv4 path. See the `xfail` reason in
> `test_sr_mpls_isis_dual_stack.py`.

### `test__dynamic_path_ipv6_from_junos_headend`

The IPv6 underlay selects the path via `p02`.

> [!NOTE]
> Currently `xfail`: Junos 26.2R1.7 rejects the PCE-initiated SR-MPLS policy
> because of an IPv6 SRPAG association. See the `xfail` reason in
> `test_sr_mpls_isis_dual_stack.py`.

### `test__dynamic_path_ipv4_from_xrd_headend`

The IPv4 underlay selects the path via `p01`.

### `test__dynamic_path_ipv6_from_xrd_headend`

The IPv6 underlay selects the path via `p02`.

> [!NOTE]
> Currently `xfail`: IOS-XR 24.4.1 rejects PCE-initiated SR-MPLS policies
> with an IPv6 endpoint. See the `xfail` reason in
> `test_sr_mpls_isis_dual_stack.py`.

### `test__dynamic_path_ipv4_from_frr_headend`

The IPv4 underlay selects the path via `p01` from `pe03`.
FRR reports only `Status: Active`, so the resolved segment list is not
asserted.

### `test__show_ted_drops_a_link_when_the_interface_goes_down`

Runs last because it mutates shared lab state. Disables `ge-0/0/0` on
`pe02`, verifies the `pe02`-`p01` link disappears from the TED, then restores
the interface and verifies the TED recovers.
