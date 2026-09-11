# SRv6 IS-IS Scenario Tests (full-SIDs)

End-to-end scenario tests for full-SID (128-bit) SRv6 explicit and dynamic
path computation using Pola PCE, GoBGP, and Containerlab.

## Topology

Same shape and IS-IS metrics as [`srv6-usid/isis`](../../srv6-usid/isis):

```text
        pe01 (XRd) ---10--- p01 (XRd)
          |    \           /    |
         100    \         /    100      p01-p02 = 10
          |      \       /      |
        p02 (XRd) ---10--- pe02 (vJunos)
```

- `pe01`: PE, PCC, BGP-LS exporter (XRd)
- `pe02`: PE, PCC, SR Policy headend (vJunos)
- `p01` / `p02`: Core routers (XRd)
- `pola`: Pola PCE
- `gobgp`: BGP-LS speaker

Each node advertises a `/64` SRv6 locator: `pe01` `2001:db8:0:a1::/64`,
`pe02` `2001:db8:0:a2::/64`, `p01` `2001:db8:0:a3::/64`, `p02` `2001:db8:0:a4::/64`.

> [!IMPORTANT]
> FRRouting is excluded: FRR 10.7's `pathd` aborts on PCInitiate with IPv6
> ENDPOINTS (FRRouting/frr#22840).
>
> No XRd dynamic-path test here: IOS-XR 24.4.1 silently drops PCE-initiated
> SRv6 candidate paths (already covered by `srv6-usid/isis` — no new signal).

## SID Structure

IOS-XR dynamically allocates End SID function values for full-SID (non-uSID)
locators, so exact SID values are non-deterministic across boots.
For this reason:

- `expected/ted.json` omits `srv6Sids` and `srv6EndXSids`
- `test__show_ted_advertises_full_sid_locators_and_endx_sids` asserts SID
  *containment* in the locator instead of exact values
- `test__explicit_path_srv6_from_junos_headend` reads the live TED to build
  the segment list at runtime (via `write_policy_file`)

## Test Cases

### `test__show_ted_advertises_full_sid_locators_and_endx_sids`

For every node: exactly one SRv6 SID, contained in that node's own locator;
every link's End.X SIDs are full SID (not uSID) and contained in the
advertising node's own locator. Also verifies `pola ted` (text output)
contains `pe01`'s locator prefix.

### `test__explicit_path_srv6_from_junos_headend`

Reads the live TED, resolves the SRv6 SIDs of `p02`, `p01`, and `pe01`, and
installs an explicit path from `pe02` built from those SIDs at runtime.

### `test__dynamic_path_srv6_from_junos_headend`

Installs `pe02-dynamic` (color 500) from `pe02` to `pe01`. The cheapest
`pe02`-to-`pe01` path is `pe02`-`p02`-`p01`-`pe01` (10+10+10 = 30) versus
`pe02`-`p01`-`pe01` (100+10 = 110); Pola emits one SID per traversed node.
