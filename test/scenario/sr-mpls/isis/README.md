# SR-MPLS IS-IS Scenario Tests

End-to-end scenario tests for SR-MPLS explicit and dynamic path computation
using Pola PCE, GoBGP, and Containerlab.

## Topology

```text
              p01 (XRd)                metric 10
            /    |    \
        pe01   pe02   pe03
        (XRd) (vJunos) (FRR)
            \    |    /
              p02 (FRR)                metric 100
```

* `pe01`: PE, PCC, SR Policy headend, BGP-LS exporter (XRd)
* `pe02`: PE, PCC, SR Policy headend (vJunos)
* `pe03`: PE, PCC, SR Policy headend (FRR)
* `p01` / `p02`: Core routers
* `pola`: Pola PCE
* `gobgp`: BGP-LS speaker

SRGB: `16000-23999` on all nodes. Prefix-SID indexes `31`–`35`
(labels `16031`–`16035`) for `pe01`, `pe02`, `pe03`, `p01`, `p02`.

## Test Flow

1. Deploy the Containerlab topology
2. Wait for PCEP session establishment
3. Verify the TED matches `expected/ted.json`
4. For each test: install an SR Policy and verify its expected state

## Test Cases

### `test__show_ted_contains_every_node_with_prefix_sids`

Verifies `pola ted` (text output) contains every node, its loopback prefix,
Prefix-SID index, and the shared SRGB.

### `test__show_ted_exposes_adjacency_sids`

Verifies every core link exposes a non-empty Adjacency-SID list.

> [!NOTE]
> Currently `xfail` (`strict=True`): upstream GoBGP v4.9.0 does not expose
> the Adjacency-SID information needed by the scenario, so `adjSids` is empty.

### `test__explicit_path_with_nai_installs_on_every_pcc`

Verifies that explicit paths with and without per-SID `localAddr` are
accepted by all three PCCs.

| File                        | PCC           | Endpoint   | Segment List   | NAI          |
| --------------------------- | ------------- | ---------- | -------------- | ------------ |
| `pe01-explicit.yaml`        | pe01 (XRd)    | 10.255.3.2 | 16034 -> 16032 | IPv4 node ID |
| `pe02-explicit-nai.yaml`    | pe02 (vJunos) | 10.255.3.1 | 16034 -> 16031 | IPv4 node ID |
| `pe02-explicit-no-nai.yaml` | pe02 (vJunos) | 10.255.3.1 | 16034 -> 16031 | absent       |
| `pe03-explicit.yaml`        | pe03 (FRR)    | 10.255.3.1 | 16034 -> 16031 | IPv4 node ID |

### `test__explicit_path_rejects_a_sid_absent_from_the_ted`

Verifies `pe01-explicit-unknown-sid.yaml` (SID `16999`) is refused with
`SID validation failed`.

### `test__dynamic_path_from_xrd_headend`

Installs `pe01-dynamic` (color 101) from `pe01` (XRd) to `pe03`.

### `test__dynamic_path_from_junos_headend`

Installs `pe02-dynamic` (color 102) from `pe02` (vJunos) to `pe01`.

### `test__dynamic_path_from_frr_headend`

Installs `pe03-dynamic` (color 103) from `pe03` (FRR) to `pe01`.
FRR reports only `Status: Active`, so the resolved segment list is not
asserted.
