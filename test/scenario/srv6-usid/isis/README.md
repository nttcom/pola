# SRv6 uSID Scenario Tests

End-to-end scenario tests for SRv6 uSID (RFC 9603) using Pola PCE,
GoBGP, and Containerlab.

## Topology

![Topology](./topo.png)

* `pe01` / `pe02`: PCEP PCCs and SR Policy headends
* `p01` / `p02`: Core routers
* `pola`: Pola PCE
* `gobgp`: BGP-LS speaker

## Test Flow

The lab is deployed once for the module. Each test installs and verifies
its own SR Policy.

1. Deploy the Containerlab topology
2. Wait for PCEP sessions
3. Verify the TED against `expected/ted.json`
4. Install and verify each SR Policy

## Test Cases

### `test__show_ted_advertises_usid_locators_and_endx_sids`

Verifies that every node advertises its own uSID locator and that all links
have uSID End.X SIDs. Also checks the `pola ted` text output.

### `test__explicit_path_usid_from_junos_headend`

Installs an explicit uSID policy from `pe02` to `pe01` via `p02` and `p01`.

Expected segment list:

```text
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1001::
```

Policy file: `input/sr-policies/pe02-explicit.yaml`

### `test__dynamic_path_usid_from_junos_headend`

Installs `DYNAMIC-POLICY` with color 100.

Expected segment list:

```text
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1001::
```

Policy file: `input/sr-policies/pe02-policy1.yaml`

The selected path is:

```text
pe02 -> p02 -> p01 -> pe01
```

The resulting SID list includes every traversed node.

### `test__dynamic_path_usid_loose_source_routing`

Installs `LOOSE-SOURCE-ROUTING-POLICY` with color 200.

Expected segment list:

```text
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1001::
```

The selected path is:

```text
pe02 -> p02 -> p01 -> p02 -> p01 -> pe01
```

The resulting SID list includes every traversed node.

Policy file: `input/sr-policies/pe02-policy-loose-source-routing.yaml`

### `test__dynamic_path_usid_from_xrd_headend`

Installs `DYNAMIC-POLICY-PE01` with color 300 on `pe01`.

Expected segment list:

```text
fcbb:bb00:1003::
fcbb:bb00:1004::
fcbb:bb00:1002::
```

The selected path is:

```text
pe01 -> p01 -> p02 -> pe02
```

Policy file: `input/sr-policies/pe01-policy1.yaml`

> [!NOTE]
> `xfail`: IOS-XR 24.4.1 silently drops PCE-initiated SRv6 candidate paths.
> No PCRpt is sent and the policy is not installed. See the `xfail` reason
> in `test_srv6_usid_isis.py`.
