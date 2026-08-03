# Dynamic Path Scenario Tests

This directory contains end-to-end scenario tests for SRv6 uSID dynamic path computation using Pola PCE, GoBGP, and Containerlab.

The tests verify:

- PCEP session establishment
- TED (Traffic Engineering Database) population
- Dynamic SR Policy installation
- SRv6 uSID segment list generation on the headend router

## Topology

![Topology](./topo.png)

The topology consists of:

- `pe01`
  - Provider edge router
- `pe02`
  - Provider edge router
  - PCEP PCC and SR Policy headend router
- `p01` / `p02`
  - Core routers
- `pola`
  - Pola PCE
- `gobgp`
  - BGP-LS speaker used to collect topology information

## Test Flow

The topology is deployed once for the whole module, then every test case installs
its own SR Policy on it. Each policy uses a distinct color and name, so the test
cases stay independent of each other and of their execution order.

1. Deploy the Containerlab topology
2. Wait for the PCEP session establishment
3. Wait until all routers appear in the TED
4. Wait until all expected links appear in the TED

Then, per test case:

1. Install an SR Policy via `pola sr-policy add`
2. Verify that the SR Policy becomes `Up`
3. Verify the generated SRv6 uSID segment list

## Test Cases

### `test__srv6_usid_dynamic_path`

Verifies normal dynamic path computation.
Installs `DYNAMIC-POLICY` with color 100.

Expected segment list:

```text
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1001::
```

Policy file:

```text
srv6-usid/input/sr-policies/pe02-policy1.yaml
```

> [!NOTE]
> According to the IGP cost, the traffic is forwarded along the following path:
>
> ```text
> pe02 -> p02 -> p01 -> pe01
> ```
>
> In the current Pola PCE implementation, the resulting SRv6 SID list includes the SID of every traversed node.

### `test__srv6_usid_loose_source_routing`

Verifies loose source routing behavior with repeated waypoint traversal.
Installs `LOOSE-SOURCE-ROUTING-POLICY` with color 200.

Expected segment list:

```text
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1004::
fcbb:bb00:1003::
fcbb:bb00:1001::
```

> [!NOTE]
> According to the IGP cost, the traffic is forwarded along the following path:
>
> ```text
> pe02 -> p02 -> p01 -> p02 -> p01 -> pe01
> ```
>
> In the current Pola PCE implementation, the resulting SRv6 SID list includes the SID of every traversed node.

Policy file:

```text
srv6-usid/input/sr-policies/pe02-policy-loose-source-routing.yaml
```
