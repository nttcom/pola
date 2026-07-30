# Explicit Path Scenario Tests

This directory contains end-to-end scenario tests for SR-MPLS explicit path SR Policies using Pola PCE and Containerlab.

The tests verify:

- PCEP session establishment with three different PCC implementations
- Explicit-path SR Policy installation via `pola sr-policy add --no-sid-validate` (without TED)
- The Node/Adjacency Identifier (NAI) built from the `localAddr` of each SID (RFC8664 4.3.1)
- Segment lists without `localAddr`, which must keep the NAI absent

## Topology

```text
                 +------+
        +--------| pe01 |--------+
        |        | XRd  |        |
        |        +------+        |
        |                        |
    +------+                +------+
    | pe02 |----------------| pe03 |
    |vJunos|                | FRR  |
    +------+                +------+

  pe01 / pe02 / pe03 are all PCEP PCCs of the pola node,
  connected through a management switch.
```

The topology consists of:

- `pe01`
  - Cisco XRd
  - PCEP PCC and SR Policy headend router
- `pe02`
  - Juniper vJunos-router
  - PCEP PCC and SR Policy headend router
- `pe03`
  - FRRouting
  - PCEP PCC and SR Policy headend router
- `pola`
  - Pola PCE, with TED disabled
- `switch`
  - Bridge that connects the PCE to every PCC

Prefix-SID labels are 16001 (pe01), 16002 (pe02) and 16003 (pe03).

## Test Flow

The scenario tests perform the following steps:

1. Deploy the Containerlab topology
2. Wait for the PCEP session establishment of all three PCCs
3. Install explicit-path SR Policies via `pola sr-policy add --no-sid-validate`
4. Verify that each PCC installs the policy and that the SR-ERO label stack matches the input
5. Verify the NAI of each SR-ERO hop on the PCC that reports it

## Test Cases

### `test__srmpls_explicit_path_with_nai`

Verifies that an explicit path whose SIDs carry a `localAddr` is accepted by every PCC, and that a path without `localAddr` still installs with the NAI absent.

Policy files:

```text
srmpls/input/sr-policies/pe01-policy1.yaml
srmpls/input/sr-policies/pe02-policy1.yaml
srmpls/input/sr-policies/pe02-policy2.yaml
srmpls/input/sr-policies/pe03-policy1.yaml
```

| File | PCC | Endpoint | Segment List | NAI |
| --- | --- | --- | --- | --- |
| `pe01-policy1.yaml` | pe01 (XRd) | 10.255.0.2 | 16002 -> 16003 | IPv4 node ID |
| `pe02-policy1.yaml` | pe02 (vJunos-router) | 10.255.0.1 | 16001 -> 16003 | IPv4 node ID |
| `pe02-policy2.yaml` | pe02 (vJunos-router) | 10.255.0.1 | 16001 -> 16003 | absent |
| `pe03-policy1.yaml` | pe03 (FRRouting) | 10.255.0.1 | 16001 -> 16002 | IPv4 node ID |

> [!NOTE]
> Of the three PCCs, only vJunos-router prints the NAI of every SR-ERO hop
> (`show spring-traffic-engineering lsp name <name> detail`). The test therefore
> asserts the NAI itself on pe02, and asserts on pe01 and pe03 only that the
> policy is installed and operational, which is what proves those PCCs accept an
> SR-ERO subobject carrying an NAI.
