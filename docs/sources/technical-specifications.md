# Technical Specifications

This document provides technical details on data models, SRv6/SR-MPLS concepts, and protocol specifications used in Pola PCE.

## SRv6 Endpoint Behavior

### Overview

SRv6 Endpoint Behavior defines how a network node processes SRv6 SIDs. It is carried in the TED as part of the Endpoint Behavior TLV (RFC 9603 §4.3.1).

### EndpointBehavior Message Structure

The `EndpointBehavior` message in the gRPC API contains three fields:

- **behavior** (uint32): Endpoint behavior code as advertised via BGP-LS.
  - Defines how the node processes this SID: End, End.X, End.DT4, End.DT6, End.AD, etc. (see RFC 8986)
  - Used during segment list computation to understand node capabilities

- **flags** (uint32): 8-bit flags octet.
  - For End.X SID TLVs: B (Backup), S (Set), P (Persistent) flags are defined in RFC 9352, RFC 9513, and RFC 9514 §7.2
  - For Endpoint Behavior TLV: flags are currently undefined by IETF
  - Pola preserves and transports this field during TED ingestion and segment generation, but does not currently interpret or utilize the flag values

- **algorithm** (uint32): SRv6 Prefix-SID algorithm number.
  - Controls how a Prefix-SID label is derived from the SID value
  - RFC 8986 Fig. 8 defines:
    - 0 = Shortest Path First (SPF)
    - 1 = Strict Shortest Path First
  - Used by nodes implementing Prefix-SID construction from the locator

## TED Data Model

### Topology Encoding Database (TED)

The TED aggregates topology information from BGP-LS (RFC 7752) and makes it available for path computation via CSPF.

### Key Concepts

- **Node Identity**: Identified by IGP Router-ID (a string), not IP address. Dual-stack nodes are represented as a single node.
- **Link Identity**: Uniquely identified by (local router ID, remote router ID, local interface identifier, remote interface identifier, address family)
- **Address Family**: Link endpoints carry both IPv4 and IPv6 addresses independently; CSPF filters edges by the target address family
- **Underlay Plane**: A combination of address family (IPv4/IPv6) and data plane (SR-MPLS/SRv6) that constrains path computation

### Supported Underlay Planes

| Address Family | Data Plane | Status      |
| -------------- | ---------- | ----------- |
| IPv4           | SR-MPLS    | Supported   |
| IPv6           | SR-MPLS    | Supported   |
| IPv6           | SRv6       | Supported   |
| IPv4           | SRv6       | Not allowed |

## Known Limitations

### Standards limitations

- **SR Adjacency-SID**: IS-IS uses the F flag to distinguish IPv4/IPv6
  Adjacency-SIDs (RFC 8667 §2.2.1), but OSPFv3 has no equivalent flag.
  The address family of an OSPFv3 Adjacency-SID cannot be determined from BGP-LS.

### BGP-LS source limitations

- Scenario tests use upstream GoBGP, whose BGP-LS API does not yet expose Multi-Topology IDs ([#3589](https://github.com/osrg/gobgp/pull/3589)) or multiple Adjacency-SIDs ([#3591](https://github.com/osrg/gobgp/pull/3591)).
  Tests depending on these features are marked `xfail(strict=True)`.

### Pola gRPC client limitations

- `polad`'s GoBGP gRPC client does not bracket IPv6 addresses when building `address:port`.
  Therefore, it cannot connect using a bare IPv6 address.
  IPv6-only scenario labs use an IPv4 management subnet for the `polad`–`gobgpd` gRPC connection; the BGP-LS session still uses IPv6.

### IOS-XR interoperability

- IOS-XR 24.4.1 rejects PCE-initiated SR-MPLS policies with IPv6 endpoints (`pcinitiate: bad sock info`).
- IOS-XR 24.4.1 does not export OSPFv3 topology to BGP-LS, so OSPFv3-only nodes, links, and Prefix-SIDs are not available in the TED.
- IOS-XR 24.4.1 does not install PCE-initiated SRv6 candidate paths.

### Junos interoperability

- Junos 26.2R1.7 rejects PCE-initiated SR-MPLS policies with IPv6 endpoints (`IPv6 SRPAG received for non SRv6 LSP`).

### FRRouting interoperability

- FRR 10.7 `pathd` aborts on PCInitiate messages with IPv6 endpoints ([#22840](https://github.com/FRRouting/frr/issues/22840)). FRR is therefore not used as a headend for IPv6-endpoint SR-MPLS or SRv6 scenario tests.
- FRR 10.7 supports SRv6 and uSID in IS-IS, but FRR-to-IOS-XR SRv6 interop has not been verified. SRv6 scenario labs therefore use IOS-XR and Junos only.
