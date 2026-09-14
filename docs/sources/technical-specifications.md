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

(IPv4 + SRv6 is not supported because SRv6 SIDs are IPv6 addresses.)
