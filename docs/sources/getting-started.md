# Getting Started with Pola PCE

This page explains how to use Pola PCE.

## Installation

### From Go

```bash
go install github.com/nttcom/pola/cmd/polad@latest
```

### From Source

```bash
git clone https://github.com/nttcom/pola.git
cd pola
go install ./cmd/polad

# or, install with cli command
go install ./...
```

### From Container Image

See the [Docker page](../../build/package/README.md).

## Configuration

Configure the IP address and port for PCEP and gRPC.
`address` must be a literal IPv4 or IPv6 address; hostnames are not resolved.
See [JSON schema](../schemas/server/polad_config.json) for config details.

### Disabling TED

To manage SR Policy without using TED, disable TED as follows.

```yaml
global:
  pcep:
    address: "2001:0db8::254"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50051
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
  usidMode: false
```

### PCEP session timers

#### Advertising Pola's timers

`global.pcep.keepalive` and `global.pcep.deadTimer` configure the timers Pola
advertises in its Open message (RFC 5440 §7.3). They default to 30 and 120
seconds. If `keepalive` is `0`, `deadTimer` must also be `0`.

```yaml
global:
  pcep:
    address: "192.0.2.254"
    port: 4189
    keepalive: 30
    deadTimer: 120
```

#### Validating peer timers

`global.pcep.minKeepalive` and `global.pcep.maxKeepalive` limit the Keepalive
value that Pola accepts from a peer's Open message (RFC 7420). Both are
optional; omitting them disables validation.

If both are set, `minKeepalive` must be less than or equal to `maxKeepalive`.

`global.pcep.allowNegotiation` controls behavior when a peer's Keepalive is
outside the configured range. It defaults to `true`, allowing Pola to negotiate
the value; when `false`, the session is rejected.

```yaml
global:
  pcep:
    address: "192.0.2.254"
    port: 4189
    keepalive: 30
    deadTimer: 120
    minKeepalive: 10
    maxKeepalive: 60
```

### Enabling TED

To manage SR Policy using TED, enable TED as follows.
This also enables dynamic path calculation.

TED updates require a supported BGP-LS source.
Currently, only GoBGP is supported.

#### Underlay address family

Path computation runs on an **underlay plane**, a combination of address
family and data plane.

Supported combinations:

| underlayFamily | dataPlane | Status         |
| -------------- | --------- | -------------- |
| ipv4           | sr-mpls   | Supported      |
| ipv6           | sr-mpls   | Supported      |
| ipv6           | srv6      | Supported      |
| ipv4           | srv6      | Not applicable |

A dynamic candidate path selects the plane with `underlayFamily` and
`dataPlane`. If both are unspecified, Pola uses the headend's unique viable
plane and rejects the request when multiple planes are available.

The endpoint and underlay address families are independent, so cross-AF
policies are supported.

```yaml
global:
  pcep:
    address: "192.0.2.254"
    port: 4189
  grpcServer:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: true
    source: "gobgp"
    asn: 65000
  gobgp:
    grpcClient:
      address: "127.0.0.1"
      port: 50051
```

Configure GoBGP as follows to enable BGP-LS.

```yaml
global:
  config:
    as: 65000
    router-id: 10.255.0.254
neighbors:
- config:
    neighbor-address: 10.100.0.1
    peer-as: 65000
  transport:
    config:
      local-address: 10.100.0.254
  afi-safis:
  - config:
      afi-safi-name: ls
```

#### Known limitations

* **BGP-LS Multi-Topology ID (TLV 263)** is not exposed through GoBGP's
  Node/Link/Prefix NLRI API. Pola infers MT-0/MT-2 adjacency usability from the
  advertised interface address family.
* **SR Adjacency-SID**: At most one SR Adjacency-SID is available per link, so
  IPv4- and IPv6-specific SIDs cannot be distinguished on the same dual-stack link.
* **IOS-XR interoperability**: IPv6-endpoint PCE-initiated SR-MPLS policies were
  observed to be rejected locally by IOS-XR 24.4.1 (`pcinitiate: bad sock info`),
  even though the PCEP message is valid on the wire. Cross-AF behavior may vary
  by PCC implementation and version.

## Run Polad

Start polad. Specify the created configuration file with the `-f` option.

```bash
$ sudo polad -f polad.yaml
2022-06-05T22:57:59.823Z        info    gRPC listen     {"listenInfo": "127.0.0.1:50052", "server": "grpc"}
2022-06-05T22:57:59.823Z        info    PCEP listen     {"listenInfo": "192.0.2.254:4189"}
```

After Polad is running, use the [pola CLI](../../cmd/pola/README.md) or
[gRPC client](../../api/grpc/) to manage the daemon.
