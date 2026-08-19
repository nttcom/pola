# Getting Started with Pola PCE

This page explains how to use Pola PCE.

## Installation

### From Go Package

```bash
go install github.com/nttcom/pola/cmd/polad@latest
```

### From Source

#### Getting the Source

```bash
git clone https://github.com/nttcom/pola.git
```

#### Build & install

```bash
$ cd pola
$ go install ./cmd/polad

# or, install with cli command
$ go install ./...
```

### From Container Image

See the [Docker page](../../build/package/README.md).

## Configuration

Specify the IP address and port number for each PCEP and gRPC.
`address` must be a literal IPv4 or IPv6 address; hostnames are not resolved.
See [JSON schema](../schemas/server/polad_config.json) for config details.

### TED disable

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

`global.pcep.keepalive` and `global.pcep.deadTimer` configure the values Pola
advertises in its Open message (RFC 5440 §7.3). If omitted, they default to a
30-second Keepalive and a DeadTimer of four times the Keepalive.

`keepalive` is the maximum interval between PCEP messages sent by Pola.
`deadTimer` is the silence after which the PCC may declare Pola down. If
`keepalive` is `0`, `deadTimer` must also be `0`.

```yaml
global:
  pcep:
    address: "192.0.2.254"
    port: 4189
    keepalive: 30
    deadTimer: 120
```

Note that these values apply to Pola's own transmissions only. The interval Pola
waits before declaring a PCC down comes from the DeadTimer that PCC advertised.

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

### TED enable

To manage SR Policy using TED, enable TED as follows.
This also enables dynamic path calculation.

A specific tool for updating TED is required to use this feature.
Currently, only GoBGP is supported.

**Not currently available for IPv6 underlay (IPv6 SR-MPLS / SRv6).**

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

## Run Pola PCE using polad

Start polad. Specify the created configuration file with the -f option.

```bash
$ sudo polad -f polad.yaml
2022-06-05T22:57:59.823Z        info    gRPC listen     {"listenInfo": "127.0.0.1:50052", "server": "grpc"}
2022-06-05T22:57:59.823Z        info    PCEP listen     {"listenInfo": "192.0.2.254:4189"}
```

After Polad is running, use [pola cmd](../../cmd/pola/README.md) or the
[gRPC client](../../api/grpc/) for daemon operations
