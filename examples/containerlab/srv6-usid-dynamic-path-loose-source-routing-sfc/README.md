# SRv6 uSID Dynamic Path with Loose Source Routing SFC

Example topology powered by [Containerlab](https://containerlab.dev/)

![Topology](./topo.png)

## Requirements

* container host (Linux)
* Cisco XRd image (`ios-xr/xrd-control-plane:24.4.1`)
* Juniper vJunos-router image (`vrnetlab/juniper_vjunos-router:25.2R1.9`)
* Pola helper image (`ghcr.io/nttcom/pola:latest-debug`)
* Host utility image (`wbitt/network-multitool:latest`)
* Statically linked GoBGP binaries in `bin/` (`gobgpd`, `gobgp`, v4.0.0 or later)

See [Prerequisites](../README.md#prerequisites) for how to install Containerlab and
prepare these images.

## Usage

### Building a Lab Network

Copy the GoBGP binaries to `bin`:

```bash
git clone https://github.com/nttcom/pola
cd pola/examples/containerlab/srv6-usid-dynamic-path-loose-source-routing-sfc
make -C ../../.. fetch-gobgp
cp ../../../test/bin/gobgpd bin/gobgpd
cp ../../../test/bin/gobgp bin/gobgp
```

Pola and GoBGP start automatically when the lab is deployed.

Start Containerlab network

```bash
sudo containerlab deploy
```

Wait for vJunos-router startup after `sudo containerlab deploy` (it takes several minutes).

```bash
$ docker logs clab-srv6-usid-dynamic-path-loose-source-routing-sfc-pe02 -f
<snip.>
2026-08-25 06:32:12,048: launch     INFO Startup complete in: 0:01:48.144289
```

### Show TED

```bash
$ docker exec -it clab-srv6-usid-dynamic-path-loose-source-routing-sfc-pola bash

root@pola:/pola# pola ted -p 50052
Node #0: 0000.0001.0001
  Hostname: pe01
  ISIS Area ID: 49.0000
  SRGB: 0 - 0
  Prefixes:
    fcbb:bb00:1001::/48
    fd00:ffff::1/128
  Links:
    Local: None Remote: None
      RemoteRouterID: 0000.0001.0003
      Metrics:
        igp: 1
      Adj-SID: 0
      SRv6 End.X SID:
        EndpointBehavior: UA
        SIDs: [fcbb:bb00:1001:e000::]
        SID Structure: Block: 32, Node: 16, Func: 16, Arg: 64
    Local: None Remote: None
      RemoteRouterID: 0000.0001.0004
      Metrics:
        igp: 1
      Adj-SID: 0
      SRv6 End.X SID:
        EndpointBehavior: UA
        SIDs: [fcbb:bb00:1001:e001::]
        SID Structure: Block: 32, Node: 16, Func: 16, Arg: 64
  SRv6 SIDs:
    SIDs: [fcbb:bb00:1001::]
    Block: 32, Node: 16, Func: 0, Arg: 80
    EndpointBehavior: UN, Flags: 0, Algorithm: 0
    MultiTopoIDs: [2]

Node #1: 0000.0001.0002
<snip.>
```

### Apply SR Policy

Connect to PCEP container, check PCEP session and SR policy

```bash
root@pola:/pola# pola session -p 50052
Session #0: fd00::2
  State:             up
  LSP-DB Sync:       finished
  Role:              active-stateful-pce
  Up Time:           00:00:49
  Session ID:        Local=0, Peer=2
  Transport:         tcp, auth=none
  Timers:
               Local  Peer  Effective
    Keepalive  30     30    30
    DeadTimer  120    120   120
  Capabilities:
    Common:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update, Instantiation
      SR-PCE-CAPABILITY [RFC8664]: SR
      PATH-SETUP-TYPE-CAPABILITY [RFC8408]: SR-TE, SRv6-TE
      ASSOC-TYPE-LIST [RFC8697]:
        6 SR Policy Association
    Local only:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Color
      SR-PCE-CAPABILITY [RFC8664]: Unlimited-SID-Depth
      SRv6-PCE-CAPABILITY [RFC9603]: SRv6
    Peer only:
      VENDOR-INFORMATION [RFC7470]: 2636 (Juniper Networks, Inc.)
      SR-PCE-CAPABILITY [RFC8664]: MSD=0
      ASSOC-TYPE-LIST [RFC8697]:
        1 Path Protection Association
      MULTIPATH-CAP [draft-ietf-pce-multipath]: Multipath, MaxMultipaths=128, Weighted
root@pola:/pola# pola sr-policy list -p 50052
Session: fd00::2 (State: up, LSP-DB Sync: finished)
  No SR Policies.
```

### Applying SR Policies

The Pola container includes `pe02-policy1.yaml`. It requests a dynamic path from pe02 to
pe01 (`fd00:ffff::1`) with color 100 and lists p01, p02 and p01 again as waypoints. End SIDs are
`fcbb:bb00:1001::` (pe01), `fcbb:bb00:1003::` (p01) and `fcbb:bb00:1004::` (p02), so p01 is
visited twice in the segment list below.

```bash
root@pola:/pola# pola sr-policy add -f pe02-policy1.yaml -p 50052
success!
root@pola:/pola# pola sr-policy list -p 50052
Session: fd00::2 (State: up, LSP-DB Sync: finished)
  PolicyName: DYNAMIC-POLICY
    PlspID: 1
    LSPID: 0
    State: active
    Type: dynamic
    Metric: igp
    SrcAddr: fd00:ffff::2 (0000.0001.0002)
    DstAddr: fd00:ffff::1 (0000.0001.0001)
    Color: 100
    Preference: 100
    SegmentList: fcbb:bb00:1003:: (local=fcbb:bb00:1003::) -> fcbb:bb00:1004:: (local=fcbb:bb00:1004::) -> fcbb:bb00:1003:: (local=fcbb:bb00:1003::) -> fcbb:bb00:1001:: (local=fcbb:bb00:1001::)
```

Enter container pe02 and check SR Policy

* user: admin
* pass: admin@123

```bash
root@pola:/pola# exit

$ ssh clab-srv6-usid-dynamic-path-loose-source-routing-sfc-pe02 -l admin

admin@pe02> show spring-traffic-engineering lsp brief
To                        State        LSPname
fd00:ffff::1-100<c6>      Up           DYNAMIC-POLICY


Total displayed LSPs: 1 (Up: 1, Down: 0, Initializing: 0)

admin@pe02> show spring-traffic-engineering lsp name DYNAMIC-POLICY detail
E = Entropy-label Capability

Name: DYNAMIC-POLICY
  Tunnel-source: Path computation element protocol(PCEP)
  Tunnel Forward Type: SRV6
  To: fd00:ffff::1-100<c6>
  From: fd00:ffff::2
  State: Up
    Path Status: NA
    Outgoing interface: NA
    Delegation compute constraints info:
      Actual-Bandwidth from PCUpdate: 0
      Bandwidth-Requested from PCUpdate: 0
      Setup-Priority: 0
      Reservation-Priority: 0
    Auto-translate status: Disabled Auto-translate result: N/A
    BFD status: N/A BFD name: N/A
    BFD remote-discriminator: N/A
    Segment ID : 128
    ERO Valid: true
      SR-ERO hop count: 4
        Hop 1 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1003::
          SID type: Micro SRv6 SID, Value: fcbb:bb00:1003::
          SSTLV: BL: 32, NL: 16, FL: 0, AL: 80
          Endpoint Behavior: End with NEXT-CSID, PSP & USD
        Hop 2 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1004::
          SID type: Micro SRv6 SID, Value: fcbb:bb00:1004::
          SSTLV: BL: 32, NL: 16, FL: 0, AL: 80
          Endpoint Behavior: End with NEXT-CSID, PSP & USD
        Hop 3 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1003::
          SID type: Micro SRv6 SID, Value: fcbb:bb00:1003::
          SSTLV: BL: 32, NL: 16, FL: 0, AL: 80
          Endpoint Behavior: End with NEXT-CSID, PSP & USD
        Hop 4 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1001::
          SID type: Micro SRv6 SID, Value: fcbb:bb00:1001::
          SSTLV: BL: 32, NL: 16, FL: 0, AL: 80
          Endpoint Behavior: End with NEXT-CSID, PSP & USD


Total displayed LSPs: 1 (Up: 1, Down: 0, Initializing: 0)
```

### Cleanup

```bash
sudo containerlab destroy
```
