# SR-MPLS + PCEP (IOS-XR/Junos/FRRouting)

Example topology powered by [Containerlab](https://containerlab.dev/)

![Topology](./topo.png)

## Requirements

* container host (Linux)
* Cisco XRd image (`ios-xr/xrd-control-plane:24.4.1`)
* Juniper vJunos-router image (`vrnetlab/juniper_vjunos-router:25.2R1.9`)
* FRRouting image (`frrouting/frr:v8.4.1`)
* MPLS kernel modules on the container host (`mpls_router`, `mpls_gso`, `mpls_iptunnel`)
* Pola helper image (`ghcr.io/nttcom/pola:latest-debug`)
* Host utility image (`wbitt/network-multitool:latest`)

See [Prerequisites](../README.md#prerequisites) for how to install Containerlab and
prepare these images.

## Usage

### Building a Lab Network

Start Containerlab network

```bash
cd pola/examples/containerlab/sr-mpls-explicit-path
sudo containerlab deploy
```

Wait for vJunos-router startup after `sudo containerlab deploy` (it takes several minutes).

```bash
$ docker logs clab-sr-mpls-explicit-path-pe02 -f
<snip.>
2026-08-25 05:58:19,052: launch     INFO Startup complete in: 0:01:44.709074
```

### Apply SR Policy

Connect to PCEP container, check PCEP session and SR policy

```bash
$ docker exec -it clab-sr-mpls-explicit-path-pola bash

root@pola:/pola# pola session
Session #0: 10.0.255.1
  State:             up
  LSP-DB Sync:       finished
  Role:              active-stateful-pce
  Up Time:           00:02:13
  Session ID:        Local=0, Peer=1
  Transport:         tcp, auth=none
  Timers:
               Local  Peer  Effective
    Keepalive  30     30    30
    DeadTimer  120    120   120
  Capabilities:
    Common:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update, Instantiation
      SR-PCE-CAPABILITY [RFC8664]: SR, MSD=0
      SRv6-PCE-CAPABILITY [RFC9603]: SRv6
      PATH-SETUP-TYPE-CAPABILITY [RFC8408]: SR-TE, SRv6-TE
      ASSOC-TYPE-LIST [RFC8697]:
        2 Disjoint Association
        3 Policy Association
        5 Double Sided Bidirectional LSP Association
        6 SR Policy Association
        9 P2MP SR Policy Association (draft)
      Unrecognized TLVs:
        type=73: SR-P2MP-POLICY-CAPABILITY (draft-ietf-pce-sr-p2mp-policy-11)
    Local only:
      color
    Peer only:
      -

Session #1: 10.0.255.2
  State:             up
  LSP-DB Sync:       finished
  Role:              active-stateful-pce
  Up Time:           00:00:12
  Session ID:        Local=0, Peer=1
  Transport:         tcp, auth=none
  Timers:
               Local  Peer  Effective
    Keepalive  30     30    30
    DeadTimer  120    120   120
  Capabilities:
    Common:
      VENDOR-INFORMATION [RFC7470]: 2636 (Juniper Networks, Inc.)
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update, Instantiation
      SR-PCE-CAPABILITY [RFC8664]: SR, MSD=0
      PATH-SETUP-TYPE-CAPABILITY [RFC8408]: SR-TE
      ASSOC-TYPE-LIST [RFC8697]:
        1 Path Protection Association
        6 SR Policy Association
      MULTIPATH-CAP [draft-ietf-pce-multipath]: Multipath, MaxMultipaths=128, Weighted
    Local only:
      color
    Peer only:
      -

Session #2: 10.0.255.3
  State:             up
  LSP-DB Sync:       finished
  Role:              active-stateful-pce
  Up Time:           00:02:38
  Session ID:        Local=0, Peer=2
  Transport:         tcp, auth=none
  Timers:
               Local  Peer  Effective
    Keepalive  30     30    30
    DeadTimer  120    120   120
  Capabilities:
    Common:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update, Instantiation
      PATH-SETUP-TYPE-CAPABILITY [RFC8408]: SR-TE
    Local only:
      color
    Peer only:
      -
root@pola:/pola# pola sr-policy list
Session: 10.0.255.1 (State: up, LSP-DB Sync: finished)
  No SR Policies.

Session: 10.0.255.2 (State: up, LSP-DB Sync: finished)
  No SR Policies.

Session: 10.0.255.3 (State: up, LSP-DB Sync: finished)
  No SR Policies.
```

### Applying SR Policies

The Pola container includes one explicit-path policy for each PCC.

| File | PCC | Endpoint | Segment List |
| --- | --- | --- | --- |
| `pe01-policy1.yaml` | pe01 (XRd) | 10.255.0.2 | 16002 -> 16003 |
| `pe02-policy1.yaml` | pe02 (vJunos-router) | 10.255.0.1 | 16001 -> 16003 |
| `pe03-policy1.yaml` | pe03 (FRRouting) | 10.255.0.1 | 16001 -> 16002 |

Prefix-SID labels are 16001 (pe01), 16002 (pe02) and 16003 (pe03).

```bash
root@pola:/pola# pola sr-policy add -f pe01-policy1.yaml --no-sid-validate
warning: skipping SID validation (--no-sid-validate)
success!
root@pola:/pola# pola sr-policy add -f pe02-policy1.yaml --no-sid-validate
warning: skipping SID validation (--no-sid-validate)
success!
root@pola:/pola# pola sr-policy add -f pe03-policy1.yaml --no-sid-validate
warning: skipping SID validation (--no-sid-validate)
success!
root@pola:/pola# pola sr-policy list
Session: 10.0.255.1 (State: up, LSP-DB Sync: finished)
  PolicyName: pe01-policy1
    PlspID: 1
    LSPID: 2
    State: active
    Type: explicit
    SrcAddr: 10.255.0.1
    DstAddr: 10.255.0.2
    Color: 1
    Preference: 100
    SegmentList: 16002 (local=10.255.0.2) -> 16003 (local=10.255.0.3)

Session: 10.0.255.2 (State: up, LSP-DB Sync: finished)
  PolicyName: pe02-policy1
    PlspID: 1
    LSPID: 0
    State: active
    Type: explicit
    SrcAddr: 10.255.0.2
    DstAddr: 10.255.0.1
    Color: 1
    Preference: 100
    SegmentList: 16001 (local=10.255.0.1) -> 16003 (local=10.255.0.3)

Session: 10.0.255.3 (State: up, LSP-DB Sync: finished)
  PolicyName: pe03-policy1
    PlspID: 1
    LSPID: 0
    State: active
    Type: explicit
    SrcAddr: 10.0.255.3
    DstAddr: 10.255.0.1
    Color: 0
    Preference: 0
    SegmentList: 16001 (local=10.255.0.1) -> 16002 (local=10.255.0.2)
```

FRRouting does not report the color, the preference and the source address of an SR Policy back to
the PCE, so those fields of `pe03-policy1` differ from the applied policy. The applied color is
visible on pe03 itself with `show sr-te policy detail`.

Enter each PCC and check the installed SR Policy

* user: admin
* pass: admin@123

```bash
root@pola:/pola# exit

$ ssh clab-sr-mpls-explicit-path-pe01 -l admin

RP/0/RP0/CPU0:pe01#show segment-routing traffic-eng policy
Tue Aug 25 06:01:32.210 UTC

SR-TE policy database
---------------------

Color: 1, End-point: 10.255.0.2
  Name: srte_c_1_ep_10.255.0.2
  Status:
    Admin: up  Operational: up for 00:01:07 (since Aug 25 06:00:24.733)
  Candidate-paths:
    Preference: 100 (PCEP) (active)
      Name: pe01-policy1
      Requested BSID: dynamic
      PCC info:
        Symbolic name: pe01-policy1
        PLSP-ID: 1
      Constraints:
        Protection Type: unprotected-preferred
        Maximum SID Depth: 10
      Dynamic (pce 10.0.255.254) (valid)
        Metric Type: TE,   Path Accumulated Metric: 0
          SID[0]: 16002 [Prefix-SID, 10.255.0.2]
          SID[1]: 16003 [Prefix-SID, 10.255.0.3]
  Attributes:
    Binding SID: 24003
    Forward Class: Not Configured
    Steering labeled-services disabled: no
    Steering BGP disabled: no
    IPv6 caps enable: yes
    Invalidation drop enabled: no
    Max Install Standby Candidate Paths: 0
    Path Type: SRMPLSv4
```

```bash
$ ssh clab-sr-mpls-explicit-path-pe02 -l admin

admin@pe02> show spring-traffic-engineering lsp detail
E = Entropy-label Capability

Name: pe02-policy1
  Tunnel-source: Path computation element protocol(PCEP)
  Tunnel Forward Type: SRMPLS
  To: 10.255.0.1-1<c>
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
      SR-ERO hop count: 2
        Hop 1 (Strict):
          NAI: IPv4 Node ID, Node address: 10.255.0.1
          SID type: 20-bit label, Value: 16001
        Hop 2 (Strict):
          NAI: IPv4 Node ID, Node address: 10.255.0.3
          SID type: 20-bit label, Value: 16003


Total displayed LSPs: 1 (Up: 1, Down: 0, Initializing: 0)
```

```bash
$ docker exec -it clab-sr-mpls-explicit-path-pe03 vtysh

pe03# show sr-te policy detail

Endpoint: 10.255.0.1  Color: 1  Name: pe03-policy1  BSID: -  Status: Active
  * Preference: 255  Name: pe03-policy1  Type: dynamic  Segment-List: (created by PCE)  Protocol-Origin: PCEP
```

### Cleanup

```bash
sudo containerlab destroy
```
