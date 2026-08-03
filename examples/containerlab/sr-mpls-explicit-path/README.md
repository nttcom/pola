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
git clone https://github.com/nttcom/pola
cd pola/examples/containerlab/sr-mpls-explicit-path
sudo containerlab deploy
```

Wait for vJunos-router startup after `sudo containerlab deploy` (it takes several minutes).

```bash
$ docker logs clab-sr-mpls-explicit-path-pe02 -f
<snip.>
2026-07-30 09:58:26,934: launch      INFO Startup complete in: 0:01:44.162598
```

### Apply SR Policy

Connect to PCEP container, check PCEP session and SR policy

```bash
$ docker exec -it clab-sr-mpls-explicit-path-pola bash

root@pola:/pola# pola session
sessionAddr(0): 10.0.255.3
  State: SESSION_STATE_UP
  Capabilities: [Stateful Update Instantiation Color SR-TE]
  IsSynced: true
sessionAddr(1): 10.0.255.1
  State: SESSION_STATE_UP
  Capabilities: [Stateful Update Instantiation Color SRv6 SR-TE SRv6-TE SR-P2MP-POLICY-CAPABILITY]
  IsSynced: true
sessionAddr(2): 10.0.255.2
  State: SESSION_STATE_UP
  Capabilities: [Stateful Update Instantiation Color SR-TE Multipath Vendor-Info(Juniper)]
  IsSynced: true

root@pola:/pola# pola sr-policy list
No SR Policies found.
```

Apply and check SR Policy

One explicit-path policy per PCC is mounted in the Pola container.

| File | PCC | Endpoint | Segment List |
| --- | --- | --- | --- |
| `pe01-policy1.yaml` | pe01 (XRd) | 10.255.0.2 | 16002 -> 16003 |
| `pe02-policy1.yaml` | pe02 (vJunos-router) | 10.255.0.1 | 16001 -> 16003 |
| `pe03-policy1.yaml` | pe03 (FRRouting) | 10.255.0.1 | 16001 -> 16002 |

Prefix-SID labels are 16001 (pe01), 16002 (pe02) and 16003 (pe03).

```bash
root@pola:/pola# pola sr-policy add -f pe01-policy1.yaml --no-sid-validate
success!
root@pola:/pola# pola sr-policy add -f pe02-policy1.yaml --no-sid-validate
success!
root@pola:/pola# pola sr-policy add -f pe03-policy1.yaml --no-sid-validate
success!

root@pola:/pola# pola sr-policy list
Session: 10.0.255.1
  PolicyName: pe01-policy1
    SrcAddr: 10.255.0.1
    DstAddr: 10.255.0.2
    Color: 1
    Preference: 100
    SegmentList: 16002 -> 16003

Session: 10.0.255.2
  PolicyName: pe02-policy1
    SrcAddr: 10.255.0.2
    DstAddr: 10.255.0.1
    Color: 1
    Preference: 100
    SegmentList: 16001 -> 16003

Session: 10.0.255.3
  PolicyName: pe03-policy1
    SrcAddr: 10.0.255.3
    DstAddr: 10.255.0.1
    Color: 0
    Preference: 0
    SegmentList: 16001 -> 16002
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
RP/0/RP0/CPU0:pe01# show segment-routing traffic-eng policy
Thu Jul 30 10:00:36.288 UTC

SR-TE policy database
---------------------

Color: 1, End-point: 10.255.0.2
  Name: srte_c_1_ep_10.255.0.2
  Status:
    Admin: up  Operational: up for 00:00:36 (since Jul 30 09:59:59.913)
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
          SID[0]: 16002
          SID[1]: 16003
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
