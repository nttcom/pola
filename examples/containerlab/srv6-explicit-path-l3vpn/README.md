# SRv6 TE + VPNv4/VPNv6

Example topology powered by [Containerlab](https://containerlab.dev/)

![Topology](./topo.png)

## Requirements

* container host (Linux)
* Juniper vJunos-router image (`vrnetlab/juniper_vjunos-router:25.2R1.9`)
* Pola helper image (`ghcr.io/nttcom/pola:latest-debug`)
* Host utility image (`wbitt/network-multitool:latest`)

See [Prerequisites](../README.md#prerequisites) for how to install Containerlab and
prepare these images.

## Usage

### Building a Lab Network

Start Containerlab network

```bash
git clone https://github.com/nttcom/pola
cd pola/examples/containerlab/srv6-explicit-path-l3vpn

sudo containerlab deploy
```

Wait for vJunos-router startup after `sudo containerlab deploy` (it takes several minutes).

```bash
$ docker logs clab-srv6-explicit-path-l3vpn-p01 -f
<snip.>
2026-07-29 10:04:52,616: launch      INFO Startup complete in: 0:02:02.424893
```

### Apply SR Policy

Connect to PCEP container, check PCEP session and SR policy

```bash
$ docker exec -it clab-srv6-explicit-path-l3vpn-pola bash

root@pola:/pola# pola session
sessionAddr(0): fd00::2
  State: SESSION_STATE_UP
  Capabilities: [Stateful Update Instantiation Color SR-TE SRv6-TE Multipath Vendor-Info(Juniper)]
  IsSynced: true
sessionAddr(1): fd00::1
  State: SESSION_STATE_UP
  Capabilities: [Stateful Update Instantiation Color SR-TE SRv6-TE Multipath Vendor-Info(Juniper)]
  IsSynced: true

root@pola:/pola# pola sr-policy list
No SR Policies found.
```

Apply and check SR Policy

One explicit-path policy per PCC is mounted in the Pola container.

| File | PCC | Endpoint | Segment List |
| --- | --- | --- | --- |
| `pe01-policy1.yaml` | pe01 | `fd00:ffff:2:0:1::` | p01 -> p02 -> pe02 |
| `pe02-policy1.yaml` | pe02 | `fd00:ffff:1:0:1::` | p02 -> p01 -> pe01 |

End SIDs are `fd00:ffff:1:0:1::` (pe01), `fd00:ffff:2:0:1::` (pe02), `fd00:ffff:3:0:1::` (p01)
and `fd00:ffff:4:0:1::` (p02).

```bash
root@pola:/pola# pola sr-policy add -f pe01-policy1.yaml --no-sid-validate
warning: skipping SID validation (--no-sid-validate)
success!
root@pola:/pola# pola sr-policy add -f pe02-policy1.yaml --no-sid-validate
warning: skipping SID validation (--no-sid-validate)
success!
root@pola:/pola# pola sr-policy list
Session: fd00::2
  PolicyName: pe02-policy1
    SrcAddr: fd00:ffff::2
    DstAddr: fd00:ffff:1:0:1::
    Color: 1
    Preference: 100
    SegmentList: fd00:ffff:4:0:1:: -> fd00:ffff:3:0:1:: -> fd00:ffff:1:0:1::

Session: fd00::1
  PolicyName: pe01-policy1
    SrcAddr: fd00:ffff::1
    DstAddr: fd00:ffff:2:0:1::
    Color: 1
    Preference: 100
    SegmentList: fd00:ffff:3:0:1:: -> fd00:ffff:4:0:1:: -> fd00:ffff:2:0:1::
```

Enter container pe01 and check SR Policy

* user: admin
* pass: admin@123

```bash
root@pola:/pola# exit

$ ssh clab-srv6-explicit-path-l3vpn-pe01 -l admin

admin@pe01> show path-computation-client lsp

  Name                                Status            PLSP-Id  LSP-Type       Controller       Path-Setup-Type       Template
  pe01-policy1                        (Act)             1        ext-provised   POLA             srv6-te

admin@pe01> show spring-traffic-engineering lsp detail
E = Entropy-label Capability

Name: pe01-policy1
  Tunnel-source: Path computation element protocol(PCEP)
  Tunnel Forward Type: SRV6
  To: fd00:ffff:2:0:1::-1<c6>
  From: fd00:ffff::1
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
      SR-ERO hop count: 3
        Hop 1 (Strict):
          NAI: IPv6 Node ID, Node address: fd00:ffff::3
          SID type: srv6-sid, Value: fd00:ffff:3:0:1::
        Hop 2 (Strict):
          NAI: IPv6 Node ID, Node address: fd00:ffff::4
          SID type: srv6-sid, Value: fd00:ffff:4:0:1::
        Hop 3 (Strict):
          NAI: IPv6 Node ID, Node address: fd00:ffff::2
          SID type: srv6-sid, Value: fd00:ffff:2:0:1::


Total displayed LSPs: 1 (Up: 1, Down: 0, Initializing: 0)

admin@pe01> show route table CUST-A.inet.0 192.168.2.0/24

CUST-A.inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

192.168.2.0/24     *[BGP/170] 00:01:40, localpref 100, from fd00:ffff::2
                      AS path: I, validation-state: unverified
                    >  to fe80::aac1:abff:fea9:267e via ge-0/0/0.0, SRv6 SID: fd00:ffff:2:0:4:a::, SRV6-Tunnel, Dest: fd00:ffff:2:0:1::-1<c6>

admin@pe01> show route table CUST-A.inet6.0 fd00:a2::/64

CUST-A.inet6.0: 5 destinations, 5 routes (5 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

fd00:a2::/64       *[BGP/170] 00:02:07, localpref 100, from fd00:ffff::2
                      AS path: I, validation-state: unverified
                    >  to fe80::aac1:abff:fea9:267e via ge-0/0/0.0, SRv6 SID: fd00:ffff:2:0:6:a::, SRV6-Tunnel, Dest: fd00:ffff:2:0:1::-1<c6>
```

Enter container host01 and check SRv6-TE

* ping over VPN

```bash
admin@pe01> exit

$ docker exec -it clab-srv6-explicit-path-l3vpn-host01 /bin/bash

host01:/# ping -c 3 192.168.2.1
PING 192.168.2.1 (192.168.2.1) 56(84) bytes of data.
64 bytes from 192.168.2.1: icmp_seq=1 ttl=62 time=32.9 ms
64 bytes from 192.168.2.1: icmp_seq=2 ttl=62 time=3.05 ms
64 bytes from 192.168.2.1: icmp_seq=3 ttl=62 time=3.31 ms

host01:/# ping -c 3 fd00:a2::1
PING fd00:a2::1 (fd00:a2::1) 56 data bytes
64 bytes from fd00:a2::1: icmp_seq=1 ttl=62 time=895 ms
64 bytes from fd00:a2::1: icmp_seq=2 ttl=62 time=2.88 ms
64 bytes from fd00:a2::1: icmp_seq=3 ttl=62 time=2.68 ms
```

* Capture on containerlab host

The FRR container has no tcpdump, so run the host's tcpdump inside the container's
network namespace with `nsenter`:

```bash
$ sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' clab-srv6-explicit-path-l3vpn-pe01) -n tcpdump -nni eth1
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
10:06:29.445984 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: RT6 (len=6, type=4, segleft=2, last-entry=2, tag=0, [0]fd00:ffff:2:0:4:a::, [1]fd00:ffff:4:0:1::, [2]fd00:ffff:3:0:1::) IP 192.168.1.1 > 192.168.2.1: ICMP echo request, id 2207, seq 1, length 64
10:06:29.471892 IP6 fd00:ffff::2 > fd00:ffff:1:0:4:a::: RT6 (len=6, type=4, segleft=0, last-entry=2, tag=0, [0]fd00:ffff:1:0:4:a::, [1]fd00:ffff:3:0:1::, [2]fd00:ffff:4:0:1::) IP 192.168.2.1 > 192.168.1.1: ICMP echo reply, id 2207, seq 1, length 64
10:06:30.440747 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: RT6 (len=6, type=4, segleft=2, last-entry=2, tag=0, [0]fd00:ffff:2:0:4:a::, [1]fd00:ffff:4:0:1::, [2]fd00:ffff:3:0:1::) IP 192.168.1.1 > 192.168.2.1: ICMP echo request, id 2207, seq 2, length 64
10:06:30.442996 IP6 fd00:ffff::2 > fd00:ffff:1:0:4:a::: RT6 (len=6, type=4, segleft=0, last-entry=2, tag=0, [0]fd00:ffff:1:0:4:a::, [1]fd00:ffff:3:0:1::, [2]fd00:ffff:4:0:1::) IP 192.168.2.1 > 192.168.1.1: ICMP echo reply, id 2207, seq 2, length 64
10:06:31.441810 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: RT6 (len=6, type=4, segleft=2, last-entry=2, tag=0, [0]fd00:ffff:2:0:4:a::, [1]fd00:ffff:4:0:1::, [2]fd00:ffff:3:0:1::) IP 192.168.1.1 > 192.168.2.1: ICMP echo request, id 2207, seq 3, length 64
10:06:31.444281 IP6 fd00:ffff::2 > fd00:ffff:1:0:4:a::: RT6 (len=6, type=4, segleft=0, last-entry=2, tag=0, [0]fd00:ffff:1:0:4:a::, [1]fd00:ffff:3:0:1::, [2]fd00:ffff:4:0:1::) IP 192.168.2.1 > 192.168.1.1: ICMP echo reply, id 2207, seq 3, length 64
10:06:35.382665 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: RT6 (len=6, type=4, segleft=2, last-entry=2, tag=0, [0]fd00:ffff:2:0:6:a::, [1]fd00:ffff:4:0:1::, [2]fd00:ffff:3:0:1::) IP6 fd00:a1::1 > fd00:a2::1: ICMP6, echo request, id 2208, seq 1, length 64
10:06:36.275209 IP6 fd00:ffff::2 > fd00:ffff:1:0:6:a::: RT6 (len=6, type=4, segleft=0, last-entry=2, tag=0, [0]fd00:ffff:1:0:6:a::, [1]fd00:ffff:3:0:1::, [2]fd00:ffff:4:0:1::) IP6 fd00:a2::1 > fd00:a1::1: ICMP6, echo reply, id 2208, seq 1, length 64
10:06:36.380178 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: RT6 (len=6, type=4, segleft=2, last-entry=2, tag=0, [0]fd00:ffff:2:0:6:a::, [1]fd00:ffff:4:0:1::, [2]fd00:ffff:3:0:1::) IP6 fd00:a1::1 > fd00:a2::1: ICMP6, echo request, id 2208, seq 2, length 64
10:06:36.382145 IP6 fd00:ffff::2 > fd00:ffff:1:0:6:a::: RT6 (len=6, type=4, segleft=0, last-entry=2, tag=0, [0]fd00:ffff:1:0:6:a::, [1]fd00:ffff:3:0:1::, [2]fd00:ffff:4:0:1::) IP6 fd00:a2::1 > fd00:a1::1: ICMP6, echo reply, id 2208, seq 2, length 64
10:06:37.380982 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: RT6 (len=6, type=4, segleft=2, last-entry=2, tag=0, [0]fd00:ffff:2:0:6:a::, [1]fd00:ffff:4:0:1::, [2]fd00:ffff:3:0:1::) IP6 fd00:a1::1 > fd00:a2::1: ICMP6, echo request, id 2208, seq 3, length 64
10:06:37.383046 IP6 fd00:ffff::2 > fd00:ffff:1:0:6:a::: RT6 (len=6, type=4, segleft=0, last-entry=2, tag=0, [0]fd00:ffff:1:0:6:a::, [1]fd00:ffff:3:0:1::, [2]fd00:ffff:4:0:1::) IP6 fd00:a2::1 > fd00:a1::1: ICMP6, echo reply, id 2208, seq 3, length 64
```

Also, you can analyze with Wireshark on your Local PC
([ref: Packet capture & Wireshark](https://containerlab.dev/manual/wireshark/)).

```bash
ssh $clab_host 'sudo nsenter -t $(docker inspect -f "{{.State.Pid}}" clab-srv6-explicit-path-l3vpn-pe01) -n tcpdump -U -nni eth1 -w -' | wireshark -k -i -
```

### Cleanup

```bash
sudo containerlab destroy
```
