# SR-MPLS TE + VPNv4

Example topology powered by [Containerlab](https://containerlab.dev/)

![Topology](./topo.png)

## Requirements

* container host (Linux)
* Containerlab
* Docker image `ghcr.io/nttcom/pola:latest-dev`
* Docker image `frrouting/frr:v8.4.1`
* Docker image `wbitt/network-multitool:latest`

Image policy: the Pola helper tracks `latest-dev`, while generic utility hosts use `wbitt/network-multitool:latest`.

## Usage

### Install Containerlab

```bash
sudo bash -c "$(curl -sL https://get.containerlab.dev)"
```

### Building a Lab Network

Get topology file and start Containerlab network

The `switch` bridge node is created automatically by Containerlab.

```bash
git clone https://github.com/nttcom/pola
cd pola/examples/containerlab/sr-mpls-explicit-path-l3vpn

sudo containerlab deploy
docker ps
```

Connect to PCEP container, check PCEP session and SR policy

```bash
docker exec -it clab-sr-mpls-l3vpn-pola /bin/bash

# pola session
sessionAddr(0): 10.0.255.1
  State: SESSION_STATE_UP
  Capabilities: [Stateful Update Instantiation Color SR-TE]
  IsSynced: true
# pola sr-policy list
No SR Policies found.
```

### Apply SR Policy

Create `policy1.yaml` (Explicit SR Policy: Segment List 16002/16004/16003 to pe01)

```bash
# vi policy1.yaml
```

```yaml
srPolicy:
  pcepSessionAddr: "10.0.255.1"
  srcAddr: "10.255.0.1"
  dstAddr: "10.255.0.3"
  name: policy1
  color: 1
  segmentList:
    - sid: 16002
      nai: "10.255.0.2"
    - sid: 16004
      nai: "10.255.0.4"
    - sid: 16003
      nai: "10.255.0.3"
```

Apply and check SR Policy

```bash
# pola sr-policy add -f policy1.yaml --no-sid-validate
success!

# pola sr-policy list
LSP(0):
  PCEPSessionAddr: 10.0.255.1
  PolicyName: policy1
  SrcAddr: 10.0.255.1
  DstAddr: 10.255.0.3
  Color: 0
  Preference: 0
  DstAddr: 10.255.0.3
  SegmentList: 16002 -> 16004 -> 16003
```

Enter container pe01 and check SR Policy

```bash
# exit
docker exec -it clab-sr-mpls-l3vpn-pe01 /bin/bash
root@pe01:/# vtysh

Hello, this is FRRouting (version 8.4.1).
Copyright 1996-2005 Kunihiro Ishiguro, et al.

pe01# show sr-te pcep session

PCE POLA
 PCE IP 10.0.255.254 port 4189
 PCC IP 10.0.255.1 port 4189
 PCC MSD 4
 Session Status UP
<snip.>
PCEP Sessions => Configured 1 ; Connected 1

pe01# show sr-te policy detail

Endpoint: 10.255.0.3  Color: 1  Name: policy1  BSID: -  Status: Active
  * Preference: 255  Name: policy1  Type: dynamic  Segment-List: (created by PCE)  Protocol-Origin: PCEP
```

Add Color setting

```bash
docker exec -it clab-sr-mpls-l3vpn-pe01 /bin/bash
vtysh -c 'conf t' -c 'router bgp 65000' -c 'address-family ipv4 vpn' -c 'neighbor 10.255.0.3 route-map color1 in'
```

Check SR header with tcpdump

```bash
root@host01:/# ping 192.168.1.2
PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
64 bytes from 192.168.1.2: icmp_seq=1 ttl=62 time=0.152 ms
64 bytes from 192.168.1.2: icmp_seq=2 ttl=62 time=0.134 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=62 time=0.132 ms
64 bytes from 192.168.1.2: icmp_seq=4 ttl=62 time=0.161 ms
64 bytes from 192.168.1.2: icmp_seq=5 ttl=62 time=0.160 ms
^C
--- 192.168.1.2 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4090ms
rtt min/avg/max/mdev = 0.132/0.147/0.161/0.012 ms
```

```bash
root@p01:/# tcpdump -i eth1
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 262144 bytes
17:54:11.744846 MPLS (label 16004, exp 0, ttl 63) (label 16003, exp 0, ttl 63) (label 80, exp 0, [S], ttl 63) IP 192.168.0.2 > 192.168.1.2: ICMP echo request, id 43, seq 1, length 64
<snip.>
```

### Cleanup

```bash
sudo containerlab destroy
```
