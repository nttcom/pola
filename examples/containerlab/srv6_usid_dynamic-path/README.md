# SRv6 uSID Dynamic Path

Example topology powered by [Containerlab](https://containerlab.dev/)

![Topology](./topo.png)

## Requirements

* container host (Linux)
* vJunos image

## Usage

### Install Containerlab & vJunos-router

[Install Containerlab](https://containerlab.dev/install/)

```bash
sudo bash -c "$(curl -sL https://get.containerlab.dev)"
```

Install vJunos on [Vrnetlab](https://containerlab.dev/manual/vrnetlab/)

### Building a Lab Network

Create bridge

```bash
sudo ip link add switch type bridge
sudo ip link set dev switch up
```

Copy Pola PCE & GoBGP to bin

* GoBGP: Use [this version](https://github.com/k1yoto/gobgp/tree/feature/bgp-ls-srv6)
* Pola PCE: Replace the GoBGP module in go.mod with your local GoBGP version, e.g.:

```text
replace github.com/osrg/gobgp/v4 => ../gobgp
```

Start Containerlab network

```bash
git clone https://github.com/nttcom/pola
cd pola/examples/containerlab/srv6_usid_dynamic-path

sudo containerlab deploy
```

### Starting Daemons

```bash
$ sudo docker exec -it clab-dynamic-path-gobgp bash
# gobgpd -f /gobgpd.yml
```

```bash
$ sudo docker exec -it clab-dynamic-path-pola bash
# polad -f /polad.yaml
```

### Show TED

```bash
$ sudo docker exec -it clab-dynamic-path-pola bash
# pola -p 50052 ted 
```

### Apply SR Policy

Connect to PCEP container, check PCEP session and SR policy

```bash
$ sudo docker exec -it clab-dynamic-path-pola bash

# pola session -p 50052
sessionAddr(0): fd00::2

# pola sr-policy list -p 50052
No SR Policies found.
```

Apply and check SR Policy

```bash
# pola sr-policy add -f /pe02-policy1.yaml -p 50052
success!

# pola sr-policy list -p 50052
Session: fd00::2
  PolicyName: DYNAMIC-POLICY
    SrcAddr: fd00:ffff::2
    DstAddr: fd00:ffff::1
    Color: 100
    Preference: 0
    SegmentList: fcbb:bb00:1004:: -> fcbb:bb00:1003:: -> fcbb:bb00:1001::
```

Enter container pe02 and check SR Policy

* user: admin
* pass: admin@123

```text
$ ssh clab-dynamic-path-pe02 -l admin

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
    Segment ID : 129
    ERO Valid: true
      SR-ERO hop count: 3
        Hop 1 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1004::
          SID type: srv6-sid, Value: fcbb:bb00:1004::
        Hop 2 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1003::
          SID type: srv6-sid, Value: fcbb:bb00:1003::
        Hop 3 (Strict):
          NAI: IPv6 Node ID, Node address: fcbb:bb00:1001::
          SID type: srv6-sid, Value: fcbb:bb00:1001::


Total displayed LSPs: 1 (Up: 1, Down: 0, Initializing: 0)
```
