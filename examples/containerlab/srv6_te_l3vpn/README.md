# SRv6 TE + VPNv4/VPNv6

Example topology powered by [Containerlab](https://containerlab.dev/)

![](./topo.png)

## Requirements
* container host (Linux)
* Juniper vMX image

## Usage

### Install Containerlab & Juniper vMX
[Install Containerlab](https://containerlab.dev/install/)
```bash
$ sudo bash -c "$(curl -sL https://get.containerlab.dev)"
```

Install Juniper vMX on [Vrnetlab](https://containerlab.dev/manual/vrnetlab/)
```bash
$ sudo apt install make
$ git clone https://github.com/hellt/vrnetlab && cd vrnetlab/vmx
$ cp ~/vmx-bundle-22.4R1.10.tgz .
$ sudo make
^Cmake[1]: *** [../makefile-install.include:39: docker-build] Interrupt
make: *** [../makefile.include:9: docker-image] Interrupt

$ sudo docker images                                       
REPOSITORY            TAG         IMAGE ID       CREATED         SIZE
vrnetlab/vr-vmx       22.4R1.10   6d2704750cd7   3 minutes ago   10.8GB

$ sudo rm -rf vrnetlab
$ sudo docker builder prune -a
```

### Building a Lab Network
Create bridge
```bash
$ sudo ip link add switch type bridge
$ sudo ip link set dev switch up
```

Start Containerlab network
```bash
$ git clone https://github.com/nttcom/pola
$ cd pola/examples/containerlab/srv6_te_l3vpn

$ sudo containerlab deploy
```

Wait for starting vMX after execute `sudo containerlab deploy` (it takes some time).
```bash
$ docker logs clab-srv6_te_l3vpn-pe01 -f
<snip.>
2023-02-20 15:03:26,233: launch     INFO     Startup complete in: 0:09:06.969773
```

### Apply SR Policy
Connect to PCEP container, check PCEP session and SR policy
```bash
$ sudo docker exec -it clab-srv6_te_l3vpn-pola-pce bash

# polad -f polad.yaml  > /dev/null 2>&1 & 

# pola session
sessionAddr(0): fd00::1
sessionAddr(1): fd00::2

# pola sr-policy list
no SR Policies
```

Apply and check SR Policy
```bash
# pola sr-policy add -f pe01-policy1.yaml --no-link-state
success!
# pola sr-policy add -f pe02-policy1.yaml --no-link-state
success!

# pola sr-policy list
Session: fd00::1
  PolicyName: pe01-policy1
    SrcAddr: fd00:ffff::1
    DstAddr: fd00:ffff:2:0:1::
    Color: 1
    Preference: 100
    SegmentList: fd00:ffff:3:0:1:: -> fd00:ffff:4:0:1::

Session: fd00::2
  PolicyName: pe02-policy1
    SrcAddr: fd00:ffff::2
    DstAddr: fd00:ffff:1:0:1::
    Color: 1
    Preference: 100
    SegmentList: fd00:ffff:3:0:1:: -> fd00:ffff:1:0:1::
```

Enter container pe01 and check SR Policy
* user: admin
* pass: admin@123
```bash
# exit
$ ssh clab-srv6_te_l3vpn-pe01 -l admin

admin@pe01> show path-computation-client lsp

  Name                                Status            PLSP-Id  LSP-Type       Controller       Path-Setup-Type       Template
  pe01-policy1                        (Act)             1        ext-provised   POLA-PCE         srv6-te

admin@pe01> show spring-traffic-engineering lsp detail
Name: pe01-policy1
  Tunnel-source: Path computation element protocol(PCEP)
  Tunnel Forward Type: SRV6
  To: fd00:ffff:2:0:1::-1<c6>
  From: fd00:ffff::1
  State: Up
    Path Status: NA
    Outgoing interface: NA
    Auto-translate status: Disabled Auto-translate result: N/A
    BFD status: N/A BFD name: N/A
    BFD remote-discriminator: N/A
    Segment ID : 129
    ERO Valid: false
      SR-ERO hop count: 2
        Hop 1 (Strict):
          NAI: None
          SID type: srv6-sid, Value: fd00:ffff:3:0:1::
        Hop 2 (Strict):
          NAI: None
          SID type: srv6-sid, Value: fd00:ffff:4:0:1::

admin@pe01> show route table CUST-A.inet.0 192.168.2.0/24

CUST-A.inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

192.168.2.0/24     *[BGP/170] 00:32:05, localpref 100, from fd00:ffff::2
                      AS path: I, validation-state: unverified
                    >  to fe80::5254:ff:feac:7101 via ge-0/0/0.0, SRV6-Tunnel, Dest: fd00:ffff:2:0:1::-1<c6>

admin@pe01> show route table CUST-A.inet6.0 fd00:a2::/64

CUST-A.inet6.0: 5 destinations, 5 routes (5 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

fd00:a2::/64       *[BGP/170] 00:32:08, localpref 100, from fd00:ffff::2
                      AS path: I, validation-state: unverified
                    >  to fe80::5254:ff:feac:7101 via ge-0/0/0.0, SRV6-Tunnel, Dest: fd00:ffff:2:0:1::-1<c6>
```

Enter container host01 and check SRv6-TE

* ping over VPN
```bash
admin@pe01> exit

$ docker exec -it  clab-srv6_te_l3vpn-host01 /bin/bash

bash-5.1# ping 192.168.2.1
PING 192.168.2.1 (192.168.2.1) 56(84) bytes of data.
64 bytes from 192.168.2.1: icmp_seq=1 ttl=62 time=3.05 ms
64 bytes from 192.168.2.1: icmp_seq=2 ttl=62 time=2.57 ms
64 bytes from 192.168.2.1: icmp_seq=3 ttl=62 time=2.70 ms

bash-5.1# ping fd00:a2::1
PING fd00:a2::1(fd00:a2::1) 56 data bytes
64 bytes from fd00:a2::1: icmp_seq=1 ttl=62 time=2.83 ms
64 bytes from fd00:a2::1: icmp_seq=2 ttl=62 time=2.63 ms
64 bytes from fd00:a2::1: icmp_seq=3 ttl=62 time=2.94 ms
```

* Capture on containerlab host
```bash
$ sudo ip netns exec clab-srv6_te_l3vpn-pe01 tcpdump -nni eth1
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 262144 bytes
^C01:05:32.064070 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: srcrt (len=4, type=4, segleft=1[|srcrt]
01:05:32.066018 IP6 fd00:ffff::2 > fd00:ffff:1:0:4:a::: srcrt (len=4, type=4, segleft=0[|srcrt]
01:05:33.064501 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: srcrt (len=4, type=4, segleft=1[|srcrt]
01:05:33.066597 IP6 fd00:ffff::2 > fd00:ffff:1:0:4:a::: srcrt (len=4, type=4, segleft=0[|srcrt]
01:05:34.065873 IP6 fd00:ffff::1 > fd00:ffff:3:0:1::: srcrt (len=4, type=4, segleft=1[|srcrt]
01:05:34.067531 IP6 fd00:ffff::2 > fd00:ffff:1:0:4:a::: srcrt (len=4, type=4, segleft=0[|srcrt]
```

Also, you can analyze with Wireshark on your Local PC ([ref: Packet capture & Wireshark](https://containerlab.dev/manual/wireshark/)).

```bash
ssh $clab_host "sudo -S ip netns exec clab-srv6_te_l3vpn-pe01 tcpdump -U -nni eth1 -w -"  | wireshark -k -i -
```
