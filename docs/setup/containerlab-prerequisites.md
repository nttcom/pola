# Containerlab Setup Prerequisites

This guide covers the common prerequisites for running Containerlab topologies and scenario tests.

## Required Tools

### Docker

Make it executable without using sudo:

```bash
$ docker --version
Docker version 28.3.3, build 980b856
```

### Containerlab

Install Containerlab:

```bash
sudo bash -c "$(curl -sL https://get.containerlab.dev)"
```

Verify installation:

```bash
$ containerlab version
  ____ ___  _   _ _____  _    ___ _   _ _____ ____  _       _
 / ___/ _ \| \ | |_   _|/ \  |_ _| \ | | ____|  _ \| | __ _| |__
| |  | | | |  \| | | | / _ \  | ||  \| |  _| | |_) | |/ _` | '_ \
| |__| |_| | |\  | | |/ ___ \ | || |\  | |___|  _ <| | (_| | |_) |
 \____\___/|_| \_| |_/_/   \_\___|_| \_|_____|_| \_\_|\__,_|_.__/

    version: 0.69.3
     commit: 49ee599b
       date: 2025-08-06T21:02:24Z
     source: https://github.com/srl-labs/containerlab
 rel. notes: https://containerlab.dev/rn/0.69/#0693
```

### uv (Python package manager)

Required for scenario tests:

```bash
$ uv -V
uv 0.8.13
```

## Container Images

### Cisco XRd

Used by: `sr-mpls-isis`, `sr-mpls-isis-dual-stack`, `sr-mpls-ospf`, `srv6-isis`, `srv6-usid-isis`

#### 1. Configure sysctl on host

```bash
$ sudo vi /etc/sysctl.conf
```

Add or update the following parameters:

```
fs.inotify.max_user_instances=64000
fs.inotify.max_user_watches=64000
net.core.netdev_max_backlog=300000
net.core.optmem_max=67108864
net.core.rmem_default=67108864
net.core.rmem_max=67108864
net.core.wmem_default=67108864
net.core.wmem_max=67108864
net.ipv4.udp_mem=1124736 10000000 67108864
```

Apply changes:

```bash
$ sudo sysctl -p
```

#### 2. Run host-check

See: [Setting up the Host Environment to run XRd](https://xrdocs.io/virtual-routing/tutorials/2022-08-22-setting-up-host-environment-to-run-xrd/)

```bash
git clone https://github.com/ios-xr/xrd-tools
cd xrd-tools/scripts
./host-check --platform xrd-control-plane
```

#### 3. Load XRd container image

```bash
docker load -i <xrd-image>.tar.gz
```

Verify installation:

```bash
$ docker images --format '{{.Repository}}:{{.Tag}}' | grep '^ios-xr/xrd-control-plane:24.4.1$'
ios-xr/xrd-control-plane:24.4.1
```

### Juniper vJunos-router

Used by: All examples except `sr-mpls-explicit-path-l3vpn`

Scenario labs: `sr-mpls-isis`, `sr-mpls-isis-dual-stack`, `srv6-isis`, `srv6-usid-isis`

Install using [Vrnetlab](https://containerlab.dev/manual/vrnetlab/):

1. Get VM image from [Juniper support downloads page](https://support.juniper.net/support/downloads/)
2. Set up Vrnetlab:

```bash
$ sudo apt install make
$ git clone https://github.com/hellt/vrnetlab && cd vrnetlab/juniper/vjunosrouter
$ cp ~/vJunos-router-26.2R1.7.qcow2 .
$ sudo make

$ docker images
REPOSITORY            TAG         IMAGE ID       CREATED         SIZE
vrnetlab/juniper_vjunos-router:26.2R1.7   <IMAGE_ID>  <CREATED>  <SIZE>

$ sudo rm -rf vrnetlab
$ docker builder prune -a
```

Verify installation:

```bash
$ docker images --format '{{.Repository}}:{{.Tag}}' | grep '^vrnetlab/juniper_vjunos-router:26.2R1.7$'
vrnetlab/juniper_vjunos-router:26.2R1.7
```

### FRRouting

Used by: `sr-mpls-isis`, `sr-mpls-isis-dual-stack`, `sr-mpls-ospf`, `sr-mpls-explicit-path-l3vpn`

No image build is required; the image is pulled directly:

```bash
docker pull quay.io/frrouting/frr:10.7.1
```

### MPLS kernel modules

Required by: FRRouting nodes in `sr-mpls-explicit-path` and `sr-mpls-explicit-path-l3vpn`

```bash
sudo modprobe mpls_router
sudo modprobe mpls_gso
sudo modprobe mpls_iptunnel
```
