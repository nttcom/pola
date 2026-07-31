# Containerlab Examples

This directory contains the supported example labs for Pola.

## Prerequisites

The host setup is common to all examples. Example-specific requirements are listed in each `Requirements` section.

### Containerlab

[Install Containerlab](https://containerlab.dev/install/)

```bash
sudo bash -c "$(curl -sL https://get.containerlab.dev)"
```

### Cisco XRd

Used by `sr-mpls-explicit-path`, `srv6-usid-dynamic-path` and
`srv6-usid-dynamic-path-loose-source-routing-sfc`.

Configure sysctl on host

```bash
$ vi /etc/sysctl.conf
fs.inotify.max_user_instances=64000
fs.inotify.max_user_watches=64000
net.core.netdev_max_backlog=300000
net.core.optmem_max=67108864
net.core.rmem_default=67108864
net.core.rmem_max=67108864
net.core.wmem_default=67108864
net.core.wmem_max=67108864
net.ipv4.udp_mem=1124736 10000000 67108864
$ sysctl -p
```

host-check (see: [Setting up the Host Environment to run XRd](https://xrdocs.io/virtual-routing/tutorials/2022-08-22-setting-up-host-environment-to-run-xrd/))

```bash
git clone https://github.com/ios-xr/xrd-tools
cd xrd-tools/scripts
./host-check --platform xrd-control-plane
```

Load XRd container image

```bash
docker load -i <xrd>.tar.gz
```

### Juniper vJunos-router

Used by every example except `sr-mpls-explicit-path-l3vpn`.

Install Juniper vJunos-router using [Vrnetlab](https://containerlab.dev/manual/vrnetlab/)

```bash
$ sudo apt install make
$ git clone https://github.com/hellt/vrnetlab && cd vrnetlab/vjunos-router
$ cp ~/vjunos-router-25.2R1.9.qcow2 .
$ sudo make
^Cmake[1]: *** [../makefile-install.include:39: docker-build] Interrupt
make: *** [../makefile.include:9: docker-image] Interrupt

$ docker images
REPOSITORY            TAG         IMAGE ID       CREATED         SIZE
vrnetlab/juniper_vjunos-router:25.2R1.9   <IMAGE_ID>  <CREATED>  <SIZE>

$ sudo rm -rf vrnetlab
$ docker builder prune -a
```

### MPLS kernel modules

Used by the FRRouting nodes of `sr-mpls-explicit-path` and `sr-mpls-explicit-path-l3vpn`.

```bash
sudo modprobe mpls_router
sudo modprobe mpls_gso
sudo modprobe mpls_iptunnel
```

## Conventions

* Topology files use `topo.clab.yml`.
* The Pola helper node is named `pola` across all examples.
* Daemons are expected to start automatically unless a README explicitly says otherwise.
* The `switch` node is a `wbitt/network-multitool:latest` container that runs a Linux bridge, providing a private Layer 2 segment for each topology without using the host network namespace.

## Image Tag Policy

* Router and network OS images are pinned to tested versions.
* The Pola helper uses `ghcr.io/nttcom/pola:latest-debug` because the topologies run `ip` in `exec` blocks and expect a shell for troubleshooting, which the slim `latest` image does not provide.
* Generic utility nodes may use upstream convenience images such as `wbitt/network-multitool:latest` when no project-maintained runtime image exists.
* The SRv6 dynamic-path examples rely on mounted GoBGP binaries inside `wbitt/network-multitool:latest` helper nodes.
