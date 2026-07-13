# Containerlab Examples

This directory contains the supported example labs for Pola.

## Conventions

* Topology files use `topo.clab.yml`.
* The Pola helper node is named `pola` across all examples.
* Daemons are expected to start automatically unless a README explicitly says otherwise.
* The `switch` bridge node is created by Containerlab from the topology; a host-side bridge does not need to be created manually.

## Image Tag Policy

* Router and network OS images are pinned to tested versions.
* The Pola helper uses `ghcr.io/nttcom/pola:latest-dev` so examples can follow current development builds.
* Generic utility nodes may use upstream convenience images such as `wbitt/network-multitool:latest` when no project-maintained runtime image exists.
* The SRv6 dynamic-path examples rely on mounted GoBGP binaries inside `wbitt/network-multitool:latest` helper nodes.
