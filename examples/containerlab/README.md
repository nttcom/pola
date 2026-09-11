# Containerlab Examples

This directory contains the supported example labs for Pola.

## Prerequisites

See [Containerlab Setup Prerequisites](../../docs/setup/containerlab-prerequisites.md) for detailed setup instructions.

Example-specific requirements are listed in each topology's `README.md` and `Requirements` section.

## Conventions

* Topology files use `topo.clab.yaml`.
* The Pola helper node is named `pola` across all examples.
* Daemons are expected to start automatically unless a README explicitly says otherwise.
* The `switch` node is a `wbitt/network-multitool:latest` container that runs a Linux bridge, providing a private Layer 2 segment for each topology without using the host network namespace.

## Image Tag Policy

* Router and network OS images are pinned to tested versions.
* The Pola helper uses `ghcr.io/nttcom/pola:latest-debug` because the topologies run `ip` in `exec` blocks and expect a shell for troubleshooting, which the slim `latest` image does not provide.
* Generic utility nodes may use upstream convenience images such as `wbitt/network-multitool:latest` when no project-maintained runtime image exists.
* The SRv6 dynamic-path examples rely on mounted GoBGP binaries inside `wbitt/network-multitool:latest` helper nodes.
