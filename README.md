<p align="center">
<img src="https://github.com/nttcom/pola/blob/main/docs/figures/pola.png" alt="Pola" width="20%">
</p>

# Pola PCE
[![Linter](https://github.com/nttcom/pola/actions/workflows/ci.yml/badge.svg)](https://github.com/nttcom/pola/actions)
[![Releaser](https://github.com/nttcom/pola/actions/workflows/release.yml/badge.svg)](https://github.com/nttcom/pola/actions)
[![Go Report Card](https://goreportcard.com/badge/nttcom/pola)](https://goreportcard.com/report/github.com/nttcom/pola) 
[![Go Reference](https://pkg.go.dev/badge/github.com/nttcom/pola.svg)](https://pkg.go.dev/github.com/nttcom/pola)
[![Go version](https://img.shields.io/github/go-mod/go-version/nttcom/pola)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

PCEP Library and Stateful PCE Implementation with Go 

## Features
* Supports SRv6 and SR-MPLS
* Active stateful PCE (PCInitiate, PCUpdate, etc.)
* Provide dynamic/explicit SR policy defined as YAML
  * Dynamic path: CSPF based on [GoBGP](https://github.com/osrg/gobgp) BGP-LS TED
  * Explicit path: Define and provide any Segment List

## Interoperability
### SR-MPLS
* IOS-XR
* Junos
* FRRouting

### SRv6
* Junos

## Installation & Use
* [Getting Started](docs/sources/getting-started.md)
* Examples (powered by [Containerlab](https://containerlab.dev/)/[Tinet](https://github.com/tinynetwork/tinet))
  * [SR-MPLS Example](examples/tinet/sr-mpls_te_l3vpn)
  * [SRv6 Example](examples/containerlab/srv6_te_l3vpn)

## Contributing
See [CONTRIBUTING](https://github.com/nttcom/pola/blob/main/CONTRIBUTING.md).  
Please fork the repository and create a Pull Request.
We welcome and appreciate your contribution.

## Licensing
Pola PCE is under [MIT license](https://en.wikipedia.org/wiki/MIT_License). 
See [LICENSE](https://github.com/nttcom/pola/blob/master/LICENSE) for the full license text.
