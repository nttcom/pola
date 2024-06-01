<p align="center">
<img src="https://github.com/nttcom/pola/blob/main/docs/figures/pola-logo.png" alt="Pola" width="20%">
</p>

# Pola PCE
[![Linter](https://github.com/nttcom/pola/actions/workflows/ci.yml/badge.svg)](https://github.com/nttcom/pola/actions)
[![Releaser](https://github.com/nttcom/pola/actions/workflows/release.yml/badge.svg)](https://github.com/nttcom/pola/actions)
[![Go Report Card](https://goreportcard.com/badge/nttcom/pola)](https://goreportcard.com/report/github.com/nttcom/pola) 
[![Go Reference](https://pkg.go.dev/badge/github.com/nttcom/pola.svg)](https://pkg.go.dev/github.com/nttcom/pola)
[![Go version](https://img.shields.io/github/go-mod/go-version/nttcom/pola)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Pola PCE is an implementation of the Path Computation Element (PCE) and a PCEP Library in Go.

## Features
* Support for SRv6(full-SID/μSID) and SR-MPLS
* Implementation of active stateful PCE functionality (PCInitiate, PCUpdate, etc.)
* Dynamic and explicit SR policy definition using YAML
  * Dynamic path: Utilizes CSPF with GoBGP BGP-LS TED
  * Explicit path: Allows users to define and provision any Segment List

## Interoperability
### SR-MPLS
* IOS-XR
* Junos
* FRRouting

### SRv6 (full-SID)
* Junos

### SRv6 (μSID)
* IOS-XR

## Installation & Use
* [Getting Started](docs/sources/getting-started.md)
* Examples (powered by [Containerlab](https://containerlab.dev/)/[Tinet](https://github.com/tinynetwork/tinet))
  * [SR-MPLS Example](examples/tinet/sr-mpls_te_l3vpn)
  * [SRv6 Example](examples/containerlab/srv6_te_l3vpn)

## Contributing
If you are interested in contributing to the project, please refer to the [CONTRIBUTING](https://github.com/nttcom/pola/blob/main/CONTRIBUTING.md) guidelines.  
Feel free to fork the repository and create a Pull Request. Your contributions are highly appreciated.

## Licensing
Pola PCE is licensed under the [MIT license](https://en.wikipedia.org/wiki/MIT_License).  
For the full license text, see [LICENSE](https://github.com/nttcom/pola/blob/master/LICENSE).
