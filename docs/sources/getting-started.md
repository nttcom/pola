# Getting Started with Pola PCE

This page explains how to use Pola PCE.

## Instllation

```bash
$ go install github.com/nttcom/pola/cmd/polad@latest
```

## Configuration

Specify the IP address and port number for each PCEP and gRPC.

**case: TED disable**

To manage SR Policy without using TED.

```yaml
global:
  pcep:
    address: **
    port: 4189
  grpc-server:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: false
```

**case: TED enable**

To manage SR Policy using TED.
Enabling TED allows dynamic path calculation.

A specific tool for updating TED is required to use this feature.
Currently, only GoBGP is supported.

```
global:
  pcep:
    address: **
    port: 4189
  grpc-server:
    address: "127.0.0.1"
    port: 50052
  log:
    path: "/var/log/pola/"
    name: "polad.log"
  ted:
    enable: true
    source: "gobgp"
  gobgp:
    grpc-client:
      address: "127.0.0.1"
      port: 50051
```


## Run Pola PCE using polad

Start polad. Specify the created configuration file with the -f option.

```bash
$ sudo polad -f polad.yaml
2022-06-05T22:57:59.823Z        info    gRPC Listen     {"listenInfo": "127.0.0.1:50051", "server": "grpc"}
2022-06-05T22:57:59.823Z        info    PCEP Listen     {"listenInfo": "10.100.0.252:4189"}
```
