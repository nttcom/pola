# Getting Started with Pola PCE

This page explains how to use Pola PCE.

## Instllation

```bash
$ go install github.com/nttcom/pola/cmd/polad@latest
```

## Configuration

Specify the IP address and port number for each PCEP and gRPC.

```yaml
global:
  pcep:
    address: "192.0.2.1"
    port: 4189
  grpc:
    address: "192.0.2.1"
    port: 50051
  log:
    path: "/var/log/pola/"
    name: "polad.log"
```

## Run Pola PCE using polad

Start polad. Specify the created configuration file with the -f option.

```bash
$ sudo polad -f polad.yaml
2022-06-05T22:57:59.823Z        info    gRPC Listen     {"listenInfo": "127.0.0.1:50051", "server": "grpc"}
2022-06-05T22:57:59.823Z        info    PCEP Listen     {"listenInfo": "10.100.0.252:4189"}
```
