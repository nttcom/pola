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
```

## Run Pola PCE using polad

Start polad. Specify the created configuration file with the -f option.

```bash
$ polad -f polad.conf
{"level":"info","ts":1653563205.5598016,"caller":"server/server.go:131","msg":"gRPC Listen","listenInfo":"192.0.2.1:50051","server":"grpc"}
{"level":"info","ts":1653563205.560059,"caller":"server/server.go:99","msg":"PCE Listen","listenInfo":"192.0.2.1:4189"}
```