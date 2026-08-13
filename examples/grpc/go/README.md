# Go gRPC API examples

Go examples demonstrating the `api.pola.v1.PCEService` gRPC API.
Use them as a starting point for building your own controller.

## Examples

| Directory | RPC | Description |
| --- | --- | --- |
| [`sr-policy-create-dynamic/`](sr-policy-create-dynamic/) | `CreateSRPolicy` | Dynamic SR Policy with the path computed from the TED (`Type: DYNAMIC`, `DisablePathCompute: false`). Also shows optional waypoints. |
| [`sr-policy-create-explicit/`](sr-policy-create-explicit/) | `CreateSRPolicy` | Explicit SR Policy with endpoints resolved through the TED (`Type: EXPLICIT`, `DisablePathCompute: false`). |
| [`sr-policy-create-no-sid-validate/`](sr-policy-create-no-sid-validate/) | `CreateSRPolicy` | Explicit SR Policy with the supplied segment list installed as-is; no TED required (`DisablePathCompute: true`, `NoSidValidate: true`). |
| [`sr-policy-create-srv6/`](sr-policy-create-srv6/) | `CreateSRPolicy` | Explicit SRv6 SR Policy with `LocalAddr` and `SidStructure` (`DisablePathCompute: true`, `NoSidValidate: true`). |
| [`sr-policy-delete/`](sr-policy-delete/) | `DeleteSRPolicy` | Delete an SR Policy. |
| [`sr-policy-list/`](sr-policy-list/) | `GetSRPolicyList` | List the SR Policies known to polad. |
| [`session-list/`](session-list/) | `GetSessionList` | List PCEP sessions with state, capabilities and sync status. |
| [`session-delete/`](session-delete/) | `DeleteSession` | Delete a PCEP session. |
| [`ted-get/`](ted-get/) | `GetTED` | Dump the traffic engineering database. |

Explicit SR Policies normally require a synchronized TED for SID validation.
Examples with `NoSidValidate` bypass that requirement.

## Running

Every example accepts a `-server` flag, defaulting to `localhost:50051`:

```shell
go run ./examples/grpc/go/session-list
go run ./examples/grpc/go/session-list -server 192.0.2.100:50051
```

The connection is insecure, matching polad's default. Add real transport
credentials before using any of this over an untrusted network.
