# Go gRPC API examples

Go examples demonstrating the `api.pola.v1.PCEService` gRPC API.
Use them as a starting point for building your own controller.

## Examples

| Directory | RPC | Description |
| --- | --- | --- |
| [`sr-policy-create-dynamic/`](sr-policy-create-dynamic/) | `CreateSRPolicy` | Create a dynamic SR Policy with optional waypoints. |
| [`sr-policy-create-explicit/`](sr-policy-create-explicit/) | `CreateSRPolicy` | Create an explicit SR Policy. |
| [`sr-policy-create-no-sid-validate/`](sr-policy-create-no-sid-validate/) | `CreateSRPolicy` | Create an explicit SR Policy without TED or SID validation. |
| [`sr-policy-create-srv6/`](sr-policy-create-srv6/) | `CreateSRPolicy` | Create an explicit SRv6 SR Policy with `LocalAddr` and `SidStructure`. |
| [`sr-policy-delete/`](sr-policy-delete/) | `DeleteSRPolicy` | Delete an SR Policy. |
| [`sr-policy-list/`](sr-policy-list/) | `GetSRPolicyList` | List SR Policies known to polad. |
| [`session-list/`](session-list/) | `GetSessionList` | List PCEP sessions with state, capabilities and sync status. |
| [`session-delete/`](session-delete/) | `DeleteSession` | Delete a PCEP session. |
| [`ted-get/`](ted-get/) | `GetTED` | Dump the traffic engineering database. |

Explicit SR Policies normally require a synchronized TED for SID validation.
Examples with `NoSidValidate` bypass that requirement.

## Running

Every example accepts a `-server` flag, defaulting to `localhost:50051`:

```shell
go run -C examples/grpc/go ./session-list
go run -C examples/grpc/go ./session-list -server 192.0.2.100:50051
```

The connection is insecure, matching polad's default. Add real transport
credentials before using any of this over an untrusted network.
