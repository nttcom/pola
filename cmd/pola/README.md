# Pola CLI Tool

## Installation

### From Go

```bash
go install github.com/nttcom/pola/cmd/pola@latest
```

### From Source

```bash
git clone https://github.com/nttcom/pola.git
cd pola
go install ./cmd/pola

# or, install with daemon
go install ./...
```

## Command Reference

### pola session [peer-address] [detail] [-j]

Displays PCEP sessions, sorted by peer address.

- `peer-address` optionally filters sessions by peer address.
- `detail` includes additional session information and message statistics.
- `-j` outputs JSON.

Text output (`pola session detail`)

```text
Session #0: 192.0.2.1
  State:             up
  LSP-DB Sync:       finished
  Role:              active-stateful-pce
  Up Time:           00:12:22
  Session ID:        Local=1, Peer=7
  Transport:         tcp, auth=none
  Timers:
               Local  Peer  Effective
    Keepalive  30     10    30
    DeadTimer  120    40    40
  Capabilities:
    Common:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Stateful, Update, Instantiation
      SR-PCE-CAPABILITY [RFC8664]: SR, SR-NAI-Supported
      ASSOC-TYPE-LIST [RFC8697]:
        SR Policy Association (0x0006) [RFC9862]
      Unrecognized TLVs:
        type=73: SR-P2MP-POLICY-CAPABILITY (draft-ietf-pce-sr-p2mp-policy-11) [sub-TLV of PATH-SETUP-TYPE-CAPABILITY]
    Local only:
      SR-PCE-CAPABILITY [RFC8664]: MSD=10
    Peer only:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Color
      SR-PCE-CAPABILITY [RFC8664]: MSD=16
      ASSOC-TYPE-LIST [RFC8697]:
        P2MP SR Policy Association (0x0009) [draft-ietf-pce-sr-p2mp-policy-11]
  Session Creation:  2026-08-19T09:30:05Z
  Initiator:         remote
  Stats:
               Sent  Rcvd
    Open       1     1
    Keepalive  25    25
    Close      0     0
    PCErr      0     0
    PCNtf      0     0
    PCReq      0     0
    PCRep      0     0
    Report     0     3
    Update     1     0
    Initiate   1     0
    Unrecognized Rcvd: 0
    Corrupt Rcvd:      0
    Session Setup:     ok=1, fail=0
```

JSON output (`pola session detail -j`)

```json
[
  {
    "peerAddress": "192.0.2.1",
    "state": "up",
    "lspDbSync": "finished",
    "upTime": "00:12:22",
    "role": "active-stateful-pce",
    "sessionId": { "local": 1, "peer": 7 },
    "timers": {
      "keepalive": { "local": 30, "peer": 10, "effective": 30 },
      "deadTimer": { "local": 120, "peer": 40, "effective": 40 }
    },
    "transport": { "protocol": "tcp", "auth": "none" },
    "capabilities": {
      "common": {
        "stateful": true,
        "update": true,
        "instantiation": true,
        "pathSetupTypes": [],
        "associationTypes": [6],
        "unrecognizedTlvTypes": [73],
        "capabilities": [
          { "capability": "STATEFUL", "items": ["Stateful", "Update", "Instantiation"] },
          { "capability": "SR", "items": ["SR", "SR-NAI-Supported"] },
          { "capability": "ASSOC_TYPE_LIST", "items": ["SR Policy Association (0x0006) [RFC9862]"] },
          {
            "capability": "UNKNOWN",
            "items": [
              "type=73: SR-P2MP-POLICY-CAPABILITY (draft-ietf-pce-sr-p2mp-policy-11) [sub-TLV of PATH-SETUP-TYPE-CAPABILITY]"
            ]
          }
        ],
        "other": []
      },
      "localOnly": [{ "capability": "SR", "items": ["MSD=10"] }],
      "peerOnly": [
        { "capability": "STATEFUL", "items": ["Color"] },
        { "capability": "SR", "items": ["MSD=16"] },
        { "capability": "ASSOC_TYPE_LIST", "items": ["P2MP SR Policy Association (0x0009) [draft-ietf-pce-sr-p2mp-policy-11]"] }
      ]
    },
    "sessionCreation": "2026-08-19T09:30:05Z",
    "initiator": "remote",
    "stats": {
      "open": { "sent": 1, "rcvd": 1 },
      "keepalive": { "sent": 25, "rcvd": 25 },
      "close": { "sent": 0, "rcvd": 0 },
      "pcerr": { "sent": 0, "rcvd": 0 },
      "pcntf": { "sent": 0, "rcvd": 0 },
      "pcreq": { "sent": 0, "rcvd": 0 },
      "pcrep": { "sent": 0, "rcvd": 0 },
      "report": { "sent": 0, "rcvd": 3 },
      "update": { "sent": 1, "rcvd": 0 },
      "initiate": { "sent": 1, "rcvd": 0 },
      "unrecognizedRcvd": 0,
      "corruptRcvd": 0,
      "sessionSetup": { "ok": 1, "fail": 0 }
    }
  }
]
```

Fields:

- `lspDbSync` indicates the LSP-DB synchronization state, using the same
  vocabulary as `pola sr-policy list`.
- `stats` contains RFC 9826 message counters.
- `capabilities.common.capabilities` lists all capabilities shared by
  both sides, grouped by TLV. Other fields provide views of commonly used
  capabilities. `other` is deprecated and retained for backward compatibility.
- `[sub-TLV of PATH-SETUP-TYPE-CAPABILITY]` indicates a capability
  advertised only as a PATH-SETUP-TYPE-CAPABILITY sub-TLV and included
  in `unrecognizedTlvTypes`.

### pola session delete *Address* [-j]

Deletes the session with the specified peer address.

JSON output

```json
{
    "status": "success"
}
```

### pola sr-policy list [-j] [--peer *address*]

Displays SR Policies managed by polad, grouped by PCEP peer and sorted by
peer address. `--peer` filters by peer address.

All connected sessions are included. `lspDbSync` indicates whether the
session is synchronized (`finished`) or not (`pending` or `ongoing`).

Text output

```text
Session: 192.0.2.2 (State: up, LSP-DB Sync: finished)
  PolicyName: sample_policy1
    PlspID: 1
    LSPID: 1
    State: up
    Type: explicit
    Headend: 192.0.2.2 (0000.0aff.0002)
    Endpoint: 192.0.2.1 (0000.0aff.0001)
    Color: 999
    Preference: 100
    SegmentList: 16003 -> 16001

Session: 2001:db8::1 (State: keep-wait, LSP-DB Sync: pending)
  No SR Policies: session is not established.
```

JSON output

```json
[
  {
    "peerAddress": "192.0.2.2",
    "state": "up",
    "lspDbSync": "finished",
    "srPolicies": [
      {
        "plspId": 1,
        "policyName": "sample_policy1",
        "segmentList": [
          { "sid": 16003 },
          { "sid": 16001 }
        ],
        "headend": "192.0.2.2",
        "endpoint": "192.0.2.1",
        "headendRouterId": "0000.0aff.0002",
        "endpointRouterId": "0000.0aff.0001",
        "color": 999,
        "candidatePath": {
          "preference": 100,
          "explicit": {
            "segmentList": [
              { "sid": 16003 },
              { "sid": 16001 }
            ]
          }
        },
        "lspId": 1,
        "state": "up"
      }
    ]
  },
  {
    "peerAddress": "2001:db8::1",
    "state": "keep-wait",
    "lspDbSync": "pending",
    "srPolicies": []
  }
]
```

Notes:

- `state` and `lspDbSync` use the same vocabulary as `pola session`.
- Policies appear after the first PCRpt is received.
- `lspId` is omitted when zero.
- `headendRouterId`/`endpointRouterId` are resolved from TED.
- `candidatePath.dynamic.metric` is included for policies with a dynamic candidate path.
- Top-level `segmentList` is the currently signaled segment list; for an
  explicit candidate path, `candidatePath.explicit.segmentList` mirrors it.

### pola sr-policy add -f `filepath`

Creates a new SR Policy.

#### Dynamic path

YAML input format

```yaml
asn: 65000
srPolicy:
  pcepSessionAddr: 192.0.2.1
  name: policy-name
  headendRouterID: 0000.0aff.0001
  endpointRouterID: 0000.0aff.0004
  color: 100
  candidatePath:
    dynamic:
      metric: igp
```

`metric` can be `igp`, `te`, or `delay`.

`candidatePath.dynamic.underlayFamily` selects the underlay address family.
When unspecified, it follows `endpointFamily` or the endpoint's address
family. Cross-AF configurations are supported by Pola but are not an IETF
interoperability guarantee.

JSON output

```json
{
  "status": "success"
}
```

#### Explicit path

YAML input format

```yaml
asn: 65000
srPolicy:
  pcepSessionAddr: 192.0.2.1
  name: policy-name
  headendRouterID: 0000.0aff.0001
  endpointRouterID: 0000.0aff.0004
  color: 100
  candidatePath:
    explicit:
      segmentList:
        - sid: 16003
        - sid: 16002
        - sid: 16004
```

JSON output

```json
{
  "status": "success"
}
```

#### Explicit path with endpoint addresses

Instead of `headendRouterID`/`endpointRouterID`, endpoints can be given
directly as `headend`/`endpoint` addresses (RFC 9256 §2.1), for either a
dynamic or an explicit candidate path. For dynamic paths, router IDs needed
for CSPF are resolved from the TED; `endpointFamily` selects the resolution
family when necessary and is valid only with the router-ID form.

Each SID is still validated against the TED, so with `ted.enable: false` this
form additionally requires `--no-sid-validate`.

`localAddr` is required for SRv6 SIDs and optional for SR-MPLS labels.

See [JSON schema](../../docs/schemas/cli/policy.json) for input details.

YAML input format

```yaml
asn: 65000
srPolicy:
  pcepSessionAddr: "2001:0db8::1"
  headend: "2001:0db8::1"
  endpoint: "2001:0db8::2"
  name: "policy-name"
  color: 100
  candidatePath:
    explicit:
      segmentList:
        - sid: "2001:0db8:1005::"
          localAddr: "2001:0db8::5"
          sidStructure: "32,16,0,80"
        - sid: "2001:0db8:1006::"
          localAddr: "2001:0db8::6"
          sidStructure: "32,16,0,80"
```

JSON output

```json
{
  "status": "success"
}
```

### pola sr-policy add -f `filepath` --no-sid-validate

Skips validation of explicit SIDs against the TED.

### pola ted [-j]

Displays the TED managed by polad, sorted by router ID. If TED is disabled by
polad, the command returns a non-zero exit status with an error message on
stderr, in both text and `-j` mode.

Text output

```text
Node #0: 0000.0aff.0001
  Hostname: host1
  ISIS Area ID: 490000
  SRGB: 16000 - 24000
  Prefixes:
    10.0.0.0/30
    10.255.0.1/32
      index: 1
  Links:
    Local: 10.0.0.1 Remote: 10.0.0.2
      RemoteRouterID: 0000.0aff.0002
      Metrics:
        igp: 10
      Adj-SID: 17
      SRv6 End.X SID:
        EndpointBehavior: ENDX
        SIDs: [2001:db8:1::1]
        SID Structure: Block: 32, Node: 16, Func: 16, Arg: 0
  SRv6 SIDs:
    SIDs: [2001:db8:1::]
    Block: 32, Node: 16, Func: 16, Arg: 0
    EndpointBehavior: END, Flags: 0, Algorithm: 0
    MultiTopoIDs: []

Node #1: 0000.0aff.0002
  Hostname: host2
  ISIS Area ID: 490000
  SRGB: 16000 - 24000
  Prefixes:
    10.0.0.0/30
    10.255.0.2/32
      index: 2
  Links:
  SRv6 SIDs:
```

JSON output. The top level is an array of nodes; there is no wrapping
`ted` object. `localIp`/`remoteIp` are omitted when no interface address
is present in the BGP-LS descriptor.

```json
[
  {
    "asn": 65000,
    "routerId": "0000.0aff.0001",
    "hostname": "host1",
    "isisAreaId": "490000",
    "srgb": { "begin": 16000, "end": 24000 },
    "prefixes": [
      { "prefix": "10.0.0.0/30" },
      { "prefix": "10.255.0.1/32", "sidIndex": 1 }
    ],
    "links": [
      {
        "localIp": "10.0.0.1",
        "remoteIp": "10.0.0.2",
        "remoteRouterId": "0000.0aff.0002",
        "metrics": [{ "type": "igp", "value": 10 }],
        "adjSid": 17,
        "srv6EndXSid": {
          "endpointBehavior": { "behavior": 5, "name": "ENDX" },
          "sids": ["2001:db8:1::1"],
          "sidStructure": { "localBlock": 32, "localNode": 16, "localFunc": 16, "localArg": 0 }
        }
      }
    ],
    "srv6Sids": [
      {
        "sids": ["2001:db8:1::"],
        "endpointBehavior": { "behavior": 1, "name": "END", "flags": 0, "algorithm": 0 },
        "sidStructure": { "localBlock": 32, "localNode": 16, "localFunc": 16, "localArg": 0 },
        "multiTopoIds": []
      }
    ]
  },
  {
    "asn": 65000,
    "routerId": "0000.0aff.0002",
    "hostname": "host2",
    "isisAreaId": "490000",
    "srgb": { "begin": 16000, "end": 24000 },
    "prefixes": [
      { "prefix": "10.0.0.0/30" },
      { "prefix": "10.255.0.2/32", "sidIndex": 2 }
    ],
    "links": [],
    "srv6Sids": []
  }
]
```

Notes:

- `metrics[].type` is a lowercase token (`igp`, `te`, `delay`, `hopcount`),
  matching the metric vocabulary used elsewhere.
- `endpointBehavior.flags`/`.algorithm` are present for node SRv6 SIDs
  (`srv6Sids`) but omitted for adjacency SIDs (`links[].srv6EndXSid`), which
  carry only the behavior.

## Completion

### Bash

```bash
pola completion bash | sudo tee -a /usr/share/bash-completion/completions/pola >/dev/null
source /usr/share/bash-completion/completions/pola
```

### Zsh

```bash
pola completion zsh > /usr/local/share/zsh/site-functions/_pola
compinit
```

### Fish

```bash
pola completion fish > ~/.config/fish/completions/pola.fish
fish_update_completions
```
