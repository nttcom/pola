# Pola CLI Tool

## Installation

### From Go Package

```bash
go install github.com/nttcom/pola/cmd/pola@latest
```

### From Source

#### Getting the Source

```bash
git clone https://github.com/nttcom/pola.git
```

#### Build & install

```bash
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

Without arguments, all sessions are shown in summary form.

Text formatted response (`pola session detail`)

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
        6 SR Policy Association
    Local only:
      SR-PCE-CAPABILITY [RFC8664]: MSD=10
    Peer only:
      STATEFUL-PCE-CAPABILITY [RFC8231/8281]: Color
      SR-PCE-CAPABILITY [RFC8664]: MSD=16
      ASSOC-TYPE-LIST [RFC8697]:
        9 P2MP SR Policy Association (draft)
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

JSON formatted response (`pola session detail -j`)

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
        "unrecognizedTlvTypes": [],
        "other": []
      },
      "localOnly": [{ "capability": "SR", "items": ["MSD=10"] }],
      "peerOnly": [
        { "capability": "STATEFUL", "items": ["Color"] },
        { "capability": "SR", "items": ["MSD=16"] },
        { "capability": "ASSOC_TYPE_LIST", "items": ["9 P2MP SR Policy Association (draft)"] }
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

Field reference:

- `sessionId.local`/`peer` are omitted until the corresponding Open
  message has been exchanged.
- `lspDbSync` indicates the LSP-DB synchronization state and uses the
  same vocabulary as `pola sr-policy list`.
- `stats` contains RFC 9826 message counters. Session setup counters
  persist across reconnects.

### pola session delete *Address* [-j]

Deletes the session with the specified peer address.

JSON formatted response

```json
{
    "status": "success"
}
```

### pola sr-policy list [-j] [--peer *address*]

Displays SR Policies managed by polad, grouped by PCEP peer and sorted by
peer address. `--peer` filters by peer address.

All connected sessions are included. Use `lspDbSync` to distinguish an
unsynchronized session (`pending` or `ongoing`) from a synced session
(`finished`) with no SR Policies.

Text formatted response

```text
Session: 192.0.2.2 (State: up, LSP-DB Sync: finished)
  PolicyName: sample_policy1
    PlspID: 1
    LSPID: 1
    State: up
    Type: explicit
    SrcAddr: 192.0.2.2 (0000.0aff.0002)
    DstAddr: 192.0.2.1 (0000.0aff.0001)
    Color: 999
    Preference: 100
    SegmentList: 16003 -> 16001

Session: 2001:db8::1 (State: keep-wait, LSP-DB Sync: pending)
  No SR Policies: session is not established.
```

JSON formatted response

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
        "srcAddr": "192.0.2.2",
        "dstAddr": "192.0.2.1",
        "srcRouterId": "0000.0aff.0002",
        "dstRouterId": "0000.0aff.0001",
        "color": 999,
        "preference": 100,
        "lspId": 1,
        "state": "up",
        "type": "explicit"
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
- `srcRouterId`/`dstRouterId` are resolved from TED.
- `type` and `metric` are available for policies created by
  `pola sr-policy add`.

### pola sr-policy add -f `filepath`

Create a new SR Policy **using TED**.

#### Dynamic path

YAML input format

```yaml
asn: 65000
srPolicy:
  pcepSessionAddr: 192.0.2.1
  name: policy-name
  srcRouterID: 0000.0aff.0001
  dstRouterID: 0000.0aff.0004
  color: 100
  type: dynamic
  metric: igp
```

`metric` can be `igp`, `te`, or `delay`.

JSON formatted response

```json
{
  "status": "success"
}
```

#### Explicit path

Each SID may include address information for the NAI.

YAML input format

```yaml
asn: 65000
srPolicy:
  pcepSessionAddr: 192.0.2.1
  name: policy-name
  srcRouterID: 0000.0aff.0001
  dstRouterID: 0000.0aff.0004
  color: 100
  type: explicit
  segmentList:
    - sid: 16003
    - sid: 16002
    - sid: 16004
```

JSON formatted response

```json
{
  "status": "success"
}
```

#### Explicit path with endpoint addresses

Instead of `srcRouterID`/`dstRouterID`, endpoints can be given directly as
`srcAddr`/`dstAddr`. This form bypasses path computation: no CSPF or router-ID
resolution is performed, so it accepts only `type: explicit` and takes the
segment list verbatim.

Each SID is still validated against the TED, so with `ted.enable: false` this
form additionally requires `--no-sid-validate`.

For each SID, specify the address information required to construct the NAI.
`localAddr` is required for SRv6 SIDs but optional for SR-MPLS labels.

See [JSON schema](../../docs/schemas/cli/policy.json) for input details.

YAML input format

```yaml
asn: 65000
srPolicy:
  pcepSessionAddr: "2001:0db8::1"
  srcAddr: "2001:0db8::1"
  dstAddr: "2001:0db8::2"
  name: "policy-name"
  color: 100
  segmentList:
    - sid: "2001:0db8:1005::"
      localAddr: "2001:0db8::5"
      sidStructure: "32,16,0,80"
    - sid: "2001:0db8:1006::"
      localAddr: "2001:0db8::6"
      sidStructure: "32,16,0,80"
```

JSON formatted response

```json
{
  "status": "success"
}
```

### pola sr-policy add -f `filepath` --no-sid-validate

Skips validation of explicit SIDs against the TED.

> [!NOTE]
> SID validation depends on the asynchronously populated BGP-LS TED and may
> not reflect the current network topology. Use this option for SIDs that
> cannot be represented in the TED.

### pola ted [-j]

Displays the TED managed by polad, sorted by router ID. If TED is disabled by
polad, the command returns a non-zero exit status with an error message on
stderr, in both text and `-j` mode.

Text formatted response

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

JSON formatted response. The top level is an array of nodes, matching the
other commands' output; there is no wrapping `ted` object. A link's `localIp`/`remoteIp` is omitted when the BGP-LS descriptor
does not contain an interface address.

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
