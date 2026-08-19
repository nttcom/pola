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

### pola session [-j]

Displays PCEP sessions, sorted by peer address.

JSON formatted response

```json
[
  {
    "Addr": "192.0.2.1",
    "State": "UP",
    "LocalSessionID": 1,
    "PccSessionID": 1,
    "LocalTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "PccTimers": { "Keepalive": 10, "DeadTimer": 40 },
    "EffectiveTimers": { "Keepalive": 30, "DeadTimer": 40 },
    "PccType": "RFC_COMPLIANT",
    "Capabilities": [
      {
        "Type": "STATEFUL",
        "Detail": {
          "LSPUpdate": true,
          "IncludeDBVersion": false,
          "LSPInstantiation": true,
          "TriggeredResync": false,
          "DeltaLSPSync": false,
          "TriggeredInitialSync": false,
          "Color": false
        }
      },
      {
        "Type": "SR",
        "Detail": {
          "UnlimitedMSD": false,
          "NAISupported": true,
          "MSD": 10
        }
      }
    ],
    "PccCapabilities": [
      {
        "Type": "SR",
        "Detail": {
          "UnlimitedMSD": false,
          "NAISupported": true,
          "MSD": 16
        }
      }
    ],
    "IsSynced": true
  }
]
```

`State` is the current PCEP session state: `TCP_PENDING`, `OPEN_WAIT`,
`KEEP_WAIT`, or `UP`.

`LocalSessionID` and `PccSessionID` are the PCEP session IDs advertised by
Pola and the PCC, respectively. They are omitted until the corresponding
Open message is received.

`LocalTimers` and `PccTimers` show the PCEP timers advertised by Pola and the
PCC. `EffectiveTimers` shows the timers currently applied by Pola. These
fields are omitted while the session is in `TCP_PENDING` or `OPEN_WAIT`.

`Capabilities` lists capabilities advertised by Pola, while `PccCapabilities`
lists those advertised by the PCC. `PccType` is the PCC type detected from its
capabilities. `IsSynced` indicates whether initial state synchronization has
completed.

### pola session delete *Address* [-j]

Deletes the session with the specified peer address.

JSON formatted response

```json
{
    "status": "success"
}
```

### pola sr-policy list [-j] [--session *address*]

Displays SR Policies managed by polad, grouped by PCEP session and sorted by
peer address. `--session` filters by peer address.

All connected sessions are included. Use `IsSynced` to distinguish an
unsynchronized session from a synced session with no SR Policies.

JSON formatted response

```json
[
  {
    "Addr": "192.0.2.2",
    "State": "UP",
    "LocalSessionID": 1,
    "PccSessionID": 1,
    "LocalTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "PccTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "EffectiveTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "PccType": "RFC_COMPLIANT",
    "Capabilities": [],
    "PccCapabilities": [],
    "IsSynced": true,
    "SRPolicies": [
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
    "Addr": "2001:0db8::1",
    "State": "KEEP_WAIT",
    "LocalSessionID": 2,
    "PccSessionID": 3,
    "LocalTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "PccTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "EffectiveTimers": { "Keepalive": 30, "DeadTimer": 120 },
    "PccType": "CISCO_LEGACY",
    "Capabilities": [],
    "PccCapabilities": [],
    "IsSynced": false,
    "SRPolicies": []
  }
]
```

Notes:

- Policies appear in `SRPolicies` only after their first PCRpt is received, so
  a session that is not yet synced reports an empty list.
- `lspId` is omitted when zero. `plspId` and `state` reflect the latest PCRpt.
- `srcRouterId`/`dstRouterId` are resolved from TED loopback addresses and are
  omitted when no matching node is found.
- `segmentList` includes NAI addresses when available and may include
  `sidStructure` for SRv6 segments.
- `type` and `metric` are retained only for policies created by
  `pola sr-policy add`; they are unavailable for policies discovered from the
  router or after a polad restart.

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
form additionally needs
[`--no-sid-validate`](#pola-sr-policy-add--f-filepath---no-sid-validate).

For each SID, specify the address information required to construct the NAI.
`localAddr` is required for SRv6 SIDs but optional for SR-MPLS labels.

See [JSON schema](../../docs/schemas/cli/policy.json) for input details.

YAML input format

```yaml
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

Skips the check that every explicit SID exists in the TED. Without the flag,
the request fails if any SID is missing from the TED, including when the TED is
disabled or not yet synchronized. With the flag, the policy is provisioned and
both the CLI and polad log a warning.

Notes:

- Dynamic paths and `waypoints[].sid` overrides are not validated.
- Validation is best-effort: the TED is populated asynchronously via BGP-LS,
  so results can lag behind the actual topology.
- For SRv6 uSID containers, only the locator portion is checked, not the
  full SID.
- SID types not represented in the TED (Binding SID, Flex-Algorithm prefix
  SID, anycast SID, static labels) always require `--no-sid-validate`.
- The `-s` shorthand was removed in 1.4.0; use the long flag.

### pola ted [-j]

Displays the TED managed by polad.

JSON formatted response

```json
{
  "ted": [
    {
      "asn": 65000,
      "hostname": "host1",
      "isisAreaID": "490000",
      "links": [
        {
          "adjSid": 17,
          "localIP": "10.0.1.1",
          "metrics": [
            {
              "type": "IGP",
              "value": 10
            }
          ],
          "remoteIP": "10.0.1.2",
          "remoteNode": "0000.0aff.0003"
        },
        {
          "adjSid": 18,
          "localIP": "10.0.0.1",
          "metrics": [
            {
              "type": "IGP",
              "value": 10
            }
          ],
          "remoteIP": "10.0.0.2",
          "remoteNode": "0000.0aff.0002"
        }
      ],
      "prefixes": [
        {
          "prefix": "10.0.1.0/30"
        },
        {
          "prefix": "10.0.0.0/30"
        },
        {
          "prefix": "10.255.0.1/32",
          "sidIndex": 1
        }
      ],
      "routerID": "0000.0aff.0001",
      "srgbBegin": 16000,
      "srgbEnd": 24000
    },
    {
      "asn": 65000,
      "hostname": "host2",
      "isisAreaID": "490000",
      "links": [
        {
          "adjSid": 17,
          "localIP": "10.0.1.2",
          "metrics": [
            {
              "type": "IGP",
              "value": 10
            }
          ],
          "remoteIP": "10.0.1.1",
          "remoteNode": "0000.0aff.0001"
        },
        {
          "adjSid": 16,
          "localIP": "10.0.2.2",
          "metrics": [
            {
              "type": "IGP",
              "value": 10
            }
          ],
          "remoteIP": "10.0.2.1",
          "remoteNode": "0000.0aff.0002"
        }
      ],
      "prefixes": [
        {
          "prefix": "10.255.0.3/32",
          "sidIndex": 3
        },
        {
          "prefix": "10.0.2.0/30"
        },
        {
          "prefix": "10.0.1.0/30"
        }
      ],
      "routerID": "0000.0aff.0003",
      "srgbBegin": 16000,
      "srgbEnd": 24000
    },
    {
      "asn": 65000,
      "hostname": "host3",
      "isisAreaID": "490000",
      "links": [
        {
          "adjSid": 24001,
          "localIP": "10.0.0.2",
          "metrics": [
            {
              "type": "IGP",
              "value": 10
            }
          ],
          "remoteIP": "10.0.0.1",
          "remoteNode": "0000.0aff.0001"
        },
        {
          "adjSid": 24003,
          "localIP": "10.0.2.1",
          "metrics": [
            {
              "type": "IGP",
              "value": 10
            }
          ],
          "remoteIP": "10.0.2.2",
          "remoteNode": "0000.0aff.0201"
        }
      ],
      "prefixes": [
        {
          "prefix": "10.0.2.0/30"
        },
        {
          "prefix": "10.0.0.0/30"
        },
        {
          "prefix": "10.255.0.2/32",
          "sidIndex": 2
        }
      ],
      "routerID": "0000.0aff.0002",
      "srgbBegin": 16000,
      "srgbEnd": 24000
    }
  ]
}
```

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
