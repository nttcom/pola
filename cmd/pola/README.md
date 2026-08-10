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

### pola session \[-j\]

Displays the peer addresses of the active session, sorted by address.

JSON formatted response

```json
[
  {
    "Addr": "192.0.2.1",
    "State": "SESSION_STATE_UP",
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
    "IsSynced": true
  }
]
```

`Capabilities` is the list of advertised capability TLVs, one entry per TLV.
`Type` identifies the TLV, and `Detail` carries its type-specific fields
(e.g. `MSD` for the SR capability, `VersionNumber` for LSP-DB-Version); it is
omitted for TLVs with no fields beyond their type.

### pola session delete *Address* \[-j\]

Deletes the specified session.

JSON formatted response

```json
{
    "status": "success"
}
```

### pola sr-policy list \[-j\] \[--session *address*\]

Displays the SR Policies managed by polad, grouped by PCEP session and sorted
by session address. Pass `--session` to only show policies on the session
with that peer address.

JSON formatted response

```json
[
  {
    "peerAddr": "192.0.2.2",
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
    "peerAddr": "2001:0db8::1",
    "srPolicies": [
      {
        "plspId": 1,
        "policyName": "sample_policy2",
        "segmentList": [
          {
            "sid": "2001:0db8:1005::",
            "localAddr": "2001:0db8::5",
            "sidStructure": "32,16,0,80"
          }
        ],
        "srcAddr": "2001:0db8::1",
        "dstAddr": "2001:0db8::2",
        "color": 888,
        "preference": 100,
        "lspId": 1,
        "state": "active",
        "type": "dynamic",
        "metric": "te"
      }
    ]
  }
]
```

Notes:

- `plspId`, `lspId`, and `state` reflect the latest PCRpt received. They may
  be omitted for newly created policies before the first report.
- `srcRouterId`/`dstRouterId` are resolved from TED loopback addresses and are
  omitted when no matching node is found.
- `segmentList` entries include `localAddr`/`remoteAddr` when the SID carries
  NAI information. SRv6 segments may also include `sidStructure`.
- `type` and `metric` reflect the candidate-path settings used when the policy
  was created by `pola sr-policy add`. They are omitted for policies discovered
  from the router or after a polad restart.

### pola sr-policy add -f `filepath`

Create a new SR Policy **using TED**

#### Case: Dynamic Path calculate

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
  metric: igp / te / delay
```

JSON formatted response

```json
{
  "status": "success"
}
```

#### Case: Explicit Path

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

#### Case: Explicit Path (endpoint addresses)

Instead of `srcRouterID`/`dstRouterID`, endpoints can be given directly as
`srcAddr`/`dstAddr`. This form bypasses path computation: no CSPF and no
router-ID resolution, so it accepts only `type: explicit` and takes the
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

### pola ted \[-j\]

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
