---
title: "pola"
linkTitle: "pola"
weight: 20
description: >
  The gRPC client of Pola PCE.
---

## Command Reference
### pola session \[-j\]
Displays the peer addresses of the active session.

json formatted response
```json
{
    "peers": [
        {
            "address": "192.0.2.1",
            "status": "active",
        },
        {
            "address": "192.0.2.2",
            "status": "active",
        },
    ]
}
```

### pola lsp list \[-j\]
Displays the lsp list managed by polad.

json formatted response
```json
{
	"lsps": [
		{
			"dstAddr": "192.0.2.1",
			"path": [
				16003,
				16001
			],
			"peerAddr": "192.0.2.1",
			"policyName": "sample_policy1",
			"srcAddr": "192.0.2.2"
		},
		{
			"dstAddr": "192.0.2.1",
			"path": null,
			"peerAddr": "192.0.2.2",
			"policyName": "sample_policy2",
			"srcAddr": "192.0.2.2"
		},
		{
			"dstAddr": "192.0.2.2",
			"path": [
				16003,
				16002
			],
			"peerAddr": "192.0.2.1",
			"policyName": "sample_policy3",
			"srcAddr": "192.0.2.1"
		}
	]
}
```

※ want to change to this format later.
```json
{
    "peers": [
        {
            "peerAddr": "192.0.2.1",
            "lsps": [
                {
                    "policyName": "sample_policy1",
                    "srcAddr": "192.0.2.1",
                    "dstAddr": "192.0.2.2",
                    "segmentlist": [
                        16003,
                        16002
                    ]
                },
                {
                    "policyName": "sample_policy2",
                    "srcAddr": "192.0.2.1",
                    "dstAddr": "192.0.2.2",
                    "segmentlist": [
                        16003,
                        16001,
                        16002
                    ]
                },
            ]
        },
        {
            "peerAddr": "192.0.2.2",
            "lsps": [
                {
                    "policyName": "sample_policy3",
                    "srcAddr": "192.0.2.2",
                    "dstAddr": "192.0.2.1",
                    "segmentlist": [
                        16003,
                        16001
                    ]
                },
                {
                    "policyName": "sample_policy4",
                    "srcAddr": "192.0.2.2",
                    "dstAddr": "192.0.2.1",
                    "segmentlist": [
                        16003,
                        16002,
                        16001
                    ]
                },
            ]
        },       
]
```

### pola lsp list -f _filepath_
Create a new SR-Policy

yaml input format
```yaml
srPolicy:
    name: name
    peerAddr: 192.0.2.1
    srcAddr: 192.0.2.1
    dstAddr: 192.0.2.2
    color: 100
    segmentlist:
        - sid: 16003
          nai: 192.0.2.3
        - sid: 16002
          nai: 192.0.2.2
```

json formatted response
```json
{
    "status": "success"
}
```
