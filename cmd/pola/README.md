# pola cli tool

## command reference

### pola session \[-j\]
Displays the peer addresses of the active session.

json formatted response
```
{
    "sessions": [
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

### pola sr-policy list \[-j\]
Displays the lsp list managed by polad.

json formatted response
```
{
	"lsps": [
		{
			"color": 999,
			"dstAddr": "192.0.2.1",
			"segmentList": [
				16003,
				16001
			],
			"peerAddr": "192.0.2.2",
			"policyName": "sample_policy1",
			"preference": 100,
			"srcAddr": "192.0.2.2"
		},
		{
			"color": 888
			"dstAddr": "192.0.2.2",
			"segmentList": [
				16003,
				16002
			],
			"peerAddr": "192.0.2.1",
			"policyName": "sample_policy2",
			"preference": 100,
			"srcAddr": "192.0.2.1"
		}
	]
}
```

※ want to change to this format later.
```
{
    "peers": [
        {
            "peerAddr": "192.0.2.1",
            "lsps": [
                {
                    "policyName": "sample_policy1",
                    "srcAddr": "192.0.2.1",
                    "dstAddr": "192.0.2.2",
                    "segmentList": [
                        16003,
                        16002
                    ]
                },
                {
                    "policyName": "sample_policy2",
                    "srcAddr": "192.0.2.1",
                    "dstAddr": "192.0.2.2",
                    "segmentList": [
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
                    "segmentList": [
                        16003,
                        16001
                    ]
                },
                {
                    "policyName": "sample_policy4",
                    "srcAddr": "192.0.2.2",
                    "dstAddr": "192.0.2.1",
                    "segmentList": [
                        16003,
                        16002,
                        16001
                    ]
                },
            ]
        },       
]
```

### pola sr-policy add -f _filepath_

Create a new SR Policy using TED 

#### Case: Dynamic Path calculate

yaml input format
```
asn: 65000
srPolicy:
    pcepSessionAddr: 192.0.2.1
    name: policy-name    
    srcRouterId: 0000.0aff.0001
    dstRouterId: 0000.0aff.0004
    color: 100
    type: dynamic 
    metric: igp / te / delay
```

json formatted response
```
{
    "status": "success"
}
```

#### Case: Explicit Path

yaml input format
```
asn: 65000
srPolicy:
    pcepSessionAddr: 192.0.2.1
    name: policy-name    
    srcRouterId: 0000.0aff.0001
    dstRouterId: 0000.0aff.0004
    color: 100
    type: explicit
	segmentList:
        - sid: 16003
        - sid: 16002
		- sid: 16004
```

json formatted response
```
{
    "status": "success"
}
```

### pola sr-policy add -f _filepath_ --no-link-state

Create a new SR Policy without using TED

yaml input format
```
srPolicy:
    pcepSessionAddr: 192.0.2.1
    srcAddr: 192.0.2.1
    dstAddr: 192.0.2.2
    name: name
    color: 100
    segmentList:
        - sid: 16003
          nai: 192.0.2.3
        - sid: 16002
          nai: 192.0.2.2
```

json formatted response
```
{
    "status": "success"
}
```

### pola ted \[-j\]
Displays the ted managed by polad.

json formatted response
```
{
	"ted": [
		{
			"asn": 65000,
			"hostname": "host1",
			"isisAreaId": "490000",
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
			"routerId": "0000.0aff.0001",
			"srgbBegin": 16000,
			"srgbEnd": 24000
		},
		{
			"asn": 65000,
			"hostname": "host2",
			"isisAreaId": "490000",
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
			"routerId": "0000.0aff.0003",
			"srgbBegin": 16000,
			"srgbEnd": 24000
		},
		{
			"asn": 65000,
			"hostname": "host3",
			"isisAreaId": "490000",
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
			"routerId": "0000.0aff.0002",
			"srgbBegin": 16000,
			"srgbEnd": 24000
		}
	]
}
```
