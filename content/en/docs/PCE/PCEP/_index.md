---
title: "PCEP Package"
linkTitle: "PCEP Package"
weight: 1
description: >
  PCEP package (pkg/packet/pcep/pcep.go).
---

## Common Header
### Header Format
Format ([RFC5440 Figure 7: PCEP Message Common Header](https://datatracker.ietf.org/doc/html/rfc5440#section-6.1))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver |  Flags  |  Message-Type |       Message-Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type CommonHeader struct { // RFC5440 6.1
	Version       uint8
	Flag          uint8
	MessageType   uint8
	MessageLength uint16
}
```

### Fields
Version: 1

Flags: No flags are currently defined. 

Message Types: The following message types are currently defined: 
```
const ( // PCEP Message-Type (1byte)
	MT_RESERVED     uint8 = 0x00 // RFC5440
	MT_OPEN         uint8 = 0x01 // RFC5440
	MT_KEEPALIVE    uint8 = 0x02 // RFC5440
	MT_PCREQ        uint8 = 0x03 // RFC5440
	MT_PCREP        uint8 = 0x04 // RFC5440
	MT_NOTIFICATION uint8 = 0x05 // RFC5440
	MT_ERROR        uint8 = 0x06 // RFC5440
	MT_CLOSE        uint8 = 0x07 // RFC5440
	MT_PCMONREQ     uint8 = 0x08 // RFC5886
	MT_PCMONREP     uint8 = 0x09 // RFC5886
	MT_REPORT       uint8 = 0x0a // RFC8231
	MT_UPDATE       uint8 = 0x0b // RFC8281
	MT_LSPINITREQ   uint8 = 0x0c // RFC8281
	MT_STARTTLS     uint8 = 0x0d // RFC8253
)
```

Message-Length: total length of the PCEP message including the common header, expressed in bytes. 

## PCEP Messages
### Open Message
#### Message Format
format ([RFC5440 6.2](https://datatracker.ietf.org/doc/html/rfc5440#section-6.2))
```
<Open Message>::= <Common Header>
                  <OPEN>
```
Message Type: 0x01

### Keepalive Message
#### Message Format
format ([RFC5440 6.3](https://datatracker.ietf.org/doc/html/rfc5440#section-6.3))
```
<Keepalive Message>::= <Common Header>
```
Message Type: 0x02

### Error (PCErr) Message
#### Message Format
format ([RFC5440 6.3](https://datatracker.ietf.org/doc/html/rfc5440#section-6.3))
```
<PCErr Message> ::= <Common Header>
                  ( <error-obj-list> [<Open>] ) | <error>
                  [<error-list>]

<error-obj-list>::=<PCEP-ERROR>[<error-obj-list>]

<error>::=[<request-id-list> | <stateful-request-id-list>]
           <error-obj-list>

<request-id-list>::=<RP>[<request-id-list>]

<stateful-request-id-list>::=<SRP>[<stateful-request-id-list>]

<error-list>::=<error>[<error-list>]
```
Message Type: 0x06

### Close Message
#### Message Format
format ([RFC5440 6.8](https://datatracker.ietf.org/doc/html/rfc5440#section-6.8))
```
<Close Message>::= <Common Header>
                   <CLOSE>
```
Message Type: 0x07

### PCRpt Message
#### Message Format
format ([RFC8231 6.1](https://datatracker.ietf.org/doc/html/rfc8231#section-6.1))
```
The format of the PCRpt message is as follows:

   <PCRpt Message> ::= <Common Header>
                       <state-report-list>
Where:

   <state-report-list> ::= <state-report>[<state-report-list>]

   <state-report> ::= [<SRP>]
                      <LSP>
                      <path>
Where:
   <path>::= <intended-path>
             [<actual-attribute-list><actual-path>]
             <intended-attribute-list>

   <actual-attribute-list>::=[<BANDWIDTH>]
                             [<metric-list>]

Where:
   <intended-path> is represented by the ERO object defined in
   Section 7.9 of [RFC5440].

   <actual-attribute-list> consists of the actual computed and
   signaled values of the <BANDWIDTH> and <metric-lists> objects
   defined in [RFC5440].

   <actual-path> is represented by the RRO object defined in
   Section 7.10 of [RFC5440].

  <intended-attribute-list> is the attribute-list defined in
  Section 6.5 of [RFC5440] and extended by PCEP extensions.
```
Message Type: 0x0a

### PCUpdate Message
#### Message Format
format ([RFC8231 6.2](https://datatracker.ietf.org/doc/html/rfc8231#section-6.2))
```
The format of a PCUpd message is as follows:

   <PCUpd Message> ::= <Common Header>
                       <update-request-list>
Where:

   <update-request-list> ::= <update-request>[<update-request-list>]

   <update-request> ::= <SRP>
                        <LSP>
                        <path>
Where:
   <path>::= <intended-path><intended-attribute-list>

Where:
   <intended-path> is represented by the ERO object defined in
   Section 7.9 of [RFC5440].

   <intended-attribute-list> is the attribute-list defined in
   [RFC5440] and extended by PCEP extensions.
```
Message Type: 0x0a

## Common Object Header
### Header Format
Format ([RFC5440 Figure 8: PCEP Common Object Header](https://datatracker.ietf.org/doc/html/rfc5440#section-6.1))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Object-Class  |   OT  |Res|P|I|   Object Length (bytes)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
//                        (Object body)                        //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type CommonObjectHeader struct { // RFC5440 7.2
	ObjectClass  uint8
	ObjectType   uint8
	ResFlags     uint8 // MUST be set to zero
	PFlag        bool  // 0: optional, 1: MUST
	IFlag        bool  // 0: processed, 1: ignored
	ObjectLength uint16
}
```

### Fields
Object-Class:  identifies the PCEP object class.
```
const ( // PCEP Object-Class (1 byte)
	OC_RESERVED       uint8 = 0x00 // RFC5440
	OC_OPEN           uint8 = 0x01 // RFC5440
	OC_RP             uint8 = 0x02 // RFC5440
	OC_NO_PATH        uint8 = 0x03 // RFC5440
	OC_END_POINTS     uint8 = 0x04 // RFC5440
	OC_BANDWIDTH      uint8 = 0x05 // RFC5440
	OC_METRIC         uint8 = 0x06 // RFC5440
	OC_ERO            uint8 = 0x07 // RFC5440
	OC_RRO            uint8 = 0x08 // RFC5440
	OC_LSPA           uint8 = 0x09 // RFC5440
	OC_IRO            uint8 = 0x0a // RFC5440
	OC_SVRC           uint8 = 0x0b // RFC5440
	OC_NOTIFICATION   uint8 = 0x0c // RFC5440
	OC_PCEP_ERROR     uint8 = 0x0d // RFC5440
	OC_LOAD_BALANCING uint8 = 0x0e // RFC5440
	OC_CLOSE          uint8 = 0x0f // RFC5440
	OC_PATH_KEY       uint8 = 0x10 // RFC5520
	OC_XRO            uint8 = 0x11 // RFC5521
	// 0x12 is Unassigned
	OC_MONITORING uint8 = 0x13 // RFC5886
	OC_PCC_REQ_ID uint8 = 0x14 // RFC5886
	OC_OF         uint8 = 0x15 // RFC5541
	OC_CLASSTYPE  uint8 = 0x16 // RFC5455
	// 0x17 is Unassigned
	OC_GLOBAL_CONSTRAINTS  uint8 = 0x18 // RFC5557
	OC_PCE_ID              uint8 = 0x19 // RFC5886
	OC_PROC_TIME           uint8 = 0x1a // RFC5886
	OC_OVERLOAD            uint8 = 0x1b // RFC5886
	OC_UNREACH_DESTINATION uint8 = 0x1c // RFC8306
	OC_SERO                uint8 = 0x1d // RFC8306
	OC_SRRO                uint8 = 0x1e // RFC8306
	OC_BNC                 uint8 = 0x1f // RFC8306
	OC_LSP                 uint8 = 0x20 // RFC8231
	OC_SRP                 uint8 = 0x21 // RFC8231
	OC_VENDOR_INFORMATION  uint8 = 0x22 // RFC7470
	OC_BU                  uint8 = 0x23 // RFC8233
	OC_INTER_LAYER         uint8 = 0x24 // RFC8282
	OC_SWITCH_LAYER        uint8 = 0x25 // RFC8282
	OC_REQ_ADAP_CAP        uint8 = 0x26 // RFC8282
	OC_SERVER_INDICATION   uint8 = 0x27 // RFC8282
	OC_ASSOCIATION         uint8 = 0x28 // RFC8697
	OC_S2LS                uint8 = 0x29 // RFC8623
	OC_WA                  uint8 = 0x2a // RFC8780
	OC_FLOWSPEC            uint8 = 0x2b // draft-ietf-pce-pcep-flowspec-12
	OC_CCI_OBJECT_TYPE     uint8 = 0x2c // RFC9050
)
```

OT:  identifies the PCEP object type.

Res flags: Reserved field.  This field MUST be set to zero.

P flag (Processing-Rule)

I flag (Ignore)

Object Length: Specifies the total object length including the header, in bytes. The Object Length field MUST always be a multiple of 4, and at least 4. The maximum object content length is 65528 bytes.

## Objects
### OPEN Object
#### Common Object Header
- OPEN Object-Class: 0x01
- OPEN Object-Type: 0x01

#### Object Body Format
Format ([RFC5440 Figure 9: OPEN Object Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.3))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ver |   Flags |   Keepalive   |  DeadTimer    |      SID      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
//                       Optional TLVs                         //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type OpenObject struct {
	Version   uint8
	Flag      uint8
	Keepalive uint8
	Deadtime  uint8
	Sid       uint8
	Tlvs      []Tlv
}
```

Ver: 1

Flags: No flags are currently defined. (RFC5440)

Keepalive: Argument of NewOpenObject(sessionID uint8, keepalive uint8)

DeadTimer: keepalive * 4

SID (PCEP Session ID): Argument of NewOpenObject(sessionID uint8, keepalive uint8)

### ENDPOINT Object 
#### Common Object Header
- ENDPOINT Object-Class: 0x04
- ENDPOINT Object-Type:
    - 0x01: IPv4
    - 0x02: IPv6

#### Object Body Format
Format IPv4 Endpoint ([RFC5440 Figure 12: END-POINTS Object Body Format for IPv4](https://datatracker.ietf.org/doc/html/rfc5440#section-7.6))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Source IPv4 address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination IPv4 address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type EndpointsObject struct {
	ObjectType uint8 // IPv4: 1, IPv6: 2
	srcIPv4    []uint8
	dstIPv4    []uint8
}
```

Source IPv4 address

Destination IPv4 address

{{% alert title="Note" color="info" %}} 
IPv6 is not implimented

Format IPv6 Endpoint ([RFC5440 Figure 13: END-POINTS Object Body Format for IPv6](https://datatracker.ietf.org/doc/html/rfc5440#section-7.6))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                Source IPv6 address (16 bytes)                 |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Destination IPv6 address (16 bytes)              |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Source IPv6 address

Destination IPv6 address
{{% /alert %}}

### BANDWIDTH Object 
#### Common Object Header
- BANDWIDTH Object-Class: 0x05
- BANDWIDTH Object-Type: 
    - 0x01: Requested bandwidth
    - 0x02: Bandwidth of an existing TE LSP for which a reoptimization is requested.

#### Object Body Format
Format ([RFC5440 Figure 14: BANDWIDTH Object Body Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.7))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Bandwidth                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type BandwidthObject struct {
	Bandwidth uint32
}
```

Bandwidth:  The requested bandwidth is encoded in 32 bits in IEEE floating point format (see [IEEE.754.1985](https://ieeexplore.ieee.org/document/30711)),

### METRIC Object
#### Common Object Header
- METRIC Object-Class: 0x06
- METRIC Object-Type: 0x01

#### Object Body Format
Format ([RFC5440 Figure 15: METRIC Object Body Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.8))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Reserved             |    Flags  |C|B|       T       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          metric-value                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type MetricObject struct {
	CFlag       bool
	BFlag       bool
	MetricType  uint8
	MetricValue uint32
}
```

Reserved: This field MUST be set to zero on transmission and MUST be ignored on receipt.

Flags: Two flags are currently defined:
- C (Computed Metric): Unimplimented
- B (Bound): Unimplimented

### ERO (Explicit Route) Object
#### Common Object Header
- ERO Object-Class: 0x07
- ERO Object-Type: 0x01

This object is constructed from a series of sub-objects.

### SR-ERO Subobject
#### Object Body Format
Format ([RFC8664 Figure 2: SR-ERO Subobject Format](https://datatracker.ietf.org/doc/html/rfc8664#section-4.3.1))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|L|   Type=36   |     Length    |  NT   |     Flags     |F|S|C|M|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         SID (optional)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                   NAI (variable, optional)                  //
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type SrEroSubobject struct {
	LFlag         bool
	SubobjectType uint8
	Length        uint8
	NaiType       uint8
	FFlag         bool
	SFlag         bool
	CFlag         bool
	MFlag         bool
	Sid           uint32
	Nai           []uint8
}
```

The L-Flag: Indicates whether the subobject represents a loose hop in the LSP.

Type: Set to 36

NAI Type (NT):  Indicates the type and format of the NAI contained in the object body, if any is present.
- NT=0: The NAI is absent.
- NT=1: The NAI is an IPv4 node ID.
- NT=2: The NAI is an IPv6 node ID.
- NT=3: The NAI is an IPv4 adjacency.
- NT=4: The NAI is an IPv6 adjacency with global IPv6 addresses.
- NT=5: The NAI is an unnumbered adjacency with IPv4 node IDs.
- NT=6: The NAI is an IPv6 adjacency with link-local IPv6 addresses.

Flags: 
- F: false
- S: false
- C: false
- M: true (MPLS)

SID: The Segment Identifier, A 4-octet index defining the offset into an MPLS label spaceper [RFC8402]

NAI: The NAI associated with the SID.

### LSPA Object
#### Common Object Header
- LSPA Object-Class: 0x09
- LSPA Object-Type: 0x01

#### Object Body Format
Format ([RFC5440 Figure 16: LSPA Object Body Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.11))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Exclude-any                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Include-any                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Include-all                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Setup Prio   |  Holding Prio |     Flags   |L|   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
//                     Optional TLVs                           //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type LspaObject struct {
	ExcludeAny      uint32
	IncludeAny      uint32
	IncludeAll      uint32
	SetupPriority   uint8
	HoldingPriority uint8
	LFlag           bool
}
```

### PCEP-ERROR Object
#### Common Object Header
- PCEP-ERROR Object-Class: 0x0d
- PCEP-ERROR Object-Type: 0x01

#### Object Body Format
Format ([RFC5440 Figure 20: PCEP-ERROR Object Body Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.15))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Reserved    |      Flags    |   Error-Type  |  Error-value  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
//                     Optional TLVs                           //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

{{% alert title="Note" color="info" %}} 
PCEP-ERROR object body is not implimented
{{% /alert %}}

### CLOSE Objcet
#### Common Object Header
- CLOSE Object-Class: 0x0f
- CLOSE Object-Type: 0x01

#### Object Body Format
Format ([RFC5440 Figure 22: CLOSE Object Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.17))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Reserved             |      Flags    |    Reason     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
//                         Optional TLVs                       //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

{{% alert title="Note" color="info" %}} 
CLOSE object body is not implimented
{{% /alert %}}

### LSP Object
#### Common Object Header
- LSP Object-Class: 0x20
- LSP Object-Type: 0x01

#### Object Body Format
Format ([RFC8664 Figure 11: The LSP Object Format](https://datatracker.ietf.org/doc/html/rfc5440#section-7.3))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                PLSP-ID                |    Flag |  O  |A|R|S|D|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                        TLVs                                 //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type LspObject struct {
	Name    string
	SrcAddr net.IP
	DstAddr net.IP
	PlspId  uint32
	OFlag   uint8
	AFlag   bool
	RFlag   bool
	SFlag   bool
	DFlag   bool
	Tlvs    []Tlv
}
```

PLSP-ID: 

Flags:
- O (Operational)
  - 0   - DOWN:       not active.
  - 1   - UP:         signaled.
  - 2   - ACTIVE:     up and carrying traffic.
  - 3   - GOING-DOWN: LSP is being torn down, and resources are being
  - 4   - GOING-UP:   LSP is being signaled.
  - 5-7 - Reserved:   these values are reserved for future use. 
- A (Administrative)
- R (Remove)
- S (SYNC)
- D (Deligate) 

### SRP Object
#### Common Object Header
- SRP Object-Class: 0x21
- SRP Object-Type: 0x01

#### Object Body Format
Format ([RFC8231 Figure 10: The SRP Object Format ](https://datatracker.ietf.org/doc/html/rfc8231#section-7.2))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Flags                                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        SRP-ID-number                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
//                      Optional TLVs                          //
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type SrpObject struct {
	RFlag bool
	SrpId uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	Tlvs  []Tlv
}
```

Flags: None defined yet. 

SRP-ID-number: The values 0x00000000 and 0xFFFFFFFF are reserved. 

### VENDOR-INFORMATION Object
#### Common Object Header
- VENDOR_INFORMATION Object-Class: 0x22
- VENDOR_INFORMATION Object-Type: 0x01
- VENDOR-INFORMATION-TLV Type 7

#### Object Body Format
Format ([RFC7470 Figure 1: Format of the Vendor Information Object and TLV](https://datatracker.ietf.org/doc/html/rfc7470#section-4))
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Enterprise Number                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~                 Enterprise-Specific Information               ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Type
```go
type VendorInformationObject struct {
	ObjectType       uint8 // vendor specific constraints: 1
	EnterpriseNumber uint32
	Color            uint32
	Preference       uint32
}
```

To specify Color for IOS XR and FRRouting, the Pola PCE uses Cisco VENDOR-INFORMATION Object (Enterprise Number: 9).
```go
func NewVendorInformationObject(vendor string, color uint32, preference uint32) VendorInformationObject {
	vendorInformationObject := VendorInformationObject{ // for Cisco PCC
		ObjectType:       uint8(1),
		EnterpriseNumber: uint32(9),
		Color:            color,
		Preference:       preference,
	}
	return vendorInformationObject
}
```
