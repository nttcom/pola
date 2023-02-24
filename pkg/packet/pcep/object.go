// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/nttcom/pola/internal/pkg/table"
)

type PccType int

const (
	CISCO_LEGACY PccType = iota
	JUNIPER_LEGACY
	RFC_COMPLIANT
)

// Determine PCC type from capability
func DeterminePccType(caps []CapabilityInterface) (pccType PccType) {
	pccType = RFC_COMPLIANT
	for _, cap := range caps {
		if t, ok := cap.(*AssocTypeList); ok {
			for _, v := range t.AssocTypes {
				if v == AssocType(20) { // Cisco specific Assoc-Type
					pccType = CISCO_LEGACY
				} else if v == AssocType(65505) { // Juniper specific Assoc-Type
					pccType = JUNIPER_LEGACY
					break
				}
			}
		}
	}
	return
}

const COMMON_OBJECT_HEADER_LENGTH uint16 = 4

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
	OC_FLOWSPEC            uint8 = 0x2b // RFC9168
	OC_CCI_OBJECT_TYPE     uint8 = 0x2c // RFC9050
	OC_PATH_ATTRIB         uint8 = 0x2d // draft-ietf-pce-multipath-07
)

type CommonObjectHeader struct { // RFC5440 7.2
	ObjectClass  uint8
	ObjectType   uint8
	ResFlags     uint8 // MUST be set to zero
	PFlag        bool  // 0: optional, 1: MUST
	IFlag        bool  // 0: processed, 1: ignored
	ObjectLength uint16
}

func (h *CommonObjectHeader) DecodeFromBytes(objectHeader []uint8) error {
	h.ObjectClass = uint8(objectHeader[0])
	h.ObjectType = uint8(objectHeader[1] & 0xf0 >> 4)
	h.ResFlags = uint8(objectHeader[1] & 0x0c >> 2)
	h.PFlag = (objectHeader[1] & 0x02) != 0
	h.IFlag = (objectHeader[1] & 0x01) != 0
	h.ObjectLength = binary.BigEndian.Uint16(objectHeader[2:4])
	return nil
}

func (h *CommonObjectHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	buf = append(buf, h.ObjectClass)
	otFlags := uint8(h.ObjectType<<4 | h.ResFlags<<2)
	if h.PFlag {
		otFlags = otFlags | 0x02
	}
	if h.IFlag {
		otFlags = otFlags | 0x01
	}
	buf = append(buf, otFlags)
	objectLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(objectLength, h.ObjectLength)
	buf = append(buf, objectLength...)
	return buf
}

func NewCommonObjectHeader(objectClass uint8, objectType uint8, messageLength uint16) *CommonObjectHeader {
	h := &CommonObjectHeader{
		ObjectClass:  objectClass,
		ObjectType:   objectType,
		ResFlags:     uint8(0), // MUST be set to zero
		PFlag:        false,    // 0: optional, 1: MUST
		IFlag:        false,    // 0: processed, 1: ignored
		ObjectLength: messageLength,
	}
	return h
}

type optParams struct {
	pccType PccType
}

type Opt func(*optParams)

func VendorSpecific(pt PccType) Opt {
	return func(op *optParams) {
		op.pccType = pt
	}
}

// OPEN Object (RFC5440 7.3)
const (
	OT_OPEN_OPEN uint8 = 0x01
)

type OpenObject struct {
	Version   uint8
	Flag      uint8
	Keepalive uint8
	Deadtime  uint8
	Sid       uint8
	Caps      []CapabilityInterface
}

func (o *OpenObject) DecodeFromBytes(objectBody []uint8) error {
	o.Version = uint8(objectBody[0] >> 5)
	o.Flag = uint8(objectBody[0] & 0x1f)
	o.Keepalive = uint8(objectBody[1])
	o.Deadtime = uint8(objectBody[2])
	o.Sid = uint8(objectBody[3])

	tlvs, err := DecodeTLVs(objectBody[4:])
	if err != nil {
		return err
	}
	for _, t := range tlvs {
		if c, ok := t.(CapabilityInterface); ok {
			o.Caps = append(o.Caps, c)
		}
	}
	return nil
}

func (o *OpenObject) Serialize() []uint8 {
	openObjectHeader := NewCommonObjectHeader(OC_OPEN, 1, o.getByteLength())
	byteOpenObjectHeader := openObjectHeader.Serialize()
	buf := make([]uint8, 4)
	buf[0] = o.Version << 5
	buf[1] = o.Keepalive
	buf[2] = o.Deadtime
	buf[3] = o.Sid

	byteTlvs := []uint8{}
	for _, cap := range o.Caps {
		byteTlvs = append(byteTlvs, cap.Serialize()...)
	}

	byteOpenObject := AppendByteSlices(byteOpenObjectHeader, buf, byteTlvs)
	return byteOpenObject
}

func (o *OpenObject) getByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, cap := range o.Caps {
		tlvsByteLength += cap.GetByteLength()
	}
	// TODO: Calculate TLV length and record in open_object_length
	// CommonObjectHeader(4byte) + openObject(4byte) + tlvslength(valiable)
	return COMMON_OBJECT_HEADER_LENGTH + 4 + tlvsByteLength
}

func NewOpenObject(sessionID uint8, keepalive uint8, capabilities []CapabilityInterface) (*OpenObject, error) {
	o := &OpenObject{
		Version:   uint8(1), // PCEP version. Current version is 1
		Flag:      uint8(0),
		Keepalive: keepalive,
		Deadtime:  keepalive * 4,
		Sid:       sessionID,
		Caps:      capabilities,
	}
	return o, nil
}

// BANDWIDTH Object (RFC5440 7.7)
type BandwidthObject struct {
	Bandwidth uint32
}

func (o *BandwidthObject) DecodeFromBytes(objectBody []uint8) error {
	o.Bandwidth = binary.BigEndian.Uint32(objectBody[:])
	return nil
}

// METRIC Object (RFC5440 7.8)
type MetricObject struct {
	CFlag       bool
	BFlag       bool
	MetricType  uint8
	MetricValue uint32
}

func (o *MetricObject) DecodeFromBytes(objectBody []uint8) error {
	o.CFlag = (objectBody[2] & 0x02) != 0
	o.BFlag = (objectBody[2] & 0x01) != 0
	o.MetricType = objectBody[3]
	o.MetricValue = binary.BigEndian.Uint32(objectBody[4:8])
	return nil
}

func (o *MetricObject) Serialize() []uint8 {
	buf := make([]uint8, 8)
	if o.CFlag {
		buf[2] = buf[2] | 0x02
	}
	if o.BFlag {
		buf[2] = buf[2] | 0x01
	}
	buf[3] = o.MetricType
	binary.BigEndian.PutUint32(buf[4:8], o.MetricValue)
	return buf
}

// LSPA Object (RFC5440 7.11)
type LspaObject struct {
	ExcludeAny      uint32
	IncludeAny      uint32
	IncludeAll      uint32
	SetupPriority   uint8
	HoldingPriority uint8
	LFlag           bool
}

func (o *LspaObject) DecodeFromBytes(objectBody []uint8) error {
	o.ExcludeAny = binary.BigEndian.Uint32(objectBody[0:4])
	o.IncludeAny = binary.BigEndian.Uint32(objectBody[4:8])
	o.IncludeAll = binary.BigEndian.Uint32(objectBody[8:12])
	o.SetupPriority = objectBody[12]
	o.HoldingPriority = objectBody[13]
	o.LFlag = (objectBody[14] & 0x01) != 0
	return nil
}

func (o *LspaObject) Serialize() []uint8 {
	buf := make([]uint8, 16)
	binary.BigEndian.PutUint32(buf[0:4], o.ExcludeAny)
	binary.BigEndian.PutUint32(buf[4:8], o.IncludeAny)
	binary.BigEndian.PutUint32(buf[8:12], o.IncludeAll)
	buf[12] = o.SetupPriority
	buf[13] = o.HoldingPriority
	if o.LFlag {
		buf[14] = buf[14] | 0x01
	}
	return buf
}

// SRP Object (RFC8231 7.2)
const (
	OT_SRP_SRP uint8 = 0x01
)

type SrpObject struct {
	RFlag bool
	SrpId uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	Tlvs  []TlvInterface
}

func (o *SrpObject) DecodeFromBytes(objectBody []uint8) error {
	o.RFlag = (objectBody[3] & 0x01) != 0
	o.SrpId = binary.BigEndian.Uint32(objectBody[4:8])
	return nil
}

func (o *SrpObject) Serialize() []uint8 {
	srpObjectHeader := NewCommonObjectHeader(OC_SRP, 1, o.getByteLength())
	byteSrpObjectHeader := srpObjectHeader.Serialize()

	byteFlags := make([]uint8, 4)
	if o.RFlag {
		byteFlags[3] = byteFlags[3] | 0x01
	}
	byteSrpId := make([]uint8, 4)
	binary.BigEndian.PutUint32(byteSrpId, o.SrpId)

	byteTlvs := []uint8{}
	for _, tlv := range o.Tlvs {
		byteTlvs = append(byteTlvs, tlv.Serialize()...)
	}
	byteSrpObject := AppendByteSlices(byteSrpObjectHeader, byteFlags, byteSrpId, byteTlvs)
	return byteSrpObject
}

func (o *SrpObject) getByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.GetByteLength()
	}
	// CommonObjectHeader(4byte) + Flags, SRP-ID(8byte)
	return COMMON_OBJECT_HEADER_LENGTH + 8 + tlvsByteLength
}

func NewSrpObject(segs []table.Segment, srpId uint32, isRemove bool) (*SrpObject, error) {
	var o *SrpObject
	if _, ok := segs[0].(table.SegmentSRMPLS); ok {
		o = &SrpObject{
			RFlag: isRemove, // RFC8281 5.2
			SrpId: srpId,
			Tlvs: []TlvInterface{
				&PathSetupType{
					PathSetupType: PST_SR_TE,
				},
			},
		}
	} else if _, ok := segs[0].(table.SegmentSRv6); ok {
		o = &SrpObject{
			RFlag: isRemove, // RFC8281 5.2
			SrpId: srpId,
			Tlvs: []TlvInterface{
				&PathSetupType{
					PathSetupType: PST_SRV6_TE,
				},
			},
		}
	} else {
		return nil, errors.New("invalid Segment type")
	}
	return o, nil
}

// LSP Object (RFC8281 5.3.1)
const (
	OT_LSP_LSP uint8 = 0x01
)

type LspObject struct {
	Name    string
	SrcAddr netip.Addr
	DstAddr netip.Addr
	PlspId  uint32
	OFlag   uint8
	AFlag   bool
	RFlag   bool
	SFlag   bool
	DFlag   bool
	Tlvs    []TlvInterface
}

func (o *LspObject) DecodeFromBytes(objectBody []uint8) error {
	o.PlspId = uint32(binary.BigEndian.Uint32(objectBody[0:4]) >> 12) // 20 bits from top
	o.OFlag = uint8(objectBody[3] & 0x0070 >> 4)
	o.AFlag = (objectBody[3] & 0x08) != 0
	o.RFlag = (objectBody[3] & 0x04) != 0
	o.SFlag = (objectBody[3] & 0x02) != 0
	o.DFlag = (objectBody[3] & 0x01) != 0
	if len(objectBody) > 4 {
		byteTlvs := objectBody[4:]

		var err error
		if o.Tlvs, err = DecodeTLVs(byteTlvs); err != nil {
			return err
		}
		for _, tlv := range o.Tlvs {

			if t, ok := tlv.(*SymbolicPathName); ok {
				o.Name = t.Name
			}
			if t, ok := tlv.(*IPv4LspIdentifiers); ok {
				o.SrcAddr = t.IPv4TunnelSenderAddress
				o.DstAddr = t.IPv4TunnelEndpointAddress
			}
			if t, ok := tlv.(*IPv6LspIdentifiers); ok {
				o.SrcAddr = t.IPv6TunnelSenderAddress
				o.DstAddr = t.IPv6TunnelEndpointAddress
			}
		}
	}
	return nil
}

func (o *LspObject) Serialize() []uint8 {
	lspObjectHeader := NewCommonObjectHeader(OC_LSP, 1, o.getByteLength())
	byteLspObjectHeader := lspObjectHeader.Serialize()

	buf := make([]uint8, 4)
	binary.BigEndian.PutUint32(buf, uint32(o.PlspId<<12)+uint32(o.OFlag<<4))
	if o.AFlag {
		buf[3] = buf[3] | 0x08
	}
	if o.RFlag {
		buf[3] = buf[3] | 0x04
	}
	if o.SFlag {
		buf[3] = buf[3] | 0x02
	}
	if o.DFlag {
		buf[3] = buf[3] | 0x01
	}
	byteTlvs := []uint8{}
	for _, tlv := range o.Tlvs {
		byteTlvs = tlv.Serialize()
	}

	byteLspObject := AppendByteSlices(byteLspObjectHeader, buf, byteTlvs)
	return byteLspObject
}

func (o *LspObject) getByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.GetByteLength()
	}
	// Flags, SRP-ID (4byte)
	lspObjectBodyLength := uint16(4) + tlvsByteLength
	// CommonObjectHeader(4byte) + Flags, SRP-ID
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + lspObjectBodyLength
}

func NewLspObject(lspName string, plspId uint32) (*LspObject, error) {
	o := &LspObject{
		Name:   lspName,
		PlspId: plspId,
		OFlag:  uint8(1), // UP (RFC8231 7.3)
		AFlag:  true,     // desired operational state is active (RFC8231 7.3)
		RFlag:  false,    // TODO: Allow setting from function arguments
		SFlag:  false,
		DFlag:  true,
		Tlvs:   []TlvInterface{},
	}
	symbolicPathNameTlv := &SymbolicPathName{
		Name: lspName,
	}
	o.Tlvs = append(o.Tlvs, TlvInterface(symbolicPathNameTlv))
	return o, nil
}

// ERO Object (RFC5440 7.9)
const (
	OT_ERO_EXPLICIT_ROUTE uint8 = 0x01
)

type EroObject struct {
	EroSubobjects []EroSubobject
}

func (o *EroObject) DecodeFromBytes(objectBody []uint8) error {
	if len(objectBody) == 0 {
		return nil
	}
	for {
		var eroSubobj EroSubobject
		if (objectBody[0] & 0x7f) == 36 {
			eroSubobj = &SREroSubobject{}
		} else if (objectBody[0] & 0x7f) == 40 {
			eroSubobj = &SRv6EroSubobject{}
		} else {
			return errors.New("invalid Subobject type")
		}
		if err := eroSubobj.DecodeFromBytes(objectBody); err != nil {
			return err
		}
		o.EroSubobjects = append(o.EroSubobjects, eroSubobj)
		if objByteLength, err := eroSubobj.getByteLength(); err != nil {
			return err
		} else if int(objByteLength) < len(objectBody) {
			objectBody = objectBody[objByteLength:]
		} else if int(objByteLength) == len(objectBody) {
			break
		} else {
			return errors.New("srerosubobject parse error")
		}
	}
	return nil
}

func (o EroObject) Serialize() ([]uint8, error) {
	eroObjectLength, err := o.getByteLength()
	if err != nil {
		return nil, err
	}
	eroObjectHeader := NewCommonObjectHeader(OC_ERO, OT_ERO_EXPLICIT_ROUTE, eroObjectLength)
	byteEroObjectHeader := eroObjectHeader.Serialize()

	byteEroObject := byteEroObjectHeader
	for _, eroSubobject := range o.EroSubobjects {
		buf := eroSubobject.Serialize()
		byteEroObject = append(byteEroObject, buf...)
	}
	return byteEroObject, nil
}

func (o EroObject) getByteLength() (uint16, error) {
	eroSubobjByteLength := uint16(0)
	for _, eroSubObj := range o.EroSubobjects {
		objByteLength, err := eroSubObj.getByteLength()
		if err != nil {
			return 0, err
		}
		eroSubobjByteLength += objByteLength
	}
	// CommonObjectHeader(4byte) + eroSubobjects(valiable)
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + eroSubobjByteLength, nil
}

func NewEroObject(segmentList []table.Segment) (*EroObject, error) {
	o := &EroObject{
		EroSubobjects: []EroSubobject{},
	}
	err := o.AddEroSubobjects(segmentList)

	if err != nil {
		return o, err
	}
	return o, nil
}

func (o *EroObject) AddEroSubobjects(SegmentList []table.Segment) error {
	for _, seg := range SegmentList {
		eroSubobject, err := NewEroSubobject(seg)
		if err != nil {
			return err
		}

		o.EroSubobjects = append(o.EroSubobjects, eroSubobject)
	}

	return nil
}

func (o *EroObject) ToSegmentList() []table.Segment {
	sl := []table.Segment{}
	for _, so := range o.EroSubobjects {
		sl = append(sl, so.ToSegment())
	}
	return sl
}

type EroSubobject interface {
	DecodeFromBytes([]uint8) error
	getByteLength() (uint16, error)
	Serialize() []uint8
	ToSegment() table.Segment
}

func NewEroSubobject(seg table.Segment) (EroSubobject, error) {
	if v, ok := seg.(table.SegmentSRMPLS); ok {
		subo, err := NewSREroSubObject(v)
		if err != nil {
			return nil, err
		}
		return subo, nil
	} else if v, ok := seg.(table.SegmentSRv6); ok {
		subo, err := NewSRv6EroSubObject(v)
		if err != nil {
			return nil, err
		}
		return subo, nil
	} else {
		return nil, errors.New("invalid Segment type")
	}
}

// SR-ERO Subobject (RFC8664 4.3.1)
const ERO_SUBOBJECT_SR uint8 = 0x24
const (
	NT_ABSENT                   uint8 = 0x00 // RFC 8664 4.3.1
	NT_IPV4_NODE                uint8 = 0x01 // RFC 8664 4.3.1
	NT_IPV6_NODE                uint8 = 0x02 // RFC 8664 4.3.1
	NT_IPV4_ADJACENCY           uint8 = 0x03 // RFC 8664 4.3.1
	NT_IPV6_ADJACENCY_GLOBAL    uint8 = 0x04 // RFC 8664 4.3.1
	NT_UNNUMBERED_ADJACENCY     uint8 = 0x05 // RFC 8664 4.3.1
	NT_IPV6_ADJACENCY_LINKLOCAL uint8 = 0x06 // RFC 8664 4.3.1
)

type SREroSubobject struct {
	LFlag         bool
	SubobjectType uint8
	Length        uint8
	NaiType       uint8
	FFlag         bool
	SFlag         bool
	CFlag         bool
	MFlag         bool
	Segment       table.SegmentSRMPLS
	Nai           netip.Addr
}

func (o *SREroSubobject) DecodeFromBytes(subObj []uint8) error {
	o.LFlag = (subObj[0] & 0x80) != 0
	o.SubobjectType = subObj[0] & 0x7f
	o.Length = subObj[1]
	o.NaiType = subObj[2] >> 4
	o.FFlag = (subObj[3] & 0x08) != 0
	o.SFlag = (subObj[3] & 0x04) != 0
	o.CFlag = (subObj[3] & 0x02) != 0
	o.MFlag = (subObj[3] & 0x01) != 0

	sid := binary.BigEndian.Uint32(subObj[4:8]) >> 12
	o.Segment = table.NewSegmentSRMPLS(sid)
	if o.NaiType == 1 {
		o.Nai, _ = netip.AddrFromSlice(subObj[8:12])
	}
	return nil
}

func (o *SREroSubobject) Serialize() []uint8 {
	buf := make([]uint8, 4)
	buf[0] = o.SubobjectType
	if o.LFlag {
		buf[0] = buf[0] | 0x80
	}
	buf[1] = o.Length
	buf[2] = o.NaiType * 16
	if o.FFlag {
		buf[3] = buf[3] | 0x08
	}
	if o.SFlag {
		buf[3] = buf[3] | 0x04
	}
	if o.CFlag {
		buf[3] = buf[3] | 0x02
	}
	if o.MFlag {
		buf[3] = buf[3] | 0x01
	}
	byteSid := make([]uint8, 4)
	binary.BigEndian.PutUint32(byteSid, o.Segment.Sid<<12)

	byteSREroSubobject := AppendByteSlices(buf, byteSid)
	return byteSREroSubobject
}

func (o *SREroSubobject) getByteLength() (uint16, error) {
	if o.NaiType == NT_ABSENT {
		// Type, Length, Flags (4byte) + SID (4byte)
		return uint16(8), nil
	} else if o.NaiType == NT_IPV4_NODE {
		// Type, Length, Flags (4byte) + SID (4byte) + Nai (4byte)
		return uint16(12), nil
	} else if o.NaiType == NT_IPV6_NODE {
		// Type, Length, Flags (4byte) + SID (4byte) + Nai (16byte)
		return uint16(24), nil
	} else {
		return uint16(0), errors.New("unsupported naitype")
	}
}

func NewSREroSubObject(seg table.SegmentSRMPLS) (*SREroSubobject, error) {
	subo := &SREroSubobject{
		LFlag:         false,
		SubobjectType: ERO_SUBOBJECT_SR,
		NaiType:       NT_ABSENT,
		FFlag:         true, // Nai is absent
		SFlag:         false,
		CFlag:         false,
		MFlag:         true, // TODO: Determine either MPLS label or index
		Segment:       seg,
	}
	length, err := subo.getByteLength()
	if err != nil {
		return subo, err
	}
	subo.Length = uint8(length)
	return subo, nil
}

func (o *SREroSubobject) ToSegment() table.Segment {
	return o.Segment
}

// SRv6-ERO Subobject (draft-ietf-pce-segment-routing-ipv6 4.3.1)
const ERO_SUBOBJECT_SRV6 uint8 = 0x28
const (
	NT_MUST_NOT_BE_INCLUDED     uint8 = 0x00 // draft-ietf-pce-segment-routing-ipv6 4.3.1
	NT_SRV6_NODE                uint8 = 0x02 // draft-ietf-pce-segment-routing-ipv6 4.3.1
	NT_SRV6_ADJACENCY_GLOBAL    uint8 = 0x04 // draft-ietf-pce-segment-routing-ipv6 4.3.1
	NT_SRV6_ADJACENCY_LINKLOCAL uint8 = 0x06 // draft-ietf-pce-segment-routing-ipv6 4.3.1
)

type SRv6EroSubobject struct {
	LFlag         bool
	SubobjectType uint8
	Length        uint8
	NaiType       uint8
	VFlag         bool
	TFlag         bool
	FFlag         bool
	SFlag         bool
	Behavior      uint16
	Segment       table.SegmentSRv6
	Nai           netip.Addr
}

func (o *SRv6EroSubobject) DecodeFromBytes(subObj []uint8) error {
	o.LFlag = (subObj[0] & 0x80) != 0
	o.SubobjectType = subObj[0] & 0x7f
	o.Length = subObj[1]
	o.NaiType = subObj[2] >> 4
	o.VFlag = (subObj[3] & 0x08) != 0
	o.TFlag = (subObj[3] & 0x04) != 0
	o.FFlag = (subObj[3] & 0x02) != 0
	o.SFlag = (subObj[3] & 0x01) != 0
	o.Behavior = binary.BigEndian.Uint16(subObj[6:8])

	sid, _ := netip.AddrFromSlice(subObj[8:24])
	o.Segment = table.NewSegmentSRv6(sid)
	if o.NaiType == 2 {
		o.Nai, _ = netip.AddrFromSlice(subObj[24:40])
	}
	return nil
}

func (o *SRv6EroSubobject) Serialize() []uint8 {
	buf := make([]uint8, 4)
	buf[0] = o.SubobjectType
	if o.LFlag {
		buf[0] = buf[0] | 0x80
	}
	buf[1] = o.Length
	buf[2] = o.NaiType * 16
	if o.VFlag {
		buf[3] = buf[3] | 0x08
	}
	if o.TFlag {
		buf[3] = buf[3] | 0x04
	}
	if o.FFlag {
		buf[3] = buf[3] | 0x02
	}
	if o.SFlag {
		buf[3] = buf[3] | 0x01
	}
	reserved := make([]uint8, 2)
	behavior := make([]uint8, 2)
	binary.BigEndian.PutUint16(behavior, o.Behavior)
	byteSid := o.Segment.Sid.AsSlice()
	byteSRv6EroSubobject := AppendByteSlices(buf, reserved, behavior, byteSid)
	return byteSRv6EroSubobject
}

func (o *SRv6EroSubobject) getByteLength() (uint16, error) {
	// The Length MUST be at least 24, and MUST be a multiple of 4.
	// An SRv6-ERO subobject MUST contain at least one of a SRv6-SID or an NAI.
	if o.NaiType == NT_MUST_NOT_BE_INCLUDED {
		// Type, Length, Flags (4byte) + Reserved(2byte) + Behavior(2byte) + SID (16byte)
		return uint16(24), nil
	} else if o.NaiType == NT_IPV6_NODE {
		// Type, Length, Flags (4byte) + Reserved(2byte) + Behavior(2byte) + SID (16byte) + Nai (16byte)
		return uint16(40), nil
	} else {
		return uint16(0), errors.New("unsupported naitype")
	}
}

func NewSRv6EroSubObject(seg table.SegmentSRv6) (*SRv6EroSubobject, error) {
	subo := &SRv6EroSubobject{
		LFlag:         false,
		SubobjectType: ERO_SUBOBJECT_SRV6,
		NaiType:       NT_MUST_NOT_BE_INCLUDED,
		VFlag:         false,
		TFlag:         false,
		FFlag:         true,
		SFlag:         false,
		Behavior:      uint16(1),
		Segment:       seg,
	}
	length, err := subo.getByteLength()
	if err != nil {
		return subo, err
	}
	subo.Length = uint8(length)
	return subo, nil
}

func (o *SRv6EroSubobject) ToSegment() table.Segment {
	return o.Segment
}

// END-POINTS Object (RFC5440 7.6)
const (
	OT_EP_IPV4 uint8 = 1
	OT_EP_IPV6 uint8 = 2
)

type EndpointsObject struct {
	ObjectType uint8
	SrcAddr    netip.Addr
	DstAddr    netip.Addr
}

func (o EndpointsObject) Serialize() ([]uint8, error) {
	var endpointsObjectHeader *CommonObjectHeader
	endpointsObjectLength, err := o.getByteLength()
	if err != nil {
		return nil, err
	}
	if o.SrcAddr.Is4() && o.DstAddr.Is4() {
		endpointsObjectHeader = NewCommonObjectHeader(OC_END_POINTS, OT_EP_IPV4, endpointsObjectLength)
	} else if o.SrcAddr.Is6() && o.DstAddr.Is6() {
		endpointsObjectHeader = NewCommonObjectHeader(OC_END_POINTS, OT_EP_IPV6, endpointsObjectLength)
	} else {
		return nil, errors.New("invalid endpoints address")
	}
	byteEroObjectHeader := endpointsObjectHeader.Serialize()
	byteEndpointsObject := AppendByteSlices(byteEroObjectHeader, o.SrcAddr.AsSlice(), o.DstAddr.AsSlice())
	return byteEndpointsObject, nil
}

func (o EndpointsObject) getByteLength() (uint16, error) {
	var length uint16
	if o.SrcAddr.Is4() && o.DstAddr.Is4() {
		// CommonObjectHeader(4byte) + srcIPv4 (4byte) + dstIPv4 (4byte)
		length = COMMON_OBJECT_HEADER_LENGTH + 4 + 4
	} else if o.SrcAddr.Is6() && o.DstAddr.Is6() {
		// CommonObjectHeader(4byte) + srcIPv4 (16byte) + dstIPv4 (16byte)
		length = COMMON_OBJECT_HEADER_LENGTH + 16 + 16
	} else {
		return uint16(0), errors.New("invalid endpoints address")
	}
	return length, nil
}

func NewEndpointsObject(dstAddr netip.Addr, srcAddr netip.Addr) (*EndpointsObject, error) {
	var objType uint8
	if dstAddr.Is4() && srcAddr.Is4() {
		objType = OT_EP_IPV4
	} else if dstAddr.Is6() && srcAddr.Is6() {
		objType = OT_EP_IPV6
	} else {
		return nil, errors.New("invalid endpoints address")
	}

	o := &EndpointsObject{
		ObjectType: objType,
		DstAddr:    dstAddr,
		SrcAddr:    srcAddr,
	}
	return o, nil
}

// ASSOCIATION Object (RFC8697 6.)
const (
	OT_ASSOC_IPV4 uint8 = 1
	OT_ASSOC_IPV6 uint8 = 2
)

const (
	ASSOC_TYPE_SR_POLICY_ASSOCIATION uint16 = 0x06
)

// Juniper specific TLV (deprecated)
const (
	JUNIPER_SPEC_TLV_EXTENDED_ASSOCIATION_ID   uint16 = 65507
	JUNIPER_SPEC_TLV_SRPOLICY_CPATH_ID         uint16 = 65508
	JUNIPER_SPEC_TLV_SRPOLICY_CPATH_PREFERENCE uint16 = 65509

	JUNIPER_SPEC_ASSOC_TYPE_SR_POLICY_ASSOCIATION uint16 = 65505
)

type AssociationObject struct {
	RFlag     bool
	AssocType uint16
	AssocId   uint16
	AssocSrc  netip.Addr
	Tlvs      []TlvInterface
}

func (o *AssociationObject) DecodeFromBytes(objectBody []uint8) error {
	o.RFlag = (objectBody[3] & 0x01) != 0
	o.AssocType = uint16(binary.BigEndian.Uint16(objectBody[4:6]))
	o.AssocId = uint16(binary.BigEndian.Uint16(objectBody[6:8]))
	assocSrcBytes, _ := netip.AddrFromSlice(objectBody[8:12])
	if assocSrcBytes.Is4() && assocSrcBytes.IsValid() {
		o.AssocSrc = assocSrcBytes
	} else if assocSrcBytes.Is6() && assocSrcBytes.IsValid() {
		o.AssocSrc, _ = netip.AddrFromSlice(objectBody[8:24])
	} else {
		return errors.New("invalid association source address")
	}
	if len(objectBody) > 24 {
		byteTlvs := objectBody[24:]
		var err error
		if o.Tlvs, err = DecodeTLVs(byteTlvs); err != nil {
			return err
		}
	}
	return nil
}

func (o AssociationObject) Serialize() ([]uint8, error) {
	var associationObjectHeader *CommonObjectHeader
	associationObjectLength, err := o.getByteLength()
	if err != nil {
		return nil, err
	}
	if o.AssocSrc.Is4() {
		associationObjectHeader = NewCommonObjectHeader(OC_ASSOCIATION, OT_ASSOC_IPV4, associationObjectLength)
	} else if o.AssocSrc.Is6() {
		associationObjectHeader = NewCommonObjectHeader(OC_ASSOCIATION, OT_ASSOC_IPV6, associationObjectLength)
	} else {
		return nil, errors.New("invalid association source address")
	}

	byteAssociationObjectHeader := associationObjectHeader.Serialize()

	buf := make([]uint8, 4)

	if o.RFlag {
		buf[4] = buf[4] | 0x01
	}

	assocType := Uint16ToByteSlice(o.AssocType)
	assocId := Uint16ToByteSlice(o.AssocId)

	byteTlvs := []uint8{}
	for _, tlv := range o.Tlvs {
		byteTlvs = append(byteTlvs, tlv.Serialize()...)
	}

	byteAssociationObject := AppendByteSlices(
		byteAssociationObjectHeader, buf, assocType, assocId, o.AssocSrc.AsSlice(), byteTlvs,
	)
	return byteAssociationObject, nil
}

func (o AssociationObject) getByteLength() (uint16, error) {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.GetByteLength()
	}
	var associationObjectBodyLength uint16
	if o.AssocSrc.Is4() {
		// Reserved(2byte) + Flags(2byte) + Assoc Type(2byte) + Assoc ID(2byte) + IPv4 Assoc Src(4byte)
		associationObjectBodyLength = uint16(12) + tlvsByteLength
	} else if o.AssocSrc.Is6() {
		// Reserved(2byte) + Flags(2byte) + Assoc Type(2byte) + Assoc ID(2byte) + IPv6 Assoc Src(16byte)
		associationObjectBodyLength = uint16(24) + tlvsByteLength
	} else {
		return uint16(0), errors.New("invalid association source address")
	}
	return (COMMON_OBJECT_HEADER_LENGTH + associationObjectBodyLength), nil
}

func NewAssociationObject(srcAddr netip.Addr, dstAddr netip.Addr, color uint32, preference uint32, opt ...Opt) (*AssociationObject, error) {
	opts := optParams{
		pccType: RFC_COMPLIANT,
	}

	for _, o := range opt {
		o(&opts)
	}

	o := &AssociationObject{
		RFlag:    false,
		Tlvs:     []TlvInterface{},
		AssocSrc: srcAddr,
	}
	if opts.pccType == JUNIPER_LEGACY {
		o.AssocId = 0
		o.AssocType = JUNIPER_SPEC_ASSOC_TYPE_SR_POLICY_ASSOCIATION
		associationObjectTLVs := []TlvInterface{
			&UndefinedTlv{
				Typ:    JUNIPER_SPEC_TLV_EXTENDED_ASSOCIATION_ID,
				Length: TLV_EXTENDED_ASSOCIATION_ID_IPV4_LENGTH, // JUNIPER_LEGACY has only IPv4 implementation
				Value: AppendByteSlices(
					Uint32ToByteSlice(color), dstAddr.AsSlice(),
				),
			},
			&UndefinedTlv{
				Typ:    JUNIPER_SPEC_TLV_SRPOLICY_CPATH_ID,
				Length: TLV_SRPOLICY_CPATH_ID_LENGTH,
				Value: []uint8{
					0x00,             // protocol origin
					0x00, 0x00, 0x00, // mbz
					0x00, 0x00, 0x00, 0x00, // Originator ASN
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originator Address
					0x00, 0x00, 0x00, 0x00, //discriminator
				},
			},
			&UndefinedTlv{
				Typ:    JUNIPER_SPEC_TLV_SRPOLICY_CPATH_PREFERENCE,
				Length: TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH,
				Value:  Uint32ToByteSlice(preference),
			},
		}
		o.Tlvs = append(o.Tlvs, associationObjectTLVs...)
	} else {
		o.AssocId = 1                                  // (I.D. pce-segment-routing-policy-cp-07 5.1)
		o.AssocType = ASSOC_TYPE_SR_POLICY_ASSOCIATION // (I.D. pce-segment-routing-policy-cp-07 5.1)
		var associationObjectTLVs []TlvInterface
		if srcAddr.Is4() {
			associationObjectTLVs = []TlvInterface{
				&UndefinedTlv{
					Typ:    TLV_EXTENDED_ASSOCIATION_ID,
					Length: TLV_EXTENDED_ASSOCIATION_ID_IPV4_LENGTH,
					Value: AppendByteSlices(
						Uint32ToByteSlice(color), dstAddr.AsSlice(),
					),
				},
				&UndefinedTlv{
					Typ:    TLV_SRPOLICY_CPATH_ID,
					Length: TLV_SRPOLICY_CPATH_ID_LENGTH,
					Value: []uint8{
						0x00,             // protocol origin
						0x00, 0x00, 0x00, // mbz
						0x00, 0x00, 0x00, 0x00, // Originator ASN
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originator Address
						0x00, 0x00, 0x00, 0x00, //discriminator
					},
				},
				&UndefinedTlv{
					Typ:    TLV_SRPOLICY_CPATH_PREFERENCE,
					Length: TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH,
					Value:  Uint32ToByteSlice(preference),
				},
			}
		} else if srcAddr.Is6() {
			associationObjectTLVs = []TlvInterface{
				&UndefinedTlv{
					Typ:    TLV_EXTENDED_ASSOCIATION_ID,
					Length: TLV_EXTENDED_ASSOCIATION_ID_IPV6_LENGTH,
					Value: AppendByteSlices(
						Uint32ToByteSlice(color), dstAddr.AsSlice(),
					),
				},
				&UndefinedTlv{
					Typ:    TLV_SRPOLICY_CPATH_ID,
					Length: TLV_SRPOLICY_CPATH_ID_LENGTH,
					Value: []uint8{
						0x00,             // protocol origin
						0x00, 0x00, 0x00, // mbz
						0x00, 0x00, 0x00, 0x00, // Originator ASN
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originator Address
						0x00, 0x00, 0x00, 0x00, //discriminator
					},
				},
				&UndefinedTlv{
					Typ:    TLV_SRPOLICY_CPATH_PREFERENCE,
					Length: TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH,
					Value:  Uint32ToByteSlice(preference),
				},
			}
		}
		o.Tlvs = append(o.Tlvs, associationObjectTLVs...)
	}

	return o, nil
}

// (I.D. pce-segment-routing-policy-cp-08 5.1)
func (o *AssociationObject) Color() uint32 {
	for _, tlv := range o.Tlvs {
		if t, ok := tlv.(*UndefinedTlv); ok {
			if t.Type() == TLV_EXTENDED_ASSOCIATION_ID {
				return uint32(binary.BigEndian.Uint32(t.Value[:4]))
			} else if t.Type() == JUNIPER_SPEC_TLV_EXTENDED_ASSOCIATION_ID {
				return uint32(binary.BigEndian.Uint32(t.Value[:4]))
			}
		}
	}
	return 0
}

// (I.D. pce-segment-routing-policy-cp-08 5.1)
func (o *AssociationObject) Preference() uint32 {
	for _, tlv := range o.Tlvs {
		if t, ok := tlv.(*UndefinedTlv); ok {
			if t.Type() == TLV_SRPOLICY_CPATH_PREFERENCE {
				return uint32(binary.BigEndian.Uint32(t.Value))
			} else if t.Type() == JUNIPER_SPEC_TLV_SRPOLICY_CPATH_PREFERENCE {
				return uint32(binary.BigEndian.Uint32(t.Value))
			}
		}
	}
	return 0
}

// VENDOR-INFORMATION Object (RFC7470 4)
const (
	EN_CISCO uint32 = 9

	CISCO_SPEC_TLV_COLOR      uint16 = 1
	CISCO_SPEC_TLV_PREFERENCE uint16 = 3

	CISCO_SPEC_TLV_COLOR_LENGTH      uint16 = 4
	CISCO_SPEC_TLV_PREFERENCE_LENGTH uint16 = 4
)

type VendorInformationObject struct {
	ObjectType       uint8 // vendor specific constraints: 1
	EnterpriseNumber uint32
	Tlvs             []TlvInterface
}

func (o *VendorInformationObject) DecodeFromBytes(objectBody []uint8) error {
	o.EnterpriseNumber = binary.BigEndian.Uint32(objectBody[0:4])
	if len(objectBody) > 4 {
		byteTlvs := objectBody[4:]
		var err error
		if o.Tlvs, err = DecodeTLVs(byteTlvs); err != nil {
			return err
		}

	}
	return nil
}

func (o *VendorInformationObject) Serialize() []uint8 {
	vendorInformationObjectHeader := NewCommonObjectHeader(OC_VENDOR_INFORMATION, 1, o.getByteLength())
	byteVendorInformationObjectHeader := vendorInformationObjectHeader.Serialize()

	enterpriseNumber := Uint32ToByteSlice(o.EnterpriseNumber)

	byteTlvs := []uint8{}
	for _, tlv := range o.Tlvs {
		byteTlvs = append(byteTlvs, tlv.Serialize()...)
	}

	byteVendorInformationObject := AppendByteSlices(
		byteVendorInformationObjectHeader, enterpriseNumber, byteTlvs,
	)
	return byteVendorInformationObject
}

func (o VendorInformationObject) getByteLength() uint16 {
	// TODO: Expantion for IPv6 Endpoint
	// CommonObjectHeader(4byte) + Enterprise Number (4byte) + colorTLV (8byte) + preferenceTLV (8byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH + 4 + 8 + 8)
}

func NewVendorInformationObject(vendor PccType, color uint32, preference uint32) (*VendorInformationObject, error) {
	var o *VendorInformationObject
	if vendor == CISCO_LEGACY {
		o = &VendorInformationObject{ // for Cisco PCC
			ObjectType:       uint8(1), // (RFC7470 4)
			EnterpriseNumber: EN_CISCO,
			Tlvs:             []TlvInterface{},
		}
		vendorInformationObjectTLVs := []TlvInterface{
			&UndefinedTlv{
				Typ:    CISCO_SPEC_TLV_COLOR,
				Length: CISCO_SPEC_TLV_COLOR_LENGTH, // TODO: 20 if ipv6 endpoint
				Value: AppendByteSlices(
					Uint32ToByteSlice(color),
				),
			},
			&UndefinedTlv{
				Typ:    CISCO_SPEC_TLV_PREFERENCE,
				Length: CISCO_SPEC_TLV_PREFERENCE_LENGTH,
				Value:  Uint32ToByteSlice(preference),
			},
		}
		o.Tlvs = append(o.Tlvs, vendorInformationObjectTLVs...)
	} else {
		return nil, errors.New("unknown vender information object type")
	}
	return o, nil
}

func (o *VendorInformationObject) Color() uint32 {
	for _, tlv := range o.Tlvs {
		if t, ok := tlv.(*UndefinedTlv); ok {
			if t.Type() == CISCO_SPEC_TLV_COLOR {
				return uint32(binary.BigEndian.Uint32(t.Value))
			}
		}
	}
	return 0
}

func (o *VendorInformationObject) Preference() uint32 {
	for _, tlv := range o.Tlvs {
		if t, ok := tlv.(*UndefinedTlv); ok {
			if t.Type() == CISCO_SPEC_TLV_PREFERENCE {
				return uint32(binary.BigEndian.Uint32(t.Value))
			}
		}
	}
	return 0
}
