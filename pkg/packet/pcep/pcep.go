// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
)

const COMMON_HEADER_LENGTH uint16 = 4

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

type CommonHeader struct { // RFC5440 6.1
	Version       uint8
	Flag          uint8
	MessageType   uint8
	MessageLength uint16
}

func (h *CommonHeader) DecodeFromBytes(data []uint8) {
	h.Version = uint8(data[0] >> 5)
	h.Flag = uint8(data[0] & 0x1f)
	h.MessageType = uint8(data[1])
	h.MessageLength = binary.BigEndian.Uint16(data[2:4])
}

func (h *CommonHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	verFlag := uint8(h.Version<<5 | h.Flag)
	buf = append(buf, verFlag)
	buf = append(buf, h.MessageType)
	messageLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(messageLength, h.MessageLength)
	buf = append(buf, messageLength...)
	return buf
}

func NewCommonHeader(messageType uint8, messageLength uint16) CommonHeader {
	commonHeader := CommonHeader{
		Version:       uint8(1),
		Flag:          uint8(0),
		MessageType:   messageType,
		MessageLength: messageLength,
	}
	return commonHeader
}

const COMMON_OBJECT_HEADER_LENGTH = 4

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

type CommonObjectHeader struct { // RFC5440 7.2
	ObjectClass  uint8
	ObjectType   uint8
	ResFlags     uint8 // MUST be set to zero
	PFlag        bool  // 0: optional, 1: MUST
	IFlag        bool  // 0: processed, 1: ignored
	ObjectLength uint16
}

func (h *CommonObjectHeader) DecodeFromBytes(data []uint8) {
	h.ObjectClass = uint8(data[0])
	h.ObjectType = uint8(data[1] & 0xf0 >> 4)
	h.ResFlags = uint8(data[1] & 0x0c >> 2)
	h.PFlag = (data[1] & 0x02) != 0
	h.IFlag = (data[1] & 0x01) != 0
	h.ObjectLength = binary.BigEndian.Uint16(data[2:4])
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

func NewCommonObjectHeader(objectClass uint8, objectType uint8, messageLength uint16) CommonObjectHeader {
	commonObjectHeader := CommonObjectHeader{
		ObjectClass:  objectClass,
		ObjectType:   objectType,
		ResFlags:     uint8(0), // MUST be set to zero
		PFlag:        false,    // 0: optional, 1: MUST
		IFlag:        false,    // 0: processed, 1: ignored
		ObjectLength: messageLength,
	}
	return commonObjectHeader
}

type Tlv struct {
	Type   uint16
	Length uint16
	Value  []uint8
}

func (tlv *Tlv) SetLength() {
	tlv.Length = uint16(len(tlv.Value))
}

func (tlv Tlv) getByteLength() uint16 {
	return uint16(4) + uint16(math.Ceil(float64(len(tlv.Value))/4)*4) // Type(2byte) + Length(2byte) + Value(valiable) + padding(valiable)
}

const ( // PCEP TLV
	TLV_RESERVED                     = 0x00 // RFC5440
	TLV_NO_PATH_VECTOR               = 0x01 // RFC5440
	TLV_OVERLOAD_DURATION            = 0x02 // RFC5440
	TLV_REQ_MISSING                  = 0x03 // RFC5440
	TLV_OF_LIST                      = 0x04 // RFC5541
	TLV_ORDER                        = 0x05 // RFC5557
	TLV_P2MP_CAPABLE                 = 0x06 // RFC8306
	TLV_VENDOR_INFORMATION           = 0x07 // RFC7470
	TLV_WAVELENGTH_SELECTION         = 0x08 // RFC8780
	TLV_WAVELENGTH_RESTRICTION       = 0x09 // RFC8780
	TLV_WAVELENGTH_ALLOCATION        = 0x0a // RFC8780
	TLV_OPTICAL_INTERFACE_CLASS_LIST = 0x0b // RFC8780
	TLV_CLIENT_SIGNAL_INFORMATION    = 0x0c // RFC8780
	TLV_H_PCE_CAPABILITY             = 0x0d // RFC8685
	TLV_DOMAIN_ID                    = 0x0e // RFC8685
	TLV_H_PCE_FLAG                   = 0x0f // RFC8685
	TLV_STATEFUL_PCE_CAPABILITY      = 0x10 // RFC8231
	TLV_SYMBOLIC_PATH_NAME           = 0x11 // RFC8231
	TLV_IPV4_LSP_IDENTIFIERS         = 0x12 // RFC8231
	TLV_IPV6_LSP_IDENTIFIERS         = 0x13 // RFC8231
	TLV_LSP_ERROR_CODE               = 0x14 // RFC8231
	TLV_RSVP_ERROR_SPEC              = 0x15 // RFC8231
	// 0x16 is Unassigned
	TLV_LSP_DB_VERSION    = 0x17 // RFC8232
	TLV_SPEAKER_ENTITY_ID = 0x18 // RFC8232
	// 0x19 is Unassigned
	TLV_SR_PCE_CAPABILITY = 0x1a // RFC8664, Deprecated
	// 0x1b is Unassigned
	TLV_PATH_SETUP_TYPE                       = 0x1c // RFC8408
	TLV_OPERATOR_CONFIGURED_ASSOCIATION_RANGE = 0x1d // RFC8697
	TLV_GLOBAL_ASSOCIATION_SOURCE             = 0x1e // RFC8697
	TLV_EXTENDED_ASSOCIATION_ID               = 0x1f // RFC8697
	TLV_P2MP_IPV4_LSP_IDENTIFIERS             = 0x20 // RFC8623
	TLV_P2MP_IPV6_LSP_IDENTIFIERS             = 0x21 // RFC8623
	TLV_PATH_SETUP_TYPE_CAPABILITY            = 0x22 // RFC8409
	TLV_ASSOC_TYPE_LIST                       = 0x23 // RFC8697
	TLV_AUTO_BANDWIDTH_CAPABILITY             = 0x24 // RFC8733
	TLV_AUTO_BANDWIDTH_ATTRIBUTES             = 0x25 // RFC8733
	TLV_PATH_PROTECTION_ASSOCIATION_GROUP_TLV = 0x26 // RFC8745
	TLV_IPV4_ADDRESS                          = 0x27 // RFC8779
	TLV_IPV6_ADDRESS                          = 0x28 // RFC8779
	TLV_UNNUMBERED_ENDPOINT                   = 0x29 // RFC8779
	TLV_LABEL_REQUEST                         = 0x2a // RFC8779
	TLV_LABEL_SET                             = 0x2b // RFC8779
	TLV_PROTECTION_ATTRIBUTE                  = 0x2c // RFC8779
	TLV_GMPLS_CAPABILITY                      = 0x2d // RFC8779
	TLV_DISJOINTNESS_CONFIGURATION            = 0x2e // RFC8800
	TLV_DISJOINTNESS_STATUS                   = 0x2f // RFC8800
	TLV_POLICY_PARAMETERSjTLV                 = 0x30 // RFC9005
	TLV_SCHED_LSP_ATTRIBUTE                   = 0x31 // RFC8934
	TLV_SCHED_PD_LSP_ATTRIBUTE                = 0x32 // RFC8934
	TLV_PCE_FLOWSPEC_CAPABILITY               = 0x33 // ietf-pce-pcep-flowspec-12
	TLV_FLOW_FILTER                           = 0x34 // ietf-pce-pcep-flowspec-12
	TLV_L2_FLOW_FILTER                        = 0x35 // ietf-pce-pcep-flowspec-12
	TLV_BIDIRECTIONAL_LSP_ASSOCIATION_GROUP   = 0x36 // RFC9059
)

const (
	TLV_STATEFUL_PCE_CAPABILITY_LENGTH = 4
	TLV_SR_PCE_CAPABILITY_LENGTH       = 4
	TLV_PATH_SETUP_TYPE_LENGTH         = 4
	TLV_ASSOC_TYPE_LIST_LENGTH         = 2 // TODO: Calculate a LIST length
)

const TL_LENGTH = 4

func (tlv *Tlv) DecodeFromBytes(data []uint8) {
	tlv.Type = binary.BigEndian.Uint16(data[0:2])
	tlv.Length = binary.BigEndian.Uint16(data[2:4])
	tlv.Value = data[4 : 4+tlv.Length]
}

func (tlv *Tlv) Serialize() []uint8 {
	bytePcepTLV := []uint8{}

	byteTlvType := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTlvType, tlv.Type)
	bytePcepTLV = append(bytePcepTLV, byteTlvType...) // Type (2byte)

	byteTlvLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTlvLength, tlv.Length)
	bytePcepTLV = append(bytePcepTLV, byteTlvLength...) // Length (2byte)

	bytePcepTLV = append(bytePcepTLV, tlv.Value...) // Value (Length byte)
	if padding := tlv.Length % 4; padding != 0 {
		bytePadding := make([]uint8, 4-padding)
		bytePcepTLV = append(bytePcepTLV, bytePadding...)
	}
	return bytePcepTLV
}

func DecodeTLVsFromBytes(data []uint8) ([]Tlv, error) {
	tlvs := []Tlv{}
	for {
		var tlv Tlv
		tlv.DecodeFromBytes(data)
		tlvs = append(tlvs, tlv)
		if int(tlv.getByteLength()) < len(data) {
			data = data[tlv.getByteLength():]
		} else if int(tlv.getByteLength()) == len(data) {
			break
		} else {
			return nil, errors.New("tlvs decode error")
		}
	}
	return tlvs, nil
}

type Label struct {
	Sid    uint32
	LoAddr []uint8
}

// OPEN Object (RFC5440 7.3)
type OpenObject struct {
	Version   uint8
	Flag      uint8
	Keepalive uint8
	Deadtime  uint8
	Sid       uint8
	Tlvs      []Tlv
}

const OPEN_OBJECT_LENGTH uint16 = 4

func NewOpenObject(sessionID uint8, keepalive uint8) OpenObject {
	openObject := OpenObject{
		Version:   uint8(1),
		Flag:      uint8(0),
		Keepalive: keepalive,
		Deadtime:  keepalive * 4,
		Sid:       sessionID,
		Tlvs:      []Tlv{},
	}
	openObjectTLVs := []Tlv{ // TODO: Functionalize
		{
			Type:   TLV_STATEFUL_PCE_CAPABILITY,
			Length: TLV_STATEFUL_PCE_CAPABILITY_LENGTH,
			Value:  []uint8{0x00, 0x00, 0x00, 0x05},
		},
		{
			Type:   TLV_SR_PCE_CAPABILITY,
			Length: TLV_SR_PCE_CAPABILITY_LENGTH,
			Value:  []uint8{0x00, 0x00, 0x00, 0x0a},
		},
		{
			Type:   TLV_ASSOC_TYPE_LIST,
			Length: TLV_ASSOC_TYPE_LIST_LENGTH,
			Value:  []uint8{0x00, 0x14},
		},
	}
	openObject.Tlvs = append(openObject.Tlvs, openObjectTLVs...)
	return openObject
}

func (o *OpenObject) DecodeFromBytes(data []uint8) {
	o.Version = uint8(data[0] >> 5)
	o.Flag = uint8(data[0] & 0x1f)
	o.Keepalive = uint8(data[1])
	o.Deadtime = uint8(data[2])
	o.Sid = uint8(data[3])
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
	for _, tlv := range o.Tlvs {
		byteTlvs = append(byteTlvs, tlv.Serialize()...)
	}

	byteOpenObject := AppendByteSlices(byteOpenObjectHeader, buf, byteTlvs)
	return byteOpenObject
}

func (o OpenObject) getByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.getByteLength()
	}
	// TODO: Calculate TLV length and record in open_object_length
	// CommonObjectHeader(4byte) + openObject(4byte) + tlvslength(valiable)
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + OPEN_OBJECT_LENGTH + tlvsByteLength
}

// BANDWIDTH Object (RFC5440 7.7)
type BandwidthObject struct {
	Bandwidth uint32
}

func (o *BandwidthObject) DecodeFromBytes(data []uint8) {
	o.Bandwidth = binary.BigEndian.Uint32(data[:])
}

// METRIC Object (RFC5440 7.8)
type MetricObject struct {
	CFlag       bool
	BFlag       bool
	MetricType  uint8
	MetricValue uint32
}

func (o *MetricObject) DecodeFromBytes(data []uint8) {
	o.CFlag = (data[2] & 0x02) != 0
	o.BFlag = (data[2] & 0x01) != 0
	o.MetricType = data[3]
	o.MetricValue = binary.BigEndian.Uint32(data[4:8])
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

func (o *LspaObject) DecodeFromBytes(data []uint8) {
	o.ExcludeAny = binary.BigEndian.Uint32(data[0:4])
	o.IncludeAny = binary.BigEndian.Uint32(data[4:8])
	o.IncludeAll = binary.BigEndian.Uint32(data[8:12])
	o.SetupPriority = data[12]
	o.HoldingPriority = data[13]
	o.LFlag = (data[14] & 0x01) != 0
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
type SrpObject struct {
	RFlag bool
	SrpId uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	Tlvs  []Tlv
}

func (o *SrpObject) DecodeFromBytes(data []uint8) {
	o.RFlag = (data[3] & 0x01) != 0
	o.SrpId = binary.BigEndian.Uint32(data[4:8])
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

func (o SrpObject) getByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.getByteLength()
	}
	// CommonObjectHeader(4byte) + Flags, SRP-ID(8byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH+8) + tlvsByteLength
}

func NewSrpObject(srpId uint32, isRemove bool) SrpObject {
	srpObject := SrpObject{
		RFlag: isRemove, // RFC8281 5.2
		SrpId: srpId,
		Tlvs: []Tlv{
			{
				Type:   TLV_PATH_SETUP_TYPE,
				Length: TLV_PATH_SETUP_TYPE_LENGTH,
				Value:  []uint8{0x00, 0x00, 0x00, 0x01},
			},
		},
	}

	return srpObject
}

// LSP Object (RFC8281 5.3.1)
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

func (o *LspObject) DecodeFromBytes(data []uint8) error {
	o.PlspId = uint32(binary.BigEndian.Uint32(data[0:4]) >> 12) // 20 bits from top
	o.OFlag = uint8(data[3] & 0x0070 >> 4)
	o.AFlag = (data[3] & 0x08) != 0
	o.RFlag = (data[3] & 0x04) != 0
	o.SFlag = (data[3] & 0x02) != 0
	o.DFlag = (data[3] & 0x01) != 0
	if len(data) > 4 {
		byteTlvs := data[4:]
		for {
			var tlv Tlv
			tlv.DecodeFromBytes(byteTlvs)

			if tlv.Type == uint16(TLV_SYMBOLIC_PATH_NAME) {
				o.Name = string(removePadding(tlv.Value))
			}
			if tlv.Type == uint16(TLV_IPV4_LSP_IDENTIFIERS) {
				// TODO: Obtain true srcAddr
				o.SrcAddr = net.IP(tlv.Value[0:4])
				o.DstAddr = net.IP(tlv.Value[12:16])
			}
			o.Tlvs = append(o.Tlvs, tlv)

			if int(tlv.getByteLength()) < len(byteTlvs) {
				byteTlvs = byteTlvs[tlv.getByteLength():]
			} else if int(tlv.getByteLength()) == len(byteTlvs) {
				break
			} else {
				return errors.New("lsp tlv decode error")
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
		byteTlvs = append(byteTlvs, tlv.Serialize()...)
	}

	byteLspObject := AppendByteSlices(byteLspObjectHeader, buf, byteTlvs)
	return byteLspObject
}

func (o LspObject) getByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.getByteLength()
	}
	// Flags, SRP-ID (4byte)
	lspObjectBodyLength := uint16(4) + tlvsByteLength
	// CommonObjectHeader(4byte) + Flags, SRP-ID
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + lspObjectBodyLength
}

func NewLspObject(lspName string, plspId uint32) LspObject {
	lspObject := LspObject{
		Name:   lspName,
		PlspId: plspId,
		OFlag:  uint8(1), // UP (RFC8231 7.3)
		AFlag:  true,     // desired operational state is active (RFC8231 7.3)
		RFlag:  false,
		SFlag:  false,
		DFlag:  true,
		Tlvs:   []Tlv{},
	}
	symbolicPathNameTlv := Tlv{
		Type:   TLV_SYMBOLIC_PATH_NAME,
		Length: 0x0000, //valiable, set next line
		Value:  []uint8(lspName),
	}
	symbolicPathNameTlv.SetLength()
	lspObject.Tlvs = append(lspObject.Tlvs, symbolicPathNameTlv)
	return lspObject
}

// ERO Object (RFC5440 7.9)
type EroObject struct {
	SrEroSubobjects []SrEroSubobject
}

func (o *EroObject) DecodeFromBytes(data []uint8) error {
	if len(data) == 0 {
		return nil
	}
	for {
		var srErosubObj SrEroSubobject
		srErosubObj.DecodeFromBytes(data)
		o.SrEroSubobjects = append(o.SrEroSubobjects, srErosubObj)
		if objByteLength, err := srErosubObj.getByteLength(); err != nil {
			return err
		} else if int(objByteLength) < len(data) {
			data = data[objByteLength:]
		} else if int(objByteLength) == len(data) {
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
	eroObjectHeader := NewCommonObjectHeader(OC_ERO, 1, eroObjectLength)
	byteEroObjectHeader := eroObjectHeader.Serialize()

	byteEroObject := byteEroObjectHeader
	for _, srEroSubobject := range o.SrEroSubobjects {
		buf := srEroSubobject.Serialize()
		byteEroObject = append(byteEroObject, buf...)
	}
	return byteEroObject, nil
}

func (o EroObject) getByteLength() (uint16, error) {
	srEroSubobjByteLength := uint16(0)
	for _, srEroSubObj := range o.SrEroSubobjects {
		objByteLength, err := srEroSubObj.getByteLength()
		if err != nil {
			return 0, err
		}
		srEroSubobjByteLength += objByteLength
	}
	// CommonObjectHeader(4byte) + eroObjectHeader(4byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + srEroSubobjByteLength, nil
}

func NewEroObject(labels []Label) (EroObject, error) {
	eroObject := EroObject{
		SrEroSubobjects: []SrEroSubobject{},
	}
	err := eroObject.AddSrEroSubobjects(labels)
	if err != nil {
		return eroObject, err
	}
	return eroObject, nil
}

func (o *EroObject) AddSrEroSubobjects(labels []Label) error {
	for _, label := range labels {
		srEroSubobject, err := NewSrEroSubObject(label.Sid, label.LoAddr)
		if err != nil {
			return err
		}
		o.SrEroSubobjects = append(o.SrEroSubobjects, srEroSubobject)
	}
	return nil
}

func (o EroObject) GetSidList() []uint32 {
	sidList := []uint32{}
	for _, srEroSubobject := range o.SrEroSubobjects {
		sidList = append(sidList, srEroSubobject.Sid)
	}
	return sidList
}

// SR-ERO Subobject (RFC8664 4.3.1)
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

func (o *SrEroSubobject) DecodeFromBytes(data []uint8) {
	o.LFlag = (data[0] & 0x80) != 0
	o.SubobjectType = data[0] & 0x7f
	o.Length = data[1]
	o.NaiType = data[2] >> 4
	o.FFlag = (data[3] & 0x08) != 0
	o.SFlag = (data[3] & 0x04) != 0
	o.CFlag = (data[3] & 0x02) != 0
	o.MFlag = (data[3] & 0x01) != 0
	o.Sid = binary.BigEndian.Uint32(data[4:8]) >> 12
	o.Nai = data[8:12]
}

func (o *SrEroSubobject) Serialize() []uint8 {
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
	binary.BigEndian.PutUint32(byteSid, o.Sid<<12)

	byteSrEroSubobject := AppendByteSlices(buf, byteSid, o.Nai)
	return byteSrEroSubobject
}

func (o SrEroSubobject) getByteLength() (uint16, error) {
	if o.NaiType == NT_ABSENT {
		// Type, Length, Flags (4byte) + SID (4byte)
		return uint16(8), nil
	} else if o.NaiType == NT_IPV4_NODE {
		// Type, Length, Flags (4byte) + SID (4byte) + Nai (4byte)
		return uint16(12), nil
	} else if o.NaiType == NT_IPV6_NODE {
		// Type, Length, Flags (4byte) + SID (4byte) + Nai (16byte)
		return uint16(20), nil
	} else {
		return uint16(0), errors.New("unsupported naitype")
	}
}

func NewSrEroSubObject(sid uint32, loAddr []uint8) (SrEroSubobject, error) {
	srEroSubObject := SrEroSubobject{
		LFlag:         false,
		SubobjectType: ERO_SUBOBJECT_SR,
		// SID: NodeSID, NAI: IPv4 address  TODO: Support another Nai Type
		NaiType: NT_IPV4_NODE,
		FFlag:   false,
		SFlag:   false,
		CFlag:   false,
		MFlag:   true, // TODO: Determine if MPLS
		Sid:     uint32(sid),
		Nai:     loAddr,
	}
	length, err := srEroSubObject.getByteLength()
	if err != nil {
		return srEroSubObject, err
	}
	srEroSubObject.Length = uint8(length)
	return srEroSubObject, nil
}

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

// END-POINTS Object (RFC5440 7.6)
type EndpointsObject struct {
	ObjectType uint8 // IPv4: 1, IPv6: 2
	srcIPv4    []uint8
	dstIPv4    []uint8
}

func (o EndpointsObject) Serialize() []uint8 {
	EndpointsObjectHeader := NewCommonObjectHeader(OC_END_POINTS, 1, o.getByteLength())
	byteEroObjectHeader := EndpointsObjectHeader.Serialize()
	byteEndpointsObject := AppendByteSlices(byteEroObjectHeader, o.srcIPv4, o.dstIPv4)
	return byteEndpointsObject
}

func (o EndpointsObject) getByteLength() uint16 {
	// TODO: Expantion for IPv6 Endpoint
	// CommonObjectHeader(4byte) + srcIPv4 (4byte) + dstIPv4 (4byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH + 4 + 4)
}

func NewEndpointsObject(objType uint8, dstIPv4 []uint8, srcIPv4 []uint8) EndpointsObject {
	// TODO: Expantion for IPv6 Endpoint
	EndpointsObject := EndpointsObject{
		ObjectType: objType,
		dstIPv4:    dstIPv4,
		srcIPv4:    srcIPv4,
	}
	return EndpointsObject
}

// VENDOR-INFORMATION Object (RFC7470 4)
type VendorInformationObject struct {
	ObjectType       uint8 // vendor specific constraints: 1
	EnterpriseNumber uint32
	Color            uint32
	Preference       uint32
}

func (o *VendorInformationObject) DecodeFromBytes(data []uint8) {
	// TODO: Supports decode Cisco specific TLV type
	o.EnterpriseNumber = binary.BigEndian.Uint32(data[0:4])
	o.Color = binary.BigEndian.Uint32(data[8:12])
	o.Preference = binary.BigEndian.Uint32(data[16:20])
}

func (o *VendorInformationObject) Serialize() []uint8 {
	vendorInformationObjectHeader := NewCommonObjectHeader(OC_VENDOR_INFORMATION, 1, o.getByteLength())
	byteVendorInformationObjectHeader := vendorInformationObjectHeader.Serialize()

	enterpriseNumber := make([]uint8, 4)
	binary.BigEndian.PutUint32(enterpriseNumber, o.EnterpriseNumber)
	tlvColor := []uint8{0x00, 0x01, 0x00, 0x04} // type: 1, length : 4
	colorValue := make([]uint8, 4)
	binary.BigEndian.PutUint32(colorValue, o.Color)
	tlvColor = AppendByteSlices(tlvColor, colorValue)
	tlvPreference := []uint8{0x00, 0x03, 0x00, 0x04} // type: 3, length: 4
	preferenceValue := make([]uint8, 4)
	binary.BigEndian.PutUint32(preferenceValue, o.Preference)
	tlvPreference = AppendByteSlices(tlvPreference, preferenceValue)
	byteVendorInformationObject := AppendByteSlices(byteVendorInformationObjectHeader, enterpriseNumber, tlvColor, tlvPreference)
	return byteVendorInformationObject
}

func (o VendorInformationObject) getByteLength() uint16 {
	// TODO: Expantion for IPv6 Endpoint
	// CommonObjectHeader(4byte) + Enterprise Number (4byte) + colorTLV (8byte) + preferenceTLV (8byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH + 4 + 8 + 8)
}

func NewVendorInformationObject(vendor string, color uint32, preference uint32) VendorInformationObject {
	vendorInformationObject := VendorInformationObject{ // for Cisco PCC
		ObjectType:       uint8(1),
		EnterpriseNumber: uint32(9),
		Color:            color,
		Preference:       preference,
	}
	return vendorInformationObject
}

// Open Message
type OpenMessage struct {
	openObject OpenObject
}

func NewOpenMessage(sessionID uint8, keepalive uint8) OpenMessage {
	var openMessage OpenMessage
	openMessage.openObject = NewOpenObject(sessionID, keepalive)
	return openMessage
}

func (o *OpenMessage) Serialize() []uint8 {
	byteOpenObject := o.openObject.Serialize()
	openMessageLength := COMMON_HEADER_LENGTH + o.openObject.getByteLength()
	openHeader := NewCommonHeader(MT_OPEN, openMessageLength)
	byteOpenHeader := openHeader.Serialize()
	byteOpenMessage := AppendByteSlices(byteOpenHeader, byteOpenObject)
	return byteOpenMessage
}

// Keepalive Message
type KeepaliveMessage struct {
}

func NewKeepaliveMessage() KeepaliveMessage {
	var keepaliveMessage KeepaliveMessage
	return keepaliveMessage
}

func (o *KeepaliveMessage) Serialize() []uint8 {
	keepaliveMessageLength := COMMON_HEADER_LENGTH
	keepaliveHeader := NewCommonHeader(MT_KEEPALIVE, keepaliveMessageLength)
	byteKeepaliveHeader := keepaliveHeader.Serialize()
	byteKeepaliveMessage := byteKeepaliveHeader
	return byteKeepaliveMessage
}

// PCRpt Message
type PCRptMessage struct {
	SrpObject               SrpObject
	LspObject               LspObject
	EroObject               EroObject
	LspaObject              LspaObject
	MetricObjects           []MetricObject
	BandwidthObjects        []BandwidthObject
	VendorInformationObject VendorInformationObject
}

func (o *PCRptMessage) DecodeFromBytes(bytePcrptObject []uint8) error {
	// TODO: Supports multiple <state-report>'s stacked PCRpt Message.
	// https://datatracker.ietf.org/doc/html/rfc8231#section-6.1
	// Currently, when more than 2 <state-report> come in, One object has multiple object information.
	var commonObjectHeader CommonObjectHeader
	commonObjectHeader.DecodeFromBytes(bytePcrptObject)

	switch commonObjectHeader.ObjectClass {
	case OC_BANDWIDTH:
		var bandwidthObject BandwidthObject
		bandwidthObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		o.BandwidthObjects = append(o.BandwidthObjects, bandwidthObject)
	case OC_METRIC:
		var metricObject MetricObject
		metricObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		o.MetricObjects = append(o.MetricObjects, metricObject)
	case OC_ERO:
		err := o.EroObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		if err != nil {
			return err
		}
	case OC_LSPA:
		o.LspaObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	case OC_LSP:
		err := o.LspObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		if err != nil {
			return err
		}
	case OC_SRP:
		o.SrpObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	case OC_VENDOR_INFORMATION:
		o.VendorInformationObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	default:
	}

	if int(commonObjectHeader.ObjectLength) < len(bytePcrptObject) {
		err := o.DecodeFromBytes(bytePcrptObject[commonObjectHeader.ObjectLength:])
		if err != nil {
			return err
		}
	}
	return nil
}

// PCInitiate Message
type PCInitiateMessage struct {
	SrpObject               SrpObject
	LspObject               LspObject
	EndpointsObject         EndpointsObject
	EroObject               EroObject
	VendorInformationObject VendorInformationObject
}

func NewPCInitiateMessage(srpId uint32, lspName string, labels []Label, color uint32, preference uint32, srcIPv4 []uint8, dstIPv4 []uint8) (PCInitiateMessage, error) {
	var pcInitiateMessage PCInitiateMessage
	pcInitiateMessage.SrpObject = NewSrpObject(srpId, false)
	pcInitiateMessage.LspObject = NewLspObject(lspName, 0)                      // PLSP-ID = 0
	pcInitiateMessage.EndpointsObject = NewEndpointsObject(1, dstIPv4, srcIPv4) // objectType = 1 (IPv4)
	var err error
	pcInitiateMessage.EroObject, err = NewEroObject(labels)
	if err != nil {
		return pcInitiateMessage, err
	}
	pcInitiateMessage.VendorInformationObject = NewVendorInformationObject("Cisco", color, preference)
	return pcInitiateMessage, nil
}

func (o *PCInitiateMessage) Serialize() ([]uint8, error) {
	byteSrpObject := o.SrpObject.Serialize()
	byteLspObject := o.LspObject.Serialize()
	byteEndpointsObject := o.EndpointsObject.Serialize()
	byteEroObject, err := o.EroObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteVendorInformationObject := o.VendorInformationObject.Serialize()

	eroObjectLength, err := o.EroObject.getByteLength()
	if err != nil {
		return nil, err
	}
	pcinitiateMessageLength := COMMON_HEADER_LENGTH + o.SrpObject.getByteLength() + o.LspObject.getByteLength() + o.EndpointsObject.getByteLength() + eroObjectLength + o.VendorInformationObject.getByteLength()
	pcinitiateHeader := NewCommonHeader(MT_LSPINITREQ, pcinitiateMessageLength)
	bytePCInitiateHeader := pcinitiateHeader.Serialize()
	bytePCInitiateMessage := AppendByteSlices(bytePCInitiateHeader, byteSrpObject, byteLspObject, byteEndpointsObject, byteEroObject, byteVendorInformationObject)
	return bytePCInitiateMessage, nil
}

// PCUpdate Message
type PCUpdMessage struct {
	SrpObject SrpObject
	LspObject LspObject
	EroObject EroObject
}

func NewPCUpdMessage(srpId uint32, lspName string, plspId uint32, labels []Label) (PCUpdMessage, error) {
	var pcUpdMessage PCUpdMessage
	pcUpdMessage.SrpObject = NewSrpObject(srpId, false)
	pcUpdMessage.LspObject = NewLspObject(lspName, plspId) // PLSP-ID = 0
	var err error
	pcUpdMessage.EroObject, err = NewEroObject(labels)
	if err != nil {
		return pcUpdMessage, err
	}
	return pcUpdMessage, nil
}

func (o *PCUpdMessage) Serialize() ([]uint8, error) {
	byteSrpObject := o.SrpObject.Serialize()
	byteLspObject := o.LspObject.Serialize()
	byteEroObject, err := o.EroObject.Serialize()
	if err != nil {
		return nil, err
	}

	eroObjectLength, err := o.EroObject.getByteLength()
	if err != nil {
		return nil, err
	}
	pcupdMessageLength := COMMON_HEADER_LENGTH + o.SrpObject.getByteLength() + o.LspObject.getByteLength() + eroObjectLength
	pcupdHeader := NewCommonHeader(MT_UPDATE, pcupdMessageLength)
	bytePCUpdHeader := pcupdHeader.Serialize()
	bytePCUpdMessage := AppendByteSlices(bytePCUpdHeader, byteSrpObject, byteLspObject, byteEroObject)
	return bytePCUpdMessage, err
}

// utils
func AppendByteSlices(byteSlices ...[]uint8) []uint8 {
	joinedSliceLength := 0
	for _, byteSlice := range byteSlices {
		joinedSliceLength += len(byteSlice)
	}
	joinedSlice := make([]uint8, 0, joinedSliceLength)
	for _, byteSlice := range byteSlices {
		joinedSlice = append(joinedSlice, byteSlice...)
	}
	return joinedSlice
}

func removePadding(data []uint8) []uint8 {
	for {
		if data[len(data)-1] == 0x00 {
			data = data[:len(data)-1]
		} else {
			return data
		}
	}
}
