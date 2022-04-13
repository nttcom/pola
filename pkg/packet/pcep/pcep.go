// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"fmt"
	"log"
	"math"
)

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

const COMMON_HEADER_LENGTH uint16 = 4

const (
	// PCEP Message-Type (1byte)
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

func (h *CommonHeader) DecodeFromBytes(data []uint8) error {
	h.Version = uint8(data[0] >> 5)
	h.Flag = uint8(data[0] & 0x1f)
	h.MessageType = uint8(data[1])
	h.MessageLength = binary.BigEndian.Uint16(data[2:4])
	return nil
}

func (h *CommonHeader) Serialize() ([]uint8, error) {
	buf := make([]uint8, 0, 4)
	verFlag := uint8(h.Version<<5 | h.Flag)
	buf = append(buf, verFlag)
	buf = append(buf, h.MessageType)
	messageLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(messageLength, h.MessageLength)
	buf = append(buf, messageLength...)
	return buf, nil
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

const (
	// PCEP Object-Class (1 byte)
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

func (h *CommonObjectHeader) DecodeFromBytes(data []uint8) error {
	h.ObjectClass = uint8(data[0])
	h.ObjectType = uint8(data[1] & 0xf0 >> 4)
	h.ResFlags = uint8(data[1] & 0x0c >> 2)
	h.PFlag = (data[1] & 0x02) != 0
	h.IFlag = (data[1] & 0x01) != 0
	h.ObjectLength = binary.BigEndian.Uint16(data[2:4])
	return nil
}

func (h *CommonObjectHeader) Serialize() ([]uint8, error) {
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
	return buf, nil
}

// ToDo: objecttype
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
	return uint16(4) + uint16(math.Ceil(float64(len(tlv.Value))/4)*4) //Type(2byte) + Length(2byte) + Value(valiable) + padding(valiable)
}

const (
	// PCEP TLV
	// https://www.iana.org/assignments/pcep/pcep.xhtml#:~:text=XRO%20Flag%20Field-,Objective%20Function,-PCEP%20TLV%20Type
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
	TLV_ASSOC_TYPE_LIST_LENGTH         = 2 // ToDo: これはLIST長分にする
)

const TL_LENGTH = 4

func unmarshalPcepTLVs(tlvs *[]Tlv, pcepTLVs []uint8) {
	fmt.Printf("pcep TLVs byte: %#v\n", pcepTLVs)
	tlvType := binary.BigEndian.Uint16(pcepTLVs[0:2])
	tlvLength := uint16(math.Ceil(float64(binary.BigEndian.Uint16(pcepTLVs[2:4]))/4) * 4) // Include padding
	fmt.Printf(" TLV length: %d\n", tlvLength)
	tlv := &Tlv{
		Type:   tlvType,
		Length: tlvLength,
		Value:  pcepTLVs[4 : 4+tlvLength],
	}
	*tlvs = append(*tlvs, *tlv)
	switch tlvType {
	case TLV_IPV4_LSP_IDENTIFIERS:
		fmt.Printf(" Unmarshal TLV_IPV4_LSP_IDENTIFIERS (%v)\n", tlvType)
	case TLV_STATEFUL_PCE_CAPABILITY:
		fmt.Printf(" Unmarshal TLV_STATEFUL_PCE_CAPABILITY (%v)\n", tlvType)
	case TLV_SYMBOLIC_PATH_NAME:
		fmt.Printf(" Unmarshal TLV_SYMBOLIC_PATH_NAME (%v)\n", tlvType)
	case TLV_SR_PCE_CAPABILITY:
		fmt.Printf(" Unmarshal TLV_SR_PCE_CAPABILITY (%v)\n", tlvType)
	case TLV_ASSOC_TYPE_LIST:
		fmt.Printf(" Unmarshal TLV_ASSOC_TYPE_LIST (%v)\n", tlvType)
	default:
		fmt.Printf(" Unimplemented TLV: %v\n", tlvType)
	}

	if len(pcepTLVs)-int(tlvLength+TL_LENGTH) >= 4 {
		unmarshalPcepTLVs(tlvs, pcepTLVs[(tlvLength+TL_LENGTH):])
	}
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

type Path struct {
	LspObject               LspObject
	SrEroSubobjects         []SrEroSubobject
	LspaObject              LspaObject
	MetricObject            MetricObject
	EndpointObject          EndpointObject
	VendorInformationObject VendorInformationObject
}

///////////////////////////////////////////////////////////////////

type Label struct {
	Sid    uint32
	LoAddr []uint8
}

/*----------------- objects ------------------*/
//////////////////////// open object //////////////////////////////
type OpenObject struct { // RFC5440 7.3
	Version   uint8
	Flag      uint8
	Keepalive uint8
	Deadtime  uint8
	Sid       uint8
	Tlvs      []Tlv
}

const OPEN_OBJECT_LENGTH uint16 = 4

func (o *OpenObject) DecodeFromBytes(data []uint8) error {
	o.Version = uint8(data[0] >> 5)
	o.Flag = uint8(data[0] & 0x1f)
	o.Keepalive = uint8(data[1])
	o.Deadtime = uint8(data[2])
	o.Sid = uint8(data[3])
	return nil
}

func (o *OpenObject) Serialize() ([]uint8, error) {
	byteOpenObject := []uint8{}
	openObjectHeader := NewCommonObjectHeader(OC_OPEN, 1, o.GetByteLength())
	byteOpenObjectHeader, err := openObjectHeader.Serialize()
	if err != nil {
		return nil, err
	}
	byteOpenObject = append(byteOpenObject, byteOpenObjectHeader...)
	verFlag := uint8(o.Version<<5 | o.Flag)
	byteOpenObject = append(byteOpenObject, verFlag)
	byteOpenObject = append(byteOpenObject, o.Keepalive)
	byteOpenObject = append(byteOpenObject, o.Deadtime)
	byteOpenObject = append(byteOpenObject, o.Sid)

	byteTlvs := []uint8{}
	for _, tlv := range o.Tlvs {
		byteTlvs = append(byteTlvs, tlv.Serialize()...)
	}

	byteOpenObject = append(byteOpenObject, byteTlvs...)

	return byteOpenObject, nil
}

func (o OpenObject) GetByteLength() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.getByteLength()
	}
	// 要修正 open_object_length に tlv の長さ入れたい
	// CommonObjectHeader(4byte) + openObject(4byte) + tlvslength(valiable)
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + OPEN_OBJECT_LENGTH + tlvsByteLength
}

func NewOpenObject(sessionID uint8, keepalive uint8, Tlvs []Tlv) OpenObject {
	openObject := OpenObject{
		Version:   uint8(1),
		Flag:      uint8(0),
		Keepalive: keepalive,
		Deadtime:  keepalive * 4,
		Sid:       sessionID,
		Tlvs:      Tlvs,
	}
	return openObject
}

//////////////////////// bandwidth object //////////////////////////////
type BandwidthObject struct { // RFC5440 7.7
	Bandwidth uint32
}

func (o *BandwidthObject) DecodeFromBytes(data []uint8) error {
	o.Bandwidth = binary.BigEndian.Uint32(data[:])
	return nil
}

//////////////////////// metric object //////////////////////////////
type MetricObject struct { // RFC5440 7.8
	CFlag       bool
	BFlag       bool
	MetricType  uint8
	MetricValue uint32
}

func (o *MetricObject) DecodeFromBytes(data []uint8) error {
	o.CFlag = (data[2] & 0x02) != 0
	o.BFlag = (data[2] & 0x01) != 0
	o.MetricType = data[3]
	o.MetricValue = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (o *MetricObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 8)
	if o.CFlag {
		buf[2] = buf[2] | 0x02
	}
	if o.BFlag {
		buf[2] = buf[2] | 0x01
	}
	buf[3] = o.MetricType
	binary.BigEndian.PutUint32(buf[4:8], o.MetricValue)
	return buf, nil
}

// func EncapMetricObject(o MetricObject) []uint8 {
// 	body, err := o.Serialize()
// 	if err != nil {
// 		fmt.Printf("metric error")
// 		log.Fatal(nil)
// 	}
// 	buf := EncapCommonObjectHeader(body, OC_METRIC)
// 	return buf
// }

//////////////////////// lspa object //////////////////////////////
type LspaObject struct { // RFC5440 7.11
	ExcludeAny      uint32
	IncludeAny      uint32
	IncludeAll      uint32
	SetupPriority   uint8
	HoldingPriority uint8
	LFlag           bool
}

func (o *LspaObject) DecodeFromBytes(data []uint8) error {
	o.ExcludeAny = binary.BigEndian.Uint32(data[0:4])
	o.IncludeAny = binary.BigEndian.Uint32(data[4:8])
	o.IncludeAll = binary.BigEndian.Uint32(data[8:12])
	o.SetupPriority = data[12]
	o.HoldingPriority = data[13]
	o.LFlag = (data[14] & 0x01) != 0
	return nil
}

func (o *LspaObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 16)
	binary.BigEndian.PutUint32(buf[0:4], o.ExcludeAny)
	binary.BigEndian.PutUint32(buf[4:8], o.IncludeAny)
	binary.BigEndian.PutUint32(buf[8:12], o.IncludeAll)
	buf[12] = o.SetupPriority
	buf[13] = o.HoldingPriority
	if o.LFlag {
		buf[14] = buf[14] | 0x01
	}
	return buf, nil
}

// func EncapLspaObject(o LspaObject) []uint8 {
// 	body, err := o.Serialize()
// 	if err != nil {
// 		fmt.Printf("lspa obj error")
// 		log.Fatal(nil)
// 	}
// 	buf := EncapCommonObjectHeader(body, OC_LSPA)
// 	return buf
// }

//////////////////////// srp object //////////////////////////////
type SrpObject struct { // RFC8281 5.2
	RFlag bool
	SrpId uint32
	Tlvs  []Tlv
}

func (o *SrpObject) DecodeFromBytes(data []uint8) error {
	o.RFlag = (data[3] & 0x01) != 0
	o.SrpId = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (o *SrpObject) Serialize() ([]uint8, error) {
	srpObjectHeader := NewCommonObjectHeader(OC_SRP, 1, o.getByteLength())
	byteSrpObjectHeader, err := srpObjectHeader.Serialize()
	if err != nil {
		return nil, err
	}

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
	return byteSrpObject, nil
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
		RFlag: isRemove, // https://datatracker.ietf.org/doc/html/rfc8231#section-7.2
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

//////////////////////// lsp object //////////////////////////////
type LspObject struct { // RFC8281 5.3.1
	Name   string
	PlspId uint32
	OFlag  uint8
	AFlag  bool
	RFlag  bool
	SFlag  bool
	DFlag  bool
	Tlvs   []Tlv
}

func (o *LspObject) DecodeFromBytes(data []uint8) error {
	o.PlspId = uint32(binary.BigEndian.Uint32(data[0:4]) >> 12) // 20 bits from top
	o.OFlag = uint8(data[3] & 0x0070 >> 4)
	o.AFlag = (data[3] & 0x08) != 0
	o.RFlag = (data[3] & 0x04) != 0
	o.SFlag = (data[3] & 0x02) != 0
	o.DFlag = (data[3] & 0x01) != 0
	// lsp の decode をしたい
	return nil
}

func (o *LspObject) Serialize() ([]uint8, error) {
	lspObjectHeader := NewCommonObjectHeader(OC_LSP, 1, o.getByteLength())
	byteLspObjectHeader, err := lspObjectHeader.Serialize()
	if err != nil {
		return nil, err
	}

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
	symbolicPathNameTlv := Tlv{
		Type:   TLV_SYMBOLIC_PATH_NAME,
		Length: 0x0000,
		Value:  []uint8(o.Name),
	}
	symbolicPathNameTlv.SetLength()
	byteTlv := symbolicPathNameTlv.Serialize()

	byteLspObject := AppendByteSlices(byteLspObjectHeader, buf, byteTlv)
	return byteLspObject, nil
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
		OFlag:  uint8(0),
		AFlag:  true, // https://datatracker.ietf.org/doc/html/rfc8231#section-7.3
		RFlag:  false,
		SFlag:  false,
		DFlag:  false,
		Tlvs: []Tlv{
			{
				Type:   TLV_SYMBOLIC_PATH_NAME,
				Length: 0x00, //可変
				Value:  []uint8(lspName),
			},
		},
	}

	return lspObject
}

//////////////////////// ero object //////////////////////////////
type EroObject struct {
	SrEroSubobjects []SrEroSubobject
}

func (o EroObject) Serialize() ([]uint8, error) {
	eroObjectHeader := NewCommonObjectHeader(OC_ERO, 1, o.getByteLength())
	byteEroObjectHeader, err := eroObjectHeader.Serialize()
	if err != nil {
		return nil, err
	}

	byteEroObject := byteEroObjectHeader
	for _, srEroSubobject := range o.SrEroSubobjects {
		buf, err := srEroSubobject.Serialize()
		if err != nil {
			fmt.Printf("[pcep] Serialize EroObject error\n")
			log.Fatal(nil)
		}
		byteEroObject = append(byteEroObject, buf...)
	}

	return byteEroObject, nil
}

func (o EroObject) getByteLength() uint16 {
	srEroSubobjByteLength := uint16(0)
	for _, srEroSubObj := range o.SrEroSubobjects {
		srEroSubobjByteLength += srEroSubObj.getByteLength()
	}
	// CommonObjectHeader(4byte) + eroObjectHeader(4byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH) + srEroSubobjByteLength
}

func NewEroObject(labels []Label) EroObject {
	eroObject := EroObject{
		SrEroSubobjects: []SrEroSubobject{},
	}
	eroObject.AddSrEroSubobjects(labels)
	return eroObject
}

func (o *EroObject) AddSrEroSubobjects(labels []Label) {
	for _, label := range labels {
		srEroSubobject := NewSrEroSubObject(label.Sid, label.LoAddr)
		o.SrEroSubobjects = append(o.SrEroSubobjects, srEroSubobject)
	}
}

//////////////////////// srerosub object //////////////////////////////
type SrEroSubobject struct { // RFC8664 4.3.1
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

func (o *SrEroSubobject) Serialize() ([]uint8, error) {
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
	return byteSrEroSubobject, nil
}

func (o SrEroSubobject) getByteLength() uint16 {
	// only used for NaiType == NT_IPV4_NODE
	// TODO: Expansion for another NaiType
	// Type, Length, Flags (4byte) + SID (4byte) + Nai (4byte)
	return uint16(12)
}

func NewSrEroSubObject(sid uint32, loAddr []uint8) SrEroSubobject {
	srEroSubObject := SrEroSubobject{
		LFlag:         false,
		SubobjectType: ERO_SUBOBJECT_SR,
		Length:        uint8(12),    // TODO: NT によって length は変わる
		NaiType:       NT_IPV4_NODE, // SID: NodeSID NAI: ipv4 address
		FFlag:         false,
		SFlag:         false,
		CFlag:         false,
		MFlag:         true, // TODO: MPLS Label判定
		Sid:           uint32(sid),
		Nai:           loAddr,
	}
	return srEroSubObject
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

//////////////////////// endpoint object //////////////////////////////
type EndpointObject struct {
	ObjectType uint8 // ipv4: 1, ipv6: 2
	srcIPv4    []uint8
	dstIPv4    []uint8
}

func (o EndpointObject) Serialize() ([]uint8, error) {
	endpointObjectHeader := NewCommonObjectHeader(OC_END_POINTS, 1, o.getByteLength())
	byteEroObjectHeader, err := endpointObjectHeader.Serialize()
	if err != nil {
		return nil, err
	}
	byteEndpointObject := AppendByteSlices(byteEroObjectHeader, o.srcIPv4, o.dstIPv4)

	return byteEndpointObject, nil
}

func (o EndpointObject) getByteLength() uint16 {
	// TODO: Expantion for IPv6 Endpoint
	// CommonObjectHeader(4byte) + srcIPv4 (4byte) + dstIPv4 (4byte)
	return uint16(COMMON_OBJECT_HEADER_LENGTH + 4 + 4)
}

func NewEndpointObject(objType uint8, dstIPv4 []uint8, srcIPv4 []uint8) EndpointObject {
	// TODO: Expantion for IPv6 Endpoint
	EndpointObject := EndpointObject{
		ObjectType: objType,
		dstIPv4:    dstIPv4,
		srcIPv4:    srcIPv4,
	}

	return EndpointObject
}

//////////////////////// vendorinfo object //////////////////////////////
type VendorInformationObject struct { // RFC7470 4
	ObjectType       uint8 // vendor specific constraints: 1
	EnterpriseNumber uint32
	Color            uint32
	Preference       uint32
}

func (o *VendorInformationObject) DecodeFromBytes(data []uint8) error {
	o.EnterpriseNumber = binary.BigEndian.Uint32(data[0:4])
	// 雑実装のため要修正
	o.Color = binary.BigEndian.Uint32(data[8:12])
	o.Preference = binary.BigEndian.Uint32(data[16:20])
	return nil
}

func (o *VendorInformationObject) Serialize() ([]uint8, error) {
	vendorInformationObjectHeader := NewCommonObjectHeader(OC_VENDOR_INFORMATION, 1, o.getByteLength())
	byteVendorInformationObjectHeader, err := vendorInformationObjectHeader.Serialize()
	if err != nil {
		return nil, err
	}

	buf := i32tob(o.EnterpriseNumber)
	tlvColor := []uint8{0x00, 0x01, 0x00, 0x04} // type: 1, length : 4
	tlvColor = AppendByteSlices(tlvColor, i32tob(o.Color))
	tlvPreference := []uint8{0x00, 0x03, 0x00, 0x04} // type: 3, length: 4
	tlvPreference = AppendByteSlices(tlvPreference, i32tob(o.Preference))
	byteVendorInformationObject := AppendByteSlices(byteVendorInformationObjectHeader, buf, tlvColor, tlvPreference)
	return byteVendorInformationObject, nil
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

///////////////////////////////////////////////////////////////////
//////////////////////// PCUpd object //////////////////////////////

// func (s *Server) SendPCUpd(conn net.Conn, path Path) {
// 	byteObjects := NewPCUpdObjects(path)

// 	messageLength := uint16(len(byteObjects) + COMMON_HEADER_LENGTH)
// 	byteCommonHeader := NewCommonHeader(MT_UPDATE, messageLength)

// 	pcupdMessage := append(byteCommonHeader, byteObjects...)

// 	fmt.Printf("[PCEP] Send PCUpd\n")
// 	_, err := conn.Write(pcupdMessage)
// 	if err != nil {
// 		fmt.Printf("pcupd error")
// 		log.Fatal(nil)
// 	}
// }

// func NewPCUpdObjects(path Path) []uint8 {
// 	// TODO: 経路のパラメータによってはObjectの数変わる？要調査
// 	byteSrpObject := NewSrpObject()
// 	byteLspObject := EncapLspObject(path.LspObject)
// 	byteEroObject := NewEroObject(path.SrEroSubobject)
// 	byteLspaObject := EncapLspaObject(path.LspaObject)
// 	byteMetricObject := EncapMetricObject(path.MetricObject)
// 	byteObjects := appendByteSlices(byteSrpObject, byteLspObject, byteEroObject, byteLspaObject, byteMetricObject)
// 	return (byteObjects)
// }

/*---------------- PCEP Message struct ----------------*/
//////////////////////// PCRpt Message //////////////////////////////
type PCRptMessage struct {
	SrpObject               SrpObject
	LspObject               LspObject
	SrEroSubobject          SrEroSubobject
	LspaObject              LspaObject
	MetricObjects           []MetricObject
	BandwidthObjects        []BandwidthObject
	VendorInformationObject VendorInformationObject
}

func (o *PCRptMessage) DecodeFromBytes(bytePcrptObject []uint8) error {
	fmt.Printf(" Start Parse PCRpt\n")
	var commonObjectHeader CommonObjectHeader
	err := commonObjectHeader.DecodeFromBytes(bytePcrptObject)
	if err != nil {
		return err
	}

	switch commonObjectHeader.ObjectClass {
	case OC_BANDWIDTH:
		fmt.Printf(" Decode OC_BANDWIDTH (%v)\n", commonObjectHeader.ObjectClass)
		var bandwidthObject BandwidthObject
		err = bandwidthObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			return err
		}
		o.BandwidthObjects = append(o.BandwidthObjects, bandwidthObject)
	case OC_METRIC:
		fmt.Printf(" Decode OC_METRIC (%v)\n", commonObjectHeader.ObjectClass)
		var metricObject MetricObject
		err = metricObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
		o.MetricObjects = append(o.MetricObjects, metricObject)
	case OC_ERO:
		fmt.Printf(" Decode OC_ERO (%v)\n", commonObjectHeader.ObjectClass)
		// report.SrEroSubobject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
	case OC_LSPA:
		fmt.Printf(" Decode OC_LSPA (%v)\n", commonObjectHeader.ObjectClass)
		err := o.LspaObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
	case OC_LSP:
		fmt.Printf(" Decode OC_LSP (%v)\n", commonObjectHeader.ObjectClass)
		tlvLength := commonObjectHeader.ObjectLength - COMMON_OBJECT_HEADER_LENGTH
		err := o.LspObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH : tlvLength+COMMON_OBJECT_HEADER_LENGTH])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
		// decodefrombyte に変換
		// unmarshalPcepTLVs(&report.LspObject.Tlvs, buf[8:tlvLength]) // common header: 4byte, [PLSP-ID, flag]: 4byte で 8byte 除いた
		// for _, tlv := range report.LspObject.Tlvs {
		// 	if tlv.Type == TLV_SYMBOLIC_PATH_NAME {
		// 		report.LspObject.Name = string(tlv.Value)
		// 	}
		// }
	case OC_SRP:
		fmt.Printf(" Decode OC_SRP (%v)\n", commonObjectHeader.ObjectClass)
		err := o.SrpObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
	case OC_VENDOR_INFORMATION:
		fmt.Printf(" Decode OC_VENDOR_INFORMATION (%v)\n", commonObjectHeader.ObjectClass)
		err := o.VendorInformationObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
	default:
		fmt.Printf(" Unimplemented Object-Class: %v\n", commonObjectHeader.ObjectClass)
	}

	if int(commonObjectHeader.ObjectLength) < len(bytePcrptObject) {
		if err := o.DecodeFromBytes(bytePcrptObject[commonObjectHeader.ObjectLength:]); err != nil {
			return err
		}
	}
	return nil
}

//////////////////////// PCInitiate Message //////////////////////////////
type PCInitiateMessage struct {
	SrpObject               SrpObject
	LspObject               LspObject
	EndpointObject          EndpointObject
	EroObject               EroObject
	VendorInformationObject VendorInformationObject
}

func NewPCInitiateMessage(srpId uint32, lspName string, labels []Label, color uint32, preference uint32, srcIPv4 []uint8, dstIPv4 []uint8) PCInitiateMessage {
	var pcInitiateMessage PCInitiateMessage
	pcInitiateMessage.SrpObject = NewSrpObject(srpId, false)
	pcInitiateMessage.LspObject = NewLspObject(lspName, 0)                    // PLSP-ID = 0
	pcInitiateMessage.EndpointObject = NewEndpointObject(1, dstIPv4, srcIPv4) // objectType = 1 (IPv4)
	pcInitiateMessage.EroObject = NewEroObject(labels)
	pcInitiateMessage.VendorInformationObject = NewVendorInformationObject("Cisco", color, preference)
	return pcInitiateMessage
}

func (o *PCInitiateMessage) Serialize() ([]uint8, error) {
	byteSrpObject, err := o.SrpObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteLspObject, err := o.LspObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteEndpointObject, err := o.EndpointObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteEroObject, err := o.EroObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteVendorInformationObject, err := o.VendorInformationObject.Serialize()
	if err != nil {
		return nil, err
	}
	pcinitiateHeaderLength := COMMON_HEADER_LENGTH + o.SrpObject.getByteLength() + o.LspObject.getByteLength() + o.EndpointObject.getByteLength() + o.EroObject.getByteLength() + o.VendorInformationObject.getByteLength()

	pcinitiateHeader := NewCommonHeader(MT_LSPINITREQ, pcinitiateHeaderLength)
	bytePCInitiateHeader, err := pcinitiateHeader.Serialize()
	if err != nil {
		return nil, err
	}
	bytePCInitiateMessage := AppendByteSlices(bytePCInitiateHeader, byteSrpObject, byteLspObject, byteEndpointObject, byteEroObject, byteVendorInformationObject)

	return bytePCInitiateMessage, nil
}

//////////////////////// PCUpdate Message //////////////////////////////

// func NewPCUpdObjects(path Path) []uint8 {
// 	// TODO: 経路のパラメータによってはObjectの数変わる？要調査
// 	byteSrpObject := NewSrpObject()
// 	byteLspObject := EncapLspObject(path.LspObject)
// 	byteEroObject := NewEroObject(path.SrEroSubobjects)
// 	byteLspaObject := EncapLspaObject(path.LspaObject)
// 	byteMetricObject := EncapMetricObject(path.MetricObject)
// 	byteObjects := appendByteSlices(byteSrpObject, byteLspObject, byteEroObject, byteLspaObject, byteMetricObject)
// 	return (byteObjects)
// }

/* utils */
func i32tob(value uint32) []uint8 {
	// uint32(0x1a2b3c4d) -> []byte{0x1a, 0x2b, 0x3c, 0x4d}
	bytes := make([]uint8, 4)
	for i := uint32(0); i < 4; i++ {
		bytes[i] = uint8((value >> (24 - (8 * i))) & 0xff)
	}
	return bytes
}
