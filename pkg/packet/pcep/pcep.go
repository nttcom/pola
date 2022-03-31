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
	"net"

	pb "github.com/nttcom/pola/api/grpc"
)

var srpID = 100000

type Server struct {
	hashKey []uint8
}

func NewServer() *Server {
	return &Server{}
}

func appendByteSlices(byteSlices ...[]uint8) []uint8 {
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

const COMMON_HEADER_LENGTH = 4

const (
	// PCEP Message-Type
	MT_RESERVED     = 0x00 // RFC5440
	MT_OPEN         = 0x01 // RFC5440
	MT_KEEPALIVE    = 0x02 // RFC5440
	MT_PCREQ        = 0x03 // RFC5440
	MT_PCREP        = 0x04 // RFC5440
	MT_NOTIFICATION = 0x05 // RFC5440
	MT_ERROR        = 0x06 // RFC5440
	MT_CLOSE        = 0x07 // RFC5440
	MT_PCMONREQ     = 0x08 // RFC5886
	MT_PCMONREP     = 0x09 // RFC5886
	MT_REPORT       = 0x0a // RFC8231
	MT_UPDATE       = 0x0b // RFC8281
	MT_LSPINITREQ   = 0x0c // RFC8281
	MT_STARTTLS     = 0x0d // RFC8253
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

func NewCommonHeader(messageType uint8, messageLength uint16) []uint8 {
	commonHeader := CommonHeader{
		Version:       uint8(1),
		Flag:          uint8(0),
		MessageType:   messageType,
		MessageLength: messageLength,
	}
	buf, err := commonHeader.Serialize()
	if err != nil {
		log.Fatal(nil)
	}
	return buf
}

const COMMON_OBJECT_HEADER_LENGTH = 4

const (
	// PCEP Object-Class
	OC_RESERVED       = 0x00 // RFC5440
	OC_OPEN           = 0x01 // RFC5440
	OC_RP             = 0x02 // RFC5440
	OC_NO_PATH        = 0x03 // RFC5440
	OC_END_POINTS     = 0x04 // RFC5440
	OC_BANDWIDTH      = 0x05 // RFC5440
	OC_METRIC         = 0x06 // RFC5440
	OC_ERO            = 0x07 // RFC5440
	OC_RRO            = 0x08 // RFC5440
	OC_LSPA           = 0x09 // RFC5440
	OC_IRO            = 0x0a // RFC5440
	OC_SVRC           = 0x0b // RFC5440
	OC_NOTIFICATION   = 0x0c // RFC5440
	OC_PCEP_ERROR     = 0x0d // RFC5440
	OC_LOAD_BALANCING = 0x0e // RFC5440
	OC_CLOSE          = 0x0f // RFC5440
	OC_PATH_KEY       = 0x10 // RFC5520
	OC_XRO            = 0x11 // RFC5521
	// 0x12 is Unassigned
	OC_MONITORING = 0x13 // RFC5886
	OC_PCC_REQ_ID = 0x14 // RFC5886
	OC_OF         = 0x15 // RFC5541
	OC_CLASSTYPE  = 0x16 // RFC5455
	// 0x17 is Unassigned
	OC_GLOBAL_CONSTRAINTS  = 0x18 // RFC5557
	OC_PCE_ID              = 0x19 // RFC5886
	OC_PROC_TIME           = 0x1a // RFC5886
	OC_OVERLOAD            = 0x1b // RFC5886
	OC_UNREACH_DESTINATION = 0x1c // RFC8306
	OC_SERO                = 0x1d // RFC8306
	OC_SRRO                = 0x1e // RFC8306
	OC_BNC                 = 0x1f // RFC8306
	OC_LSP                 = 0x20 // RFC8231
	OC_SRP                 = 0x21 // RFC8231
	OC_VENDOR_INFORMATION  = 0x22 // RFC7470
	OC_BU                  = 0x23 // RFC8233
	OC_INTER_LAYER         = 0x24 // RFC8282
	OC_SWITCH_LAYER        = 0x25 // RFC8282
	OC_REQ_ADAP_CAP        = 0x26 // RFC8282
	OC_SERVER_INDICATION   = 0x27 // RFC8282
	OC_ASSOCIATION         = 0x28 // RFC8697
	OC_S2LS                = 0x29 // RFC8623
	OC_WA                  = 0x2a // RFC8780
	OC_FLOWSPEC            = 0x2b // draft-ietf-pce-pcep-flowspec-12
	OC_CCI_OBJECT_TYPE     = 0x2c // RFC9050
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
func NewCommonObjectHeader(objectClass uint8, objectType uint8, messageLength uint16) []uint8 {
	commonObjectHeader := CommonObjectHeader{
		ObjectClass:  objectClass,
		ObjectType:   objectType,
		ResFlags:     uint8(0), // MUST be set to zero
		PFlag:        false,    // 0: optional, 1: MUST
		IFlag:        false,    // 0: processed, 1: ignored
		ObjectLength: messageLength,
	}
	buf, err := commonObjectHeader.Serialize()
	if err != nil {
		fmt.Printf("common obj error")
		log.Fatal(nil)
	}
	return buf
}

func EncapCommonObjectHeader(body []uint8, metricType uint8) []uint8 { // TODO: TLVも追加する
	messageLength := uint16(len(body) + COMMON_OBJECT_HEADER_LENGTH)
	header := NewCommonObjectHeader(metricType, 1, messageLength) // 第二引数は object type = LSP(1) の意
	buf := append(header, body...)
	return buf
}

type Tlv struct {
	Type   uint16
	Length uint16
	Value  []uint8
}

func (tlv *Tlv) SetLength() {
	tlv.Length = uint16(len(tlv.Value))
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

func marshalPcepTLVs(pcepTLVs []Tlv) []uint8 {
	var bytePcepTLVs []uint8
	// ToDo: 書き直す
	// TLV の struct 情報をもとに作成できるようにする
	for _, tlv := range pcepTLVs {
		byteTlvType := make([]uint8, 2)
		binary.BigEndian.PutUint16(byteTlvType, tlv.Type)
		byteTlvLength := make([]uint8, 2)
		binary.BigEndian.PutUint16(byteTlvLength, tlv.Length)

		bytePcepTLV := []uint8{}
		bytePcepTLV = append(bytePcepTLV, byteTlvType...)   // Type (2byte)
		bytePcepTLV = append(bytePcepTLV, byteTlvLength...) // Length (2byte)
		bytePcepTLV = append(bytePcepTLV, tlv.Value...)     // Value (Length byte)
		if padding := tlv.Length % 4; padding != 0 {
			bytePadding := make([]uint8, 4-padding)
			fmt.Printf("\n\n%#v\n\n", bytePadding)
			bytePcepTLV = append(bytePcepTLV, bytePadding...)
		}
		bytePcepTLVs = append(bytePcepTLVs, bytePcepTLV...)
	}

	return bytePcepTLVs
}

type Path struct {
	LspObject               LspObject
	SrEroSubobjects         []SrEroSubobject
	LspaObject              LspaObject
	MetricObject            MetricObject
	EndpointObject          EndpointObject
	VendorInformationObject VendorInformationObject
}

func (path *Path) AddSREroSubobjects(labels []Label) {
	for _, label := range labels {
		srEroSubobject := SrEroSubobject{
			LFlag:         false,
			SubobjectType: uint8(ERO_SUBOBJECT_SR),
			Length:        uint8(12),
			NaiType:       uint8(NT_IPV4_NODE), // SID: NodeSID NAI: ipv4 address
			FFlag:         false,
			SFlag:         false,
			CFlag:         false,
			MFlag:         true, // TODO: MPLS Label判定
			Sid:           uint32(label.Sid << 12),
			Nai:           label.LoAddr,
		}
		path.SrEroSubobjects = append(path.SrEroSubobjects, srEroSubobject)
	}
}

type PcrptObjects struct {
	SrpObject               SrpObject
	LspObject               LspObject
	SrEroSubobject          SrEroSubobject
	LspaObject              LspaObject
	MetricObjects           []MetricObject
	BandwidthObjects        []BandwidthObject
	VendorInformationObject VendorInformationObject
}

type Label struct {
	Sid    uint32
	LoAddr []uint8
}

///////////////////////////////////////////////////////////////////
//////////////////////// open object //////////////////////////////
type OpenObject struct { // RFC5440 7.3
	Version   uint8
	Flag      uint8
	Keepalive uint8
	Deadtime  uint8
	Sid       uint8
}

func (o *OpenObject) DecodeFromBytes(data []uint8) error {
	o.Version = uint8(data[0] >> 5)
	o.Flag = uint8(data[0] & 0x1f)
	o.Keepalive = uint8(data[1])
	o.Deadtime = uint8(data[2])
	o.Sid = uint8(data[3])
	return nil
}

func (o *OpenObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 0, 4)
	verFlag := uint8(o.Version<<5 | o.Flag)
	buf = append(buf, verFlag)
	buf = append(buf, o.Keepalive)
	buf = append(buf, o.Deadtime)
	buf = append(buf, o.Sid)
	return buf, nil
}

func NewOpenObject(sessionID uint8) []uint8 {
	openObject := OpenObject{
		Version:   uint8(1),
		Flag:      uint8(0),
		Keepalive: uint8(30),
		Deadtime:  uint8(120),
		Sid:       sessionID,
	}
	buf, err := openObject.Serialize()
	if err != nil {
		fmt.Printf("open obj error")
		log.Fatal(nil)
	}
	return buf
}

const ERO_SUBOBJECT_SR = 0x24

const (
	NT_ABSENT                   = 0 // RFC 8664 4.3.1
	NT_IPV4_NODE                = 1 // RFC 8664 4.3.1
	NT_IPV6_NODE                = 2 // RFC 8664 4.3.1
	NT_IPV4_ADJACENCY           = 3 // RFC 8664 4.3.1
	NT_IPV6_ADJACENCY_GLOBAL    = 4 // RFC 8664 4.3.1
	NT_UNNUMBERED_ADJACENCY     = 5 // RFC 8664 4.3.1
	NT_IPV6_ADJACENCY_LINKLOCAL = 6 // RFC 8664 4.3.1
)

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

func EncapMetricObject(o MetricObject) []uint8 {
	body, err := o.Serialize()
	if err != nil {
		fmt.Printf("metric error")
		log.Fatal(nil)
	}
	buf := EncapCommonObjectHeader(body, OC_METRIC)
	return buf
}

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

func EncapLspaObject(o LspaObject) []uint8 {
	body, err := o.Serialize()
	if err != nil {
		fmt.Printf("lspa obj error")
		log.Fatal(nil)
	}
	buf := EncapCommonObjectHeader(body, OC_LSPA)
	return buf
}

//////////////////////// srp object //////////////////////////////
type SrpObject struct { // RFC8281 5.2
	RFlag bool
	SrpId uint32
}

func (o *SrpObject) DecodeFromBytes(data []uint8) error {
	o.RFlag = (data[3] & 0x01) != 0
	o.SrpId = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (o *SrpObject) Serialize() ([]uint8, error) {
	flags := make([]uint8, 4, 4)
	if o.RFlag {
		flags[3] = flags[3] | 0x01
	}
	srpId := make([]uint8, 4)
	binary.BigEndian.PutUint32(srpId, o.SrpId)
	buf := append(flags, srpId...)
	return buf, nil
}

func newSrpObjectBody() []uint8 {
	srpID += 1
	srpObject := SrpObject{
		RFlag: false,
		SrpId: uint32(10), // 正しいものを入れる
	}
	buf, err := srpObject.Serialize()
	if err != nil {
		fmt.Printf("srp obj error")
		log.Fatal(nil)
	}
	return buf
}

func newSrpObjectTLVs() []uint8 {
	pcepTLVs := [...]Tlv{Tlv{
		Type:   TLV_PATH_SETUP_TYPE,
		Length: TLV_PATH_SETUP_TYPE_LENGTH,
		Value:  []uint8{0x00, 0x00, 0x00, 0x01},
	}}
	bytePcepTLVs := marshalPcepTLVs(pcepTLVs[:])
	return bytePcepTLVs
}

func NewSrpObject() []uint8 {
	// SRP はこの TLV 固定?
	bytePcepTLVs := newSrpObjectTLVs()
	byteSrpObjectBody := newSrpObjectBody()
	messageLength := uint16(len(byteSrpObjectBody) + len(bytePcepTLVs) + COMMON_OBJECT_HEADER_LENGTH)

	byteCommonObjectHeader := NewCommonObjectHeader(OC_SRP, 1, messageLength)
	byteSrpObject := appendByteSlices(byteCommonObjectHeader, byteSrpObjectBody, bytePcepTLVs)
	return byteSrpObject
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
	return nil
}

func (o *LspObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 4)
	binary.BigEndian.PutUint32(buf, uint32(o.PlspId*4096)+uint32(o.OFlag*16))
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
	return buf, nil
}

func EncapLspObject(o LspObject) []uint8 {
	body, err := o.Serialize()
	if err != nil {
		fmt.Printf("enc lsp error")

		log.Fatal(nil)
	}
	buf := EncapCommonObjectHeader(body, OC_LSP)
	return buf
}

func EncapLspObjectForInitiate(o LspObject) []uint8 {
	body, err := o.Serialize()
	if err != nil {
		fmt.Printf("enc lsp for init error")
		log.Fatal(nil)
	}
	// lspTLV := [...]int{TLV_SYMBOLIC_PATH_NAME}
	lspTLV := [...]Tlv{Tlv{
		Type:   TLV_SYMBOLIC_PATH_NAME,
		Length: 0x00, //可変
		Value:  []uint8(o.Name),
	}}
	lspTLV[0].SetLength()

	// ToDo: length と pathname value を可変にする
	byteLspTLV := marshalPcepTLVs(lspTLV[:])
	fmt.Printf("lsptlv: %#v\n\n", byteLspTLV)
	body = appendByteSlices(body, byteLspTLV)
	buf := EncapCommonObjectHeader(body, OC_LSP)
	return buf
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
	buf := i32tob(o.EnterpriseNumber)
	tlvColor := []uint8{0x00, 0x01, 0x00, 0x04} // type: 1, length : 4
	tlvColor = appendByteSlices(tlvColor, i32tob(o.Color))
	tlvPreference := []uint8{0x00, 0x03, 0x00, 0x04} // type: 3, length: 4
	tlvPreference = appendByteSlices(tlvPreference, i32tob(o.Preference))
	buf = appendByteSlices(buf, tlvColor, tlvPreference)
	return buf, nil
}

func NewVendorInformationObjectBody(vendorInfoObj VendorInformationObject) []uint8 {

	buf, err := vendorInfoObj.Serialize()
	if err != nil {
		log.Fatal(nil)
	}
	return buf
}

func NewVendorInformationObject(vendorInfoObj VendorInformationObject) []uint8 {
	byteEpObjectBody := NewVendorInformationObjectBody(vendorInfoObj)
	messageLength := uint16(len(byteEpObjectBody) + COMMON_OBJECT_HEADER_LENGTH)
	byteCommonObjectHeader := NewCommonObjectHeader(OC_VENDOR_INFORMATION, vendorInfoObj.ObjectType, messageLength)
	byteEpObject := appendByteSlices(byteCommonObjectHeader, byteEpObjectBody)
	return byteEpObject
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
	return buf, nil
}

//////////////////////// ero object //////////////////////////////
func newEroObjectBody(srEroSubobjects []SrEroSubobject) []uint8 {
	// TODO: SegmentListの数だけループさせる
	eroObjectBody := []uint8{}
	for _, srEroSubobject := range srEroSubobjects {
		buf, err := srEroSubobject.Serialize()
		if err != nil {
			fmt.Printf("ero obj error")
			log.Fatal(nil)
		}
		byteSid := make([]uint8, 4)
		binary.BigEndian.PutUint32(byteSid, srEroSubobject.Sid)
		buf = appendByteSlices(buf, byteSid, srEroSubobject.Nai)
		eroObjectBody = appendByteSlices(eroObjectBody, buf)
	}

	return eroObjectBody
}

func NewEroObject(srEroSubobjects []SrEroSubobject) []uint8 {
	byteEroObjectBody := newEroObjectBody(srEroSubobjects)
	messageLength := uint16(len(byteEroObjectBody) + COMMON_OBJECT_HEADER_LENGTH)
	byteCommonObjectHeader := NewCommonObjectHeader(OC_ERO, 1, messageLength)
	byteEroObject := append(byteCommonObjectHeader, byteEroObjectBody...)
	return byteEroObject
}

//////////////////////// endpoint object //////////////////////////////
type ipv4 [4]uint8

type ipv6 [16]uint8

type EndpointObject struct {
	ObjectType uint8 // ipv4: 1, ipv6: 2
	srcIPv4    []uint8
	dstIPv4    []uint8
	srcIPv6    []uint8
	dstIPv6    []uint8
}

func NewEndpointObjectBody(epObj EndpointObject) []uint8 {
	var buf []uint8
	if epObj.ObjectType == 1 { //ipv4 処理
		buf = appendByteSlices(epObj.srcIPv4, epObj.dstIPv4)
	} else if epObj.ObjectType == 2 { //ipv6 処理
		buf = appendByteSlices(epObj.srcIPv6, epObj.dstIPv6)
	}
	return buf
}

func NewEndpointObject(epObject EndpointObject) []uint8 {
	byteEpObjectBody := NewEndpointObjectBody(epObject)
	messageLength := uint16(len(byteEpObjectBody) + COMMON_OBJECT_HEADER_LENGTH) //ここまでok
	byteCommonObjectHeader := NewCommonObjectHeader(OC_END_POINTS, epObject.ObjectType, messageLength)
	byteEpObject := appendByteSlices(byteCommonObjectHeader, byteEpObjectBody)
	return byteEpObject
}

///////////////////////////////////////////////////////////////////
//////////////////////// PCUpd object //////////////////////////////
func NewPCUpdObjects(path Path) []uint8 {
	// TODO: 経路のパラメータによってはObjectの数変わる？要調査
	byteSrpObject := NewSrpObject()
	byteLspObject := EncapLspObject(path.LspObject)
	byteEroObject := NewEroObject(path.SrEroSubobjects)
	byteLspaObject := EncapLspaObject(path.LspaObject)
	byteMetricObject := EncapMetricObject(path.MetricObject)
	byteObjects := appendByteSlices(byteSrpObject, byteLspObject, byteEroObject, byteLspaObject, byteMetricObject)
	return (byteObjects)
}

func (s *Server) ReadOpen(conn net.Conn) (uint8, error) {
	// Parse CommonHeader
	headerBuf := make([]uint8, COMMON_HEADER_LENGTH)

	_, err := conn.Read(headerBuf)
	if err != nil {
		return 0, err
	}

	var commonHeader CommonHeader
	err = commonHeader.DecodeFromBytes(headerBuf)
	if err != nil {
		return 0, err
	}

	// CommonHeader Validation
	if commonHeader.Version != 1 {
		log.Panicf("PCEP version mismatch: %i", commonHeader.Version)
	}
	if commonHeader.MessageType != MT_OPEN {
		log.Panicf("Message Type is : %i, This peer has not been opened.", commonHeader.MessageType)
	}

	fmt.Printf("[PCEP] Receive Open\n")

	// Parse objectClass
	objectClassBuf := make([]uint8, commonHeader.MessageLength-COMMON_HEADER_LENGTH)

	// connection に残っているものを上からとっていく?
	_, err = conn.Read(objectClassBuf)
	if err != nil {
		return 0, err
	}
	var commonObjectHeader CommonObjectHeader
	err = commonObjectHeader.DecodeFromBytes(objectClassBuf)
	if err != nil {
		return 0, err
	}
	// first get が open object でない場合は破棄
	if commonObjectHeader.ObjectClass != OC_OPEN {
		log.Panicf("ObjectClass %i is not Open", commonObjectHeader.ObjectClass)
	}

	if commonObjectHeader.ObjectType != 1 {
		log.Panicf("Unimplemented objectType: %i", commonObjectHeader.ObjectType)
	}

	var openObject OpenObject
	err = openObject.DecodeFromBytes(objectClassBuf)
	if err != nil {
		return 0, err
	}

	// ToDo: 何か受け取って処理する
	// unmarshalPcepTLVs(objectClassBuf)

	return openObject.Sid, nil
}

func (s *Server) ReadPcepHeader(conn net.Conn) (messageType uint8, messageLength uint16) {
	headerBuf := make([]uint8, COMMON_HEADER_LENGTH)

	_, err := conn.Read(headerBuf)
	if err != nil {
		fmt.Printf("read error \n")
		log.Fatal(nil)

	}

	var commonHeader CommonHeader
	err = commonHeader.DecodeFromBytes(headerBuf)
	if err != nil {

		fmt.Printf("read pcep error")
		log.Fatal(nil)
	}

	return commonHeader.MessageType, commonHeader.MessageLength
}

func parsePcrpt(buf []uint8, report *PcrptObjects) {
	var commonObjectHeader CommonObjectHeader
	err := commonObjectHeader.DecodeFromBytes(buf)
	if err != nil {
		fmt.Printf("PCRpt parse error\n")
		log.Fatal(nil)
	}
	fmt.Printf(" Start Parse PCRpt\n")
	switch commonObjectHeader.ObjectClass {
	case OC_BANDWIDTH:
		fmt.Printf(" Decode OC_BANDWIDTH (%v)\n", commonObjectHeader.ObjectClass)
		var bandwidthObject BandwidthObject
		err = bandwidthObject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
		report.BandwidthObjects = append(report.BandwidthObjects, bandwidthObject)
	case OC_METRIC:
		fmt.Printf(" Decode OC_METRIC (%v)\n", commonObjectHeader.ObjectClass)
		var metricObject MetricObject
		err = metricObject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
		report.MetricObjects = append(report.MetricObjects, metricObject)
	case OC_ERO:
		fmt.Printf(" Decode OC_ERO (%v)\n", commonObjectHeader.ObjectClass)
		// report.SrEroSubobject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
	case OC_LSPA:
		fmt.Printf(" Decode OC_LSPA (%v)\n", commonObjectHeader.ObjectClass)
		err := report.LspaObject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
	case OC_LSP:
		fmt.Printf(" Decode OC_LSP (%v)\n", commonObjectHeader.ObjectClass)
		tlvLength := commonObjectHeader.ObjectLength - COMMON_OBJECT_HEADER_LENGTH
		err := report.LspObject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH : tlvLength+COMMON_OBJECT_HEADER_LENGTH])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
		fmt.Printf("lsp buf: %#v\n\n", buf)
		unmarshalPcepTLVs(&report.LspObject.Tlvs, buf[8:tlvLength]) // common header: 4byte, [PLSP-ID, flag]: 4byte で 8byte 除いた
		for _, tlv := range report.LspObject.Tlvs {
			if tlv.Type == TLV_SYMBOLIC_PATH_NAME {
				report.LspObject.Name = string(tlv.Value)
			}
		}
	case OC_SRP:
		fmt.Printf(" Decode OC_SRP (%v)\n", commonObjectHeader.ObjectClass)
		err := report.SrpObject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
	case OC_VENDOR_INFORMATION:
		fmt.Printf(" Decode OC_VENDOR_INFORMATION (%v)\n", commonObjectHeader.ObjectClass)
		err := report.VendorInformationObject.DecodeFromBytes(buf[COMMON_OBJECT_HEADER_LENGTH:])
		if err != nil {
			fmt.Printf("parse error")
			log.Fatal(nil)
		}
	default:
		fmt.Printf(" Unimplemented Object-Class: %v\n", commonObjectHeader.ObjectClass)
	}

	if int(commonObjectHeader.ObjectLength) < len(buf) {
		parsePcrpt(buf[commonObjectHeader.ObjectLength:], report)
	}
}

func (s *Server) ReadPcrpt(conn net.Conn, messageLength uint16, report *PcrptObjects) {
	buf := make([]uint8, messageLength-COMMON_HEADER_LENGTH)
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Printf("PCRpt read error")
		log.Fatal(nil)
	}
	parsePcrpt(buf, report)
}

func (s *Server) SendOpen(conn net.Conn, sessionID uint8) error {
	byteOpenObject := NewOpenObject(sessionID)
	// pcepTLVs := [...]int{TLV_STATEFUL_PCE_CAPABILITY, TLV_SR_PCE_CAPABILITY, TLV_ASSOC_TYPE_LIST}
	pcepTLVs := [...]Tlv{
		Tlv{
			Type:   TLV_STATEFUL_PCE_CAPABILITY,
			Length: TLV_STATEFUL_PCE_CAPABILITY_LENGTH,
			Value:  []uint8{0x00, 0x00, 0x00, 0x05},
		},
		Tlv{
			Type:   TLV_SR_PCE_CAPABILITY,
			Length: TLV_SR_PCE_CAPABILITY_LENGTH,
			Value:  []uint8{0x00, 0x00, 0x00, 0x0a},
		},
		Tlv{
			Type:   TLV_ASSOC_TYPE_LIST,
			Length: TLV_ASSOC_TYPE_LIST_LENGTH,
			Value:  []uint8{0x00, 0x14},
		},
	}
	bytePcepTLVs := marshalPcepTLVs(pcepTLVs[:])

	messageLength := uint16(len(byteOpenObject) + len(bytePcepTLVs) + COMMON_OBJECT_HEADER_LENGTH)
	byteCommonObjectHeader := NewCommonObjectHeader(OC_OPEN, 1, messageLength)

	byteCommonHeader := NewCommonHeader(MT_OPEN, uint16(messageLength+COMMON_HEADER_LENGTH))

	openMessage := appendByteSlices(byteCommonHeader, byteCommonObjectHeader, byteOpenObject, bytePcepTLVs)

	fmt.Printf("[PCEP] Send Open\n")
	_, err := conn.Write(openMessage)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) SendKeepAlive(conn net.Conn) error {
	byteCommonHeader := NewCommonHeader(MT_KEEPALIVE, uint16(COMMON_HEADER_LENGTH))

	fmt.Printf("[PCEP] Send KeepAlive\n")
	_, err := conn.Write(byteCommonHeader)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) SendPCUpd(conn net.Conn, path Path) {
	byteObjects := NewPCUpdObjects(path)

	messageLength := uint16(len(byteObjects) + COMMON_HEADER_LENGTH)
	byteCommonHeader := NewCommonHeader(MT_UPDATE, messageLength)

	pcupdMessage := append(byteCommonHeader, byteObjects...)

	fmt.Printf("[PCEP] Send PCUpd\n")
	_, err := conn.Write(pcupdMessage)
	if err != nil {
		fmt.Printf("pcupd error")
		log.Fatal(nil)
	}
}

func NewPCInitiateObjects(path Path) []uint8 {
	byteSrpObject := NewSrpObject()

	byteLspObject := EncapLspObjectForInitiate(path.LspObject)
	fmt.Printf("lspObject: %#v\n", byteLspObject)

	byteEpObject := NewEndpointObject(path.EndpointObject)

	byteEroObject := NewEroObject(path.SrEroSubobjects)

	byteVenderInfoObject := NewVendorInformationObject(path.VendorInformationObject)

	byteObjects := appendByteSlices(byteSrpObject, byteLspObject, byteEpObject, byteEroObject, byteVenderInfoObject)

	return (byteObjects)
}

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

func (s *Server) SendPCInitiate(conn net.Conn, lspData *pb.LspData) error {
	fmt.Printf(" *********************Start PCInitiate \n")
	// PCInitiate 用の オブジェクトを作成
	initiatePath := Path{
		// policy name を作ってみたけどまだ使っていない
		LspObject: LspObject{
			Name:   lspData.PolicyName,
			PlspId: uint32(0), // initiate は pslpID=0
			OFlag:  uint8(0),
			AFlag:  true,
			RFlag:  false,
			SFlag:  false,
			DFlag:  false,
		},
		SrEroSubobjects: []SrEroSubobject{},
		EndpointObject: EndpointObject{
			ObjectType: 1, // ipv4: 1, ipv6: 2,
			dstIPv4:    lspData.GetDstAddr(),
			srcIPv4:    lspData.GetSrcAddr(),
		},
		VendorInformationObject: VendorInformationObject{
			ObjectType:       uint8(1),
			EnterpriseNumber: uint32(9),
			Color:            uint32(lspData.Color),
			Preference:       uint32(50),
		},
	}

	labels := []Label{}
	for _, receivedLabel := range lspData.GetLabels() {
		tmpLabel := Label{
			Sid:    receivedLabel.GetSid(),
			LoAddr: receivedLabel.GetLoAddr(),
		}
		labels = append(labels, tmpLabel)
	}

	initiatePath.AddSREroSubobjects(labels)
	byteObjects := NewPCInitiateObjects(initiatePath)
	messageLength := uint16(len(byteObjects) + COMMON_HEADER_LENGTH)
	// 各オブジェクトを作成して、さいごに concat
	byteCommonHeader := NewCommonHeader(MT_LSPINITREQ, messageLength)
	InitiateMessage := appendByteSlices(byteCommonHeader, byteObjects)

	fmt.Printf("******************** [PCEP] Send Initiate\n")
	_, err := conn.Write(InitiateMessage)

	if err != nil {
		fmt.Printf("initiate error")
		return err
	}
	return nil
}

func i32tob(value uint32) []uint8 {
	// uint32(0x1a2b3c4d) -> []byte{0x1a, 0x2b, 0x3c, 0x4d}
	bytes := make([]uint8, 4)
	for i := uint32(0); i < 4; i++ {
		bytes[i] = uint8((value >> (24 - (8 * i))) & 0xff)
	}
	return bytes
}
