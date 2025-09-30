// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"

	"github.com/nttcom/pola/internal/pkg/table"
)

type PccType int

const commonObjectHeaderLength uint16 = 4

// PCEP Object-Class (1 byte) Ref: https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-objects
type ObjectClass uint8
type ObjectType uint8
type SubObjectType uint8

const (
	ObjectClassOpen                              ObjectClass = 0x01
	ObjectClassRP                                ObjectClass = 0x02
	ObjectClassNoPath                            ObjectClass = 0x03
	ObjectClassEndpoints                         ObjectClass = 0x04
	ObjectClassBandwidth                         ObjectClass = 0x05
	ObjectClassMetric                            ObjectClass = 0x06
	ObjectClassERO                               ObjectClass = 0x07
	ObjectClassRRO                               ObjectClass = 0x08
	ObjectClassLSPA                              ObjectClass = 0x09
	ObjectClassIRO                               ObjectClass = 0x0a
	ObjectClassSVEC                              ObjectClass = 0x0b
	ObjectClassNotification                      ObjectClass = 0x0c
	ObjectClassPCEPError                         ObjectClass = 0x0d
	ObjectClassLoadBalancing                     ObjectClass = 0x0e
	ObjectClassClose                             ObjectClass = 0x0f
	ObjectClassPathKey                           ObjectClass = 0x10
	ObjectClassXRO                               ObjectClass = 0x11
	ObjectClassMonitoring                        ObjectClass = 0x13
	ObjectClassPCCReqID                          ObjectClass = 0x14
	ObjectClassOF                                ObjectClass = 0x15
	ObjectClassClassType                         ObjectClass = 0x16
	ObjectClassGlobalConstraints                 ObjectClass = 0x18
	ObjectClassPCEID                             ObjectClass = 0x19
	ObjectClassProcTime                          ObjectClass = 0x1a
	ObjectClassOverload                          ObjectClass = 0x1b
	ObjectClassUnreachDestination                ObjectClass = 0x1c
	ObjectClassSERO                              ObjectClass = 0x1d
	ObjectClassSRRO                              ObjectClass = 0x1e
	ObjectClassBNC                               ObjectClass = 0x1f
	ObjectClassLSP                               ObjectClass = 0x20
	ObjectClassSRP                               ObjectClass = 0x21
	ObjectClassVendorInformation                 ObjectClass = 0x22
	ObjectClassBU                                ObjectClass = 0x23
	ObjectClassInterLayer                        ObjectClass = 0x24
	ObjectClassSwitchLayer                       ObjectClass = 0x25
	ObjectClassReqAdapCap                        ObjectClass = 0x26
	ObjectClassServerIndication                  ObjectClass = 0x27
	ObjectClassAssociation                       ObjectClass = 0x28
	ObjectClassS2LS                              ObjectClass = 0x29
	ObjectClassWA                                ObjectClass = 0x2a
	ObjectClassFlowSpec                          ObjectClass = 0x2b
	ObjectClassCCIObjectType                     ObjectClass = 0x2c
	ObjectClassPathAttrib                        ObjectClass = 0x2d
	ObjectClassBGPPeerInfoObjectType             ObjectClass = 0x2e
	ObjectClassExplicitPeerRouteObjectType       ObjectClass = 0x2f
	ObjectClassPeerPrefixAdvertisementObjectType ObjectClass = 0x30
)

var objectClassDescriptions = map[ObjectClass]struct {
	Description string
	Reference   string
}{
	ObjectClassOpen:                              {"Open", "RFC5440"},
	ObjectClassRP:                                {"RP", "RFC5440"},
	ObjectClassNoPath:                            {"NO-PATH", "RFC5440"},
	ObjectClassEndpoints:                         {"END-POINTS", "RFC5440"},
	ObjectClassBandwidth:                         {"BANDWIDTH", "RFC5440"},
	ObjectClassMetric:                            {"METRIC", "RFC5440"},
	ObjectClassERO:                               {"ERO", "RFC5440"},
	ObjectClassRRO:                               {"RRO", "RFC5440"},
	ObjectClassLSPA:                              {"LSPA", "RFC5440"},
	ObjectClassIRO:                               {"IRO", "RFC5440"},
	ObjectClassSVEC:                              {"SVEC", "RFC5440"},
	ObjectClassNotification:                      {"NOTIFICATION", "RFC5440"},
	ObjectClassPCEPError:                         {"PCEP-ERROR", "RFC5440"},
	ObjectClassLoadBalancing:                     {"LOAD-BALANCING", "RFC5440"},
	ObjectClassClose:                             {"CLOSE", "RFC5440"},
	ObjectClassPathKey:                           {"PATH-KEY", "RFC5520"},
	ObjectClassXRO:                               {"XRO", "RFC5521"},
	ObjectClassMonitoring:                        {"MONITORING", "RFC5886"},
	ObjectClassPCCReqID:                          {"PCC-REQ-ID", "RFC5886"},
	ObjectClassOF:                                {"OF", "RFC5541"},
	ObjectClassClassType:                         {"CLASSTYPE", "RFC5455"},
	ObjectClassGlobalConstraints:                 {"GLOBAL-CONSTRAINTS", "RFC5557"},
	ObjectClassPCEID:                             {"PCE-ID", "RFC5886"},
	ObjectClassProcTime:                          {"PROC-TIME", "RFC5886"},
	ObjectClassOverload:                          {"OVERLOAD", "RFC5886"},
	ObjectClassUnreachDestination:                {"UNREACH-DESTINATION", "RFC8306"},
	ObjectClassSERO:                              {"SERO", "RFC8306"},
	ObjectClassSRRO:                              {"SRRO", "RFC8306"},
	ObjectClassBNC:                               {"BNC", "RFC8306"},
	ObjectClassLSP:                               {"LSP", "RFC8231"},
	ObjectClassSRP:                               {"SRP", "RFC8231"},
	ObjectClassVendorInformation:                 {"VENDOR-INFORMATION", "RFC7470"},
	ObjectClassBU:                                {"BU", "RFC8233"},
	ObjectClassInterLayer:                        {"INTER-LAYER", "RFC8282"},
	ObjectClassSwitchLayer:                       {"SWITCH-LAYER", "RFC8282"},
	ObjectClassReqAdapCap:                        {"REQ-ADAP-CAP", "RFC8282"},
	ObjectClassServerIndication:                  {"SERVER-INDICATION", "RFC8282"},
	ObjectClassAssociation:                       {"ASSOCIATION", "RFC8697"},
	ObjectClassS2LS:                              {"S2LS", "RFC8623"},
	ObjectClassWA:                                {"WA", "RFC8780"},
	ObjectClassFlowSpec:                          {"FLOWSPEC", "RFC9168"},
	ObjectClassCCIObjectType:                     {"CCI", "RFC9050"},
	ObjectClassPathAttrib:                        {"PATH-ATTRIB", "draft-ietf-pce-multipath-07"},
	ObjectClassBGPPeerInfoObjectType:             {"BGP-PEER-INFO", "RFC9757"},
	ObjectClassExplicitPeerRouteObjectType:       {"EXPLICIT-PEER-ROUTE", "RFC9757"},
	ObjectClassPeerPrefixAdvertisementObjectType: {"PEER-PREFIX-ADVERTISEMENT", "RFC9757"},
}

func (c ObjectClass) String() string {
	if desc, ok := objectClassDescriptions[c]; ok {
		return fmt.Sprintf("%s (0x%02x)", desc.Description, uint8(c))
	}
	return fmt.Sprintf("Unknown Object Class (0x%02x)", uint8(c))
}

func (c ObjectClass) StringWithReference() string {
	if desc, ok := objectClassDescriptions[c]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, c, desc.Reference)
	}
	return fmt.Sprintf("Unknown Object Class (0x%02x)", uint8(c))
}

type CommonObjectHeader struct { // RFC5440 7.2
	ObjectClass  ObjectClass
	ObjectType   ObjectType
	ResFlags     uint8 // MUST be set to zero
	PFlag        bool  // 0: optional, 1: MUST
	IFlag        bool  // 0: processed, 1: ignored
	ObjectLength uint16
}

const (
	IFlagMask uint8 = 0x01
	PFlagMask uint8 = 0x02
)

func (h *CommonObjectHeader) DecodeFromBytes(objectHeader []uint8) error {
	h.ObjectClass = ObjectClass(objectHeader[0])
	h.ObjectType = ObjectType((objectHeader[1] & 0xf0) >> 4)
	h.ResFlags = uint8((objectHeader[1] & 0x0c) >> 2)
	h.PFlag = (objectHeader[1] & PFlagMask) != 0
	h.IFlag = (objectHeader[1] & IFlagMask) != 0
	h.ObjectLength = binary.BigEndian.Uint16(objectHeader[2:4])
	return nil
}

func (h *CommonObjectHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	buf = append(buf, uint8(h.ObjectClass))
	Flagbyte := uint8(h.ObjectType)<<4 | uint8(h.ResFlags)<<2
	if h.PFlag {
		Flagbyte = Flagbyte | PFlagMask
	}
	if h.IFlag {
		Flagbyte = Flagbyte | IFlagMask
	}
	buf = append(buf, Flagbyte)
	buf = append(buf, Uint16ToByteSlice(h.ObjectLength)...)
	return buf
}

func NewCommonObjectHeader(objectClass ObjectClass, objectType ObjectType, messageLength uint16) *CommonObjectHeader {
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

// OPEN Object (RFC5440 7.3)
const (
	ObjectTypeOpenOpen ObjectType = 0x01
)

type OpenObject struct {
	ObjectType ObjectType
	Version    uint8
	Flag       uint8
	Keepalive  uint8
	Deadtime   uint8
	Sid        uint8
	Caps       []CapabilityInterface
}

func (o *OpenObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
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
	openObjectHeader := NewCommonObjectHeader(ObjectClassOpen, o.ObjectType, o.Len())
	byteOpenObjectHeader := openObjectHeader.Serialize()
	buf := make([]uint8, 4)
	buf[0] = o.Version << 5
	buf[1] = o.Keepalive
	buf[2] = o.Deadtime
	buf[3] = o.Sid

	byteTLVs := []uint8{}
	for _, cap := range o.Caps {
		byteTLVs = append(byteTLVs, cap.Serialize()...)
	}

	byteOpenObject := AppendByteSlices(byteOpenObjectHeader, buf, byteTLVs)
	return byteOpenObject
}

func (o *OpenObject) Len() uint16 {
	tlvsByteLength := uint16(0)
	for _, cap := range o.Caps {
		tlvsByteLength += cap.Len()
	}
	// TODO: Calculate TLV length and record in open_object_length
	// CommonObjectHeader(4byte) + openObject(4byte) + tlvslength(valiable)
	return commonObjectHeaderLength + 4 + tlvsByteLength
}

func NewOpenObject(sessionID uint8, keepalive uint8, capabilities []CapabilityInterface) (*OpenObject, error) {
	o := &OpenObject{
		ObjectType: ObjectTypeOpenOpen,
		Version:    uint8(1), // PCEP version. Current version is 1
		Flag:       uint8(0),
		Keepalive:  keepalive,
		Deadtime:   keepalive * 4,
		Sid:        sessionID,
		Caps:       capabilities,
	}
	return o, nil
}

// BANDWIDTH Object (RFC5440 7.7)
type BandwidthObject struct {
	ObjectType ObjectType
	Bandwidth  uint32
}

func (o *BandwidthObject) DecodeFromBytes(objectType ObjectType, objectBody []uint8) error {
	o.ObjectType = objectType
	o.Bandwidth = binary.BigEndian.Uint32(objectBody[:])
	return nil
}

// METRIC Object (RFC5440 7.8)
type MetricObject struct {
	ObjectType  ObjectType
	CFlag       bool
	BFlag       bool
	MetricType  uint8
	MetricValue uint32
}

func (o *MetricObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.CFlag = (objectBody[2] & 0x02) != 0
	o.BFlag = (objectBody[2] & 0x01) != 0
	o.MetricType = objectBody[3]
	o.MetricValue = binary.BigEndian.Uint32(objectBody[4:8])
	return nil
}

func (o *MetricObject) Serialize() []uint8 {
	metricObjectHeader := NewCommonObjectHeader(ObjectClassMetric, o.ObjectType, o.Len())
	byteMetricObjectHeader := metricObjectHeader.Serialize()

	buf := make([]uint8, 8)
	if o.CFlag {
		buf[2] = buf[2] | 0x02
	}
	if o.BFlag {
		buf[2] = buf[2] | 0x01
	}
	buf[3] = o.MetricType
	tmpMetVal := math.Float32bits(float32(o.MetricValue))
	binary.BigEndian.PutUint32(buf[4:8], tmpMetVal)
	byteMetricObject := AppendByteSlices(byteMetricObjectHeader, buf)
	return byteMetricObject
}

func (o *MetricObject) Len() uint16 {
	// CommonObjectHeader(4byte) + Flags, SRP-ID(8byte)
	return commonObjectHeaderLength + 8
}

func NewMetricObject() (*MetricObject, error) {
	o := &MetricObject{
		ObjectType:  ObjectType(1),
		MetricType:  uint8(2),
		MetricValue: uint32(30),
	}
	return o, nil
}

// LSPA Object (RFC5440 7.11)
type LSPAObject struct {
	ObjectType      ObjectType
	ExcludeAny      uint32
	IncludeAny      uint32
	IncludeAll      uint32
	SetupPriority   uint8
	HoldingPriority uint8
	LFlag           bool
}

func (o *LSPAObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.ExcludeAny = binary.BigEndian.Uint32(objectBody[0:4])
	o.IncludeAny = binary.BigEndian.Uint32(objectBody[4:8])
	o.IncludeAll = binary.BigEndian.Uint32(objectBody[8:12])
	o.SetupPriority = objectBody[12]
	o.HoldingPriority = objectBody[13]
	o.LFlag = (objectBody[14] & 0x01) != 0
	return nil
}

func (o *LSPAObject) Serialize() []uint8 {
	lspaObjectHeader := NewCommonObjectHeader(ObjectClassLSPA, o.ObjectType, o.Len())
	byteLSPAObjectHeader := lspaObjectHeader.Serialize()

	buf := make([]uint8, 16)
	binary.BigEndian.PutUint32(buf[0:4], o.ExcludeAny)
	binary.BigEndian.PutUint32(buf[4:8], o.IncludeAny)
	binary.BigEndian.PutUint32(buf[8:12], o.IncludeAll)
	buf[12] = o.SetupPriority
	buf[13] = o.HoldingPriority
	if o.LFlag {
		buf[14] = buf[14] | 0x01
	}

	byteLSPAObject := AppendByteSlices(byteLSPAObjectHeader, buf)
	return byteLSPAObject
}

func (o *LSPAObject) Len() uint16 {
	// CommonObjectHeader(4byte) + Flags, SRP-ID(8byte)
	return commonObjectHeaderLength + 16
}

func NewLSPAObject() (*LSPAObject, error) {
	o := &LSPAObject{
		ObjectType:      ObjectType(1),
		SetupPriority:   uint8(7),
		HoldingPriority: uint8(7),
		LFlag:           true,
	}
	return o, nil
}

// PCEP Error Object (RFC5440 7.15)
const (
	ObjectTypeErrorError ObjectType = 0x01
)

type PCEPErrorObject struct {
	ObjectType ObjectType
	ErrorType  uint8
	ErrorValue uint8
	Tlvs       []TLVInterface
}

func (o *PCEPErrorObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.ErrorType = objectBody[2]
	o.ErrorValue = objectBody[3]
	if len(objectBody) > 4 {
		byteTlvs := objectBody[4:]
		var err error
		if o.Tlvs, err = DecodeTLVs(byteTlvs); err != nil {
			return err
		}
	}
	return nil
}

func (o *PCEPErrorObject) Serialize() []uint8 {
	pcepErrorObjectHeader := NewCommonObjectHeader(ObjectClassPCEPError, o.ObjectType, o.Len())
	bytePCEPErrorObjectHeader := pcepErrorObjectHeader.Serialize()

	buf := make([]uint8, 4)

	buf[2] = o.ErrorType
	buf[3] = o.ErrorValue
	bytePCEPErrorObject := AppendByteSlices(bytePCEPErrorObjectHeader, buf)
	return bytePCEPErrorObject
}

func (o *PCEPErrorObject) Len() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.Len()
	}
	// CommonObjectHeader(4byte) + Flags,Error-Type,Error-value(4byte) + tlvslength(valiable)
	return commonObjectHeaderLength + 4 + tlvsByteLength
}

func NewPCEPErrorObject(errorType uint8, errorValue uint8, tlvs []TLVInterface) (*PCEPErrorObject, error) {
	o := &PCEPErrorObject{
		ObjectType: ObjectTypeErrorError,
		ErrorType:  errorType,
		ErrorValue: errorValue,
		Tlvs:       tlvs,
	}
	return o, nil
}

// Close Object (RFC5440 7.17)
const (
	ObjectTypeCloseClose ObjectType = 0x01
)

type CloseReason uint8

const (
	CloseReasonNoExplanationProvided           CloseReason = 0x01
	CloseReasonDeadTimerExpired                CloseReason = 0x02
	CloseReasonMalformedPCEPMessage            CloseReason = 0x03
	CloseReasonTooManyUnknownRequestsReplies   CloseReason = 0x04
	CloseReasonTooManyUnrecognizedPCEPMessages CloseReason = 0x05
)

var closeReasonDescriptions = map[CloseReason]struct {
	Description string
	Reference   string
}{
	CloseReasonNoExplanationProvided:           {"No explanation provided", "RFC5440"},
	CloseReasonDeadTimerExpired:                {"DeadTimer expired", "RFC5440"},
	CloseReasonMalformedPCEPMessage:            {"Reception of a malformed PCEP message", "RFC5440"},
	CloseReasonTooManyUnknownRequestsReplies:   {"Reception of an unacceptable number of unknown requests/replies", "RFC5440"},
	CloseReasonTooManyUnrecognizedPCEPMessages: {"Reception of an unacceptable number of unrecognized PCEP messages", "RFC5440"},
}

func (r CloseReason) String() string {
	if desc, ok := closeReasonDescriptions[r]; ok {
		return fmt.Sprintf("%s (0x%02x)", desc.Description, uint8(r))
	}
	return fmt.Sprintf("Unknown Close Reason (0x%02x)", uint8(r))
}

func (r CloseReason) StringWithReference() string {
	if desc, ok := closeReasonDescriptions[r]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, r, desc.Reference)
	}
	return fmt.Sprintf("Unknown Close Reason (0x%02x)", uint8(r))
}

type CloseObject struct {
	ObjectType ObjectType
	Reason     CloseReason
}

func (o *CloseObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.Reason = CloseReason(objectBody[3])
	return nil
}

func (o *CloseObject) Serialize() []uint8 {
	closeObjectHeader := NewCommonObjectHeader(ObjectClassClose, o.ObjectType, o.Len())
	byteCloseObjectHeader := closeObjectHeader.Serialize()

	buf := make([]uint8, 4)

	buf[3] = uint8(o.Reason)
	byteCloseObject := AppendByteSlices(byteCloseObjectHeader, buf)
	return byteCloseObject
}

func (o *CloseObject) Len() uint16 {
	// CommonObjectHeader(4byte) + CloseObjectBody(4byte)
	return commonObjectHeaderLength + 4
}

func NewCloseObject(reason CloseReason) (*CloseObject, error) {
	o := &CloseObject{
		ObjectType: ObjectTypeCloseClose,
		Reason:     reason,
	}
	return o, nil
}

// SRP Object (RFC8231 7.2)
const (
	ObjectTypeSRPSRP ObjectType = 0x01
)

type SrpObject struct {
	ObjectType ObjectType
	RFlag      bool
	SrpID      uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	TLVs       []TLVInterface
}

func (o *SrpObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.RFlag = (objectBody[3] & 0x01) != 0
	o.SrpID = binary.BigEndian.Uint32(objectBody[4:8])
	return nil
}

func (o *SrpObject) Serialize() []uint8 {
	srpObjectHeader := NewCommonObjectHeader(ObjectClassSRP, o.ObjectType, o.Len())
	byteSrpObjectHeader := srpObjectHeader.Serialize()

	byteFlags := make([]uint8, 4)
	if o.RFlag {
		byteFlags[3] = byteFlags[3] | 0x01
	}
	byteSrpID := make([]uint8, 4)
	binary.BigEndian.PutUint32(byteSrpID, o.SrpID)

	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		byteTLVs = append(byteTLVs, tlv.Serialize()...)
	}
	byteSrpObject := AppendByteSlices(byteSrpObjectHeader, byteFlags, byteSrpID, byteTLVs)
	return byteSrpObject
}

func (o *SrpObject) Len() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	// CommonObjectHeader(4byte) + Flags, SRP-ID(8byte)
	return commonObjectHeaderLength + 8 + tlvsByteLength
}

func NewSrpObject(segs []table.Segment, srpID uint32, isRemove bool) (*SrpObject, error) {
	o := &SrpObject{
		ObjectType: ObjectTypeSRPSRP,
		RFlag:      isRemove, // RFC8281 5.2
		SrpID:      srpID,
		TLVs:       []TLVInterface{},
	}
	if len(segs) == 0 {
		return o, nil
	}
	if _, ok := segs[0].(table.SegmentSRMPLS); ok {
		o.TLVs = append(o.TLVs, &PathSetupType{PathSetupType: PathSetupTypeSRTE})
	} else if _, ok := segs[0].(table.SegmentSRv6); ok {
		o.TLVs = append(o.TLVs, &PathSetupType{PathSetupType: PathSetupTypeSRv6TE})
	} else {
		return nil, errors.New("invalid Segment type")
	}
	return o, nil
}

// LSP Object (RFC8281 5.3.1)
const (
	ObjectTypeLSPLSP ObjectType = 0x01
)

type LSPObject struct {
	ObjectType ObjectType
	Name       string
	SrcAddr    netip.Addr
	DstAddr    netip.Addr
	PlspID     uint32
	LSPID      uint16
	CFlag      bool
	OFlag      uint8
	AFlag      bool
	RFlag      bool
	SFlag      bool
	DFlag      bool
	TLVs       []TLVInterface
}

func (o *LSPObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.PlspID = uint32(binary.BigEndian.Uint32(objectBody[0:4]) >> 12) // 20 bits from top
	o.OFlag = uint8(objectBody[3] & 0x0070 >> 4)
	o.AFlag = (objectBody[3] & 0x08) != 0
	o.RFlag = (objectBody[3] & 0x04) != 0
	o.SFlag = (objectBody[3] & 0x02) != 0
	o.DFlag = (objectBody[3] & 0x01) != 0
	if len(objectBody) > 4 {
		byteTLVs := objectBody[4:]

		var err error
		if o.TLVs, err = DecodeTLVs(byteTLVs); err != nil {
			return err
		}
		for _, tlv := range o.TLVs {

			if t, ok := tlv.(*SymbolicPathName); ok {
				o.Name = t.Name
			}
			if t, ok := tlv.(*IPv4LSPIdentifiers); ok {
				o.SrcAddr = t.IPv4TunnelSenderAddress
				o.DstAddr = t.IPv4TunnelEndpointAddress
				o.LSPID = t.LSPID
			}
			if t, ok := tlv.(*IPv6LSPIdentifiers); ok {
				o.SrcAddr = t.IPv6TunnelSenderAddress
				o.DstAddr = t.IPv6TunnelEndpointAddress
				o.LSPID = t.LSPID
			}
		}
	}
	return nil
}

func (o *LSPObject) Serialize() []uint8 {
	lspObjectHeader := NewCommonObjectHeader(ObjectClassLSP, o.ObjectType, o.Len())
	byteLSPObjectHeader := lspObjectHeader.Serialize()

	buf := make([]uint8, 4)
	binary.BigEndian.PutUint32(buf, uint32(o.PlspID<<12)+uint32(o.OFlag<<4))
	if o.CFlag {
		buf[3] = buf[3] | 0x80
	}
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
	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		byteTLVs = AppendByteSlices(byteTLVs, tlv.Serialize())
	}

	byteLSPObject := AppendByteSlices(byteLSPObjectHeader, buf, byteTLVs)
	return byteLSPObject
}

func (o *LSPObject) Len() uint16 {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	// Flags, SRP-ID (4byte)
	lspObjectBodyLength := uint16(4) + tlvsByteLength
	// CommonObjectHeader(4byte) + Flags, SRP-ID
	return uint16(commonObjectHeaderLength) + lspObjectBodyLength
}

func NewLSPObject(lspName string, color *uint32, plspID uint32) (*LSPObject, error) {
	o := &LSPObject{
		ObjectType: ObjectTypeLSPLSP,
		Name:       lspName,
		PlspID:     plspID,
		CFlag:      true,     // (RFC8281 5.3.1)
		OFlag:      uint8(1), // UP (RFC8231 7.3)
		AFlag:      true,     // desired operational state is active (RFC8231 7.3)
		RFlag:      false,    // TODO: Allow setting from function arguments
		SFlag:      false,
		DFlag:      true,
		TLVs:       []TLVInterface{},
	}
	symbolicPathNameTLV := &SymbolicPathName{
		Name: lspName,
	}

	o.TLVs = append(o.TLVs, TLVInterface(symbolicPathNameTLV))

	var colorTLV *Color
	if color != nil {
		colorTLV = &Color{
			Color: *color,
		}
	}
	if colorTLV != nil {
		o.TLVs = append(o.TLVs, TLVInterface(colorTLV))
	}
	return o, nil
}

// (I.D.draft-ietf-pce-pcep-color-12)
func (o *LSPObject) Color() uint32 {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*Color); ok {
			return t.Color
		}

	}
	return 0
}

// ERO Object (RFC5440 7.9)
const (
	ObjectTypeEROExplicitRoute ObjectType = 0x01
)

type EroObject struct {
	ObjectType    ObjectType
	EroSubobjects []EroSubobject
}

func (o *EroObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	if len(objectBody) == 0 {
		return nil
	}
	for {
		var eroSubobj EroSubobject
		switch SubObjectType(objectBody[0] & 0x7f) {
		case SubObjectTypeEROSR:
			eroSubobj = &SREroSubobject{}
		case SubObjectTypeEROSRv6:
			eroSubobj = &SRv6EroSubobject{}
		default:
			return errors.New("invalid Subobject type")
		}
		if err := eroSubobj.DecodeFromBytes(objectBody); err != nil {
			return err
		}
		o.EroSubobjects = append(o.EroSubobjects, eroSubobj)
		if objByteLength, err := eroSubobj.Len(); err != nil {
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
	eroObjectLength, err := o.Len()
	if err != nil {
		return nil, err
	}
	eroObjectHeader := NewCommonObjectHeader(ObjectClassERO, o.ObjectType, eroObjectLength)
	byteEroObjectHeader := eroObjectHeader.Serialize()

	byteEroObject := byteEroObjectHeader
	for _, eroSubobject := range o.EroSubobjects {
		buf := eroSubobject.Serialize()
		byteEroObject = append(byteEroObject, buf...)
	}
	return byteEroObject, nil
}

func (o EroObject) Len() (uint16, error) {
	eroSubobjByteLength := uint16(0)
	for _, eroSubObj := range o.EroSubobjects {
		objByteLength, err := eroSubObj.Len()
		if err != nil {
			return 0, err
		}
		eroSubobjByteLength += objByteLength
	}
	// CommonObjectHeader(4byte) + eroSubobjects(valiable)
	return uint16(commonObjectHeaderLength) + eroSubobjByteLength, nil
}

func NewEroObject(segmentList []table.Segment) (*EroObject, error) {
	o := &EroObject{
		ObjectType:    ObjectTypeEROExplicitRoute,
		EroSubobjects: []EroSubobject{},
	}
	err := o.AddEroSubobjects(segmentList)

	if err != nil {
		return o, err
	}
	return o, nil
}

func (o *EroObject) AddEroSubobjects(SegmentList []table.Segment) error {
	for _, segment := range SegmentList {
		eroSubobject, err := NewEroSubobject(segment)
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
	Len() (uint16, error)
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
	}
	return nil, errors.New("invalid Segment type")
}

// SR-ERO Subobject (RFC8664 4.3.1)
const (
	SubObjectTypeEROSR SubObjectType = 0x24
)

type NAITypeSR uint8

const (
	NAITypeSRAbsent                 NAITypeSR = 0x00
	NAITypeSRIPv4Node               NAITypeSR = 0x01
	NAITypeSRIPv6Node               NAITypeSR = 0x02
	NAITypeSRIPv4Adjacency          NAITypeSR = 0x03
	NAITypeSRIPv6AdjacencyGlobal    NAITypeSR = 0x04
	NAITypeSRUnnumberedAdjacency    NAITypeSR = 0x05
	NAITypeSRIPv6AdjacencyLinkLocal NAITypeSR = 0x06
)

var naiTypeSRDescriptions = map[NAITypeSR]struct {
	Description string
	Reference   string
}{
	NAITypeSRAbsent:                 {"NAI is absent", "RFC8664"},
	NAITypeSRIPv4Node:               {"NAI is an IPv4 node ID", "RFC8664"},
	NAITypeSRIPv6Node:               {"NAI is an IPv6 node ID", "RFC8664"},
	NAITypeSRIPv4Adjacency:          {"NAI is an IPv4 adjacency", "RFC8664"},
	NAITypeSRIPv6AdjacencyGlobal:    {"NAI is an IPv6 adjacency with global IPv6 addresses", "RFC8664"},
	NAITypeSRUnnumberedAdjacency:    {"NAI is an unnumbered adjacency with IPv4 node IDs", "RFC8664"},
	NAITypeSRIPv6AdjacencyLinkLocal: {"NAI is an IPv6 adjacency with link-local IPv6 addresses", "RFC8664"},
}

func (nt NAITypeSR) String() string {
	if desc, ok := naiTypeSRDescriptions[nt]; ok {
		return fmt.Sprintf("%s (0x%02x)", desc.Description, uint8(nt))
	}
	return fmt.Sprintf("Unknown NAI Type (0x%02x)", uint8(nt))
}

func (nt NAITypeSR) StringWithReference() string {
	if desc, ok := naiTypeSRDescriptions[nt]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, uint8(nt), desc.Reference)
	}
	return fmt.Sprintf("Unknown NAI Type (0x%02x)", uint8(nt))
}

type SREroSubobject struct {
	LFlag         bool
	SubobjectType SubObjectType
	Length        uint8
	NAIType       NAITypeSR
	FFlag         bool
	SFlag         bool
	CFlag         bool
	MFlag         bool
	Segment       table.SegmentSRMPLS
	NAI           netip.Addr
}

func (o *SREroSubobject) DecodeFromBytes(subObject []uint8) error {
	o.LFlag = (subObject[0] & 0x80) != 0
	o.SubobjectType = SubObjectType(subObject[0] & 0x7f)
	o.Length = subObject[1]
	o.NAIType = NAITypeSR(subObject[2] >> 4)
	o.FFlag = (subObject[3] & 0x08) != 0
	o.SFlag = (subObject[3] & 0x04) != 0
	o.CFlag = (subObject[3] & 0x02) != 0
	o.MFlag = (subObject[3] & 0x01) != 0

	sid := binary.BigEndian.Uint32(subObject[4:8]) >> 12
	o.Segment = table.NewSegmentSRMPLS(sid)
	if o.NAIType == NAITypeSRIPv4Node {
		o.NAI, _ = netip.AddrFromSlice(subObject[8:12])
	}
	return nil
}

func (o *SREroSubobject) Serialize() []uint8 {
	buf := make([]uint8, 4)
	buf[0] = uint8(o.SubobjectType)
	if o.LFlag {
		buf[0] = buf[0] | 0x80
	}
	buf[1] = o.Length
	buf[2] = uint8(o.NAIType) * 16
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

func (o *SREroSubobject) Len() (uint16, error) {
	switch o.NAIType {
	case NAITypeSRAbsent:
		// Type, Length, Flags (4byte) + SID (4byte)
		return uint16(8), nil
	case NAITypeSRIPv4Node:
		// Type, Length, Flags (4byte) + SID (4byte) + NAI (4byte)
		return uint16(12), nil
	case NAITypeSRIPv6Node:
		// Type, Length, Flags (4byte) + SID (4byte) + NAI (16byte)
		return uint16(24), nil
	default:
		return uint16(0), errors.New("unsupported naitype")
	}
}

func NewSREroSubObject(seg table.SegmentSRMPLS) (*SREroSubobject, error) {
	subo := &SREroSubobject{
		LFlag:         false,
		SubobjectType: SubObjectTypeEROSR,
		NAIType:       NAITypeSRAbsent,
		FFlag:         true, // NAI is absent
		SFlag:         false,
		CFlag:         false,
		MFlag:         true, // TODO: Determine either MPLS label or index
		Segment:       seg,
	}
	length, err := subo.Len()
	if err != nil {
		return subo, err
	}
	subo.Length = uint8(length)
	return subo, nil
}

func (o *SREroSubobject) ToSegment() table.Segment {
	return o.Segment
}

// SRv6-ERO Subobject (RFC9603 4.3.1)
const (
	SubObjectTypeEROSRv6 SubObjectType = 0x28
)

type NAITypeSRv6 uint8

const (
	NAITypeSRv6Absent                 NAITypeSRv6 = 0x00
	NAITypeSRv6IPv6Node               NAITypeSRv6 = 0x02
	NAITypeSRv6IPv6AdjacencyGlobal    NAITypeSRv6 = 0x04
	NAITypeSRv6IPv6AdjacencyLinkLocal NAITypeSRv6 = 0x06
)

var naiTypeSRv6Descriptions = map[NAITypeSRv6]struct {
	Description string
	Reference   string
}{
	NAITypeSRv6Absent:                 {"NAI is absent", "RFC9603"},
	NAITypeSRv6IPv6Node:               {"NAI is an IPv6 node ID", "RFC9603"},
	NAITypeSRv6IPv6AdjacencyGlobal:    {"NAI is an IPv6 adjacency with global IPv6 addresses", "RFC9603"},
	NAITypeSRv6IPv6AdjacencyLinkLocal: {"NAI is an IPv6 adjacency with link-local IPv6 addresses", "RFC9603"},
}

func (nt NAITypeSRv6) String() string {
	if desc, ok := naiTypeSRv6Descriptions[nt]; ok {
		return fmt.Sprintf("%s (0x%02x)", desc.Description, uint8(nt))
	}
	return fmt.Sprintf("Unknown NAI Type (0x%02x)", uint8(nt))
}

func (nt NAITypeSRv6) StringWithReference() string {
	if desc, ok := naiTypeSRv6Descriptions[nt]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, uint8(nt), desc.Reference)
	}
	return fmt.Sprintf("Unknown NAI Type (0x%02x)", uint8(nt))
}

type SRv6EroSubobject struct {
	LFlag         bool
	SubobjectType SubObjectType
	Length        uint8
	NAIType       NAITypeSRv6
	VFlag         bool
	TFlag         bool
	FFlag         bool
	SFlag         bool
	Segment       table.SegmentSRv6
}

func (o *SRv6EroSubobject) DecodeFromBytes(subObject []uint8) error {
	o.LFlag = (subObject[0] & 0x80) != 0
	o.SubobjectType = SubObjectType(subObject[0] & 0x7f)
	o.Length = subObject[1]
	o.NAIType = NAITypeSRv6(subObject[2] >> 4)
	o.VFlag = (subObject[3] & 0x08) != 0
	o.TFlag = (subObject[3] & 0x04) != 0
	o.FFlag = (subObject[3] & 0x02) != 0
	o.SFlag = (subObject[3] & 0x01) != 0

	sid, _ := netip.AddrFromSlice(subObject[8:24])
	o.Segment = table.NewSegmentSRv6(sid)
	if o.NAIType == NAITypeSRv6IPv6Node {
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subObject[24:40])
	}
	if o.NAIType == NAITypeSRv6IPv6AdjacencyGlobal {
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subObject[24:40])
		o.Segment.RemoteAddr, _ = netip.AddrFromSlice(subObject[40:56])
	}
	return nil
}

func (o *SRv6EroSubobject) Serialize() []uint8 {
	buf := make([]uint8, 4)
	buf[0] = uint8(o.SubobjectType)
	if o.LFlag {
		buf[0] = buf[0] | 0x80
	}
	buf[1] = o.Length
	buf[2] = uint8(o.NAIType) * 16
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
	behavior := Uint16ToByteSlice(o.Segment.Behavior())
	byteSid := o.Segment.Sid.AsSlice()

	byteNAI := []uint8{}
	if o.Segment.LocalAddr.IsValid() {
		byteNAI = append(byteNAI, o.Segment.LocalAddr.AsSlice()...)
		if o.Segment.RemoteAddr.IsValid() {
			byteNAI = append(byteNAI, o.Segment.RemoteAddr.AsSlice()...)
		}
	}

	byteSidStructure := []uint8{}
	if o.Segment.Structure != nil {
		byteSidStructure = append(byteSidStructure, o.Segment.Structure...)
		byteSidStructure = append(byteSidStructure, make([]uint8, 4)...)
	}

	byteSRv6EroSubobject := AppendByteSlices(buf, reserved, behavior, byteSid, byteNAI, byteSidStructure)
	return byteSRv6EroSubobject
}

func (o *SRv6EroSubobject) Len() (uint16, error) {
	// The Length MUST be at least 24, and MUST be a multiple of 4.
	// An SRv6-ERO subobject MUST contain at least one of a SRv6-SID or an NAI.

	// Type, Length, Flags (4byte) + Reserved(2byte) + Behavior(2byte)
	length := uint16(8)
	// SRv6-SID value in the subobject body is NOT absent
	if !o.SFlag {
		length += 16
	}
	// NAI value in the subobject body is NOT absent
	if !o.FFlag {
		switch o.NAIType {
		case NAITypeSRv6IPv6Node:
			length += 16
		case NAITypeSRv6IPv6AdjacencyGlobal:
			length += 32
		case NAITypeSRv6IPv6AdjacencyLinkLocal:
			length += 40
		case NAITypeSRv6Absent:
			return uint16(0), errors.New("when naitype is 0 then FFlag must be 1")
		default:
			return uint16(0), errors.New("unsupported naitype")
		}
	}
	if o.TFlag {
		length += 8
	}
	return length, nil
}

func NewSRv6EroSubObject(seg table.SegmentSRv6) (*SRv6EroSubobject, error) {
	subo := &SRv6EroSubobject{
		LFlag:         false,
		SubobjectType: SubObjectTypeEROSRv6,
		VFlag:         false,
		SFlag:         false, // SID is absent
		Segment:       seg,
	}

	if seg.Structure != nil {
		subo.TFlag = true // the SID Structure value in the subobject body is present
	} else {
		subo.TFlag = false
	}
	if seg.LocalAddr.IsValid() {
		subo.FFlag = false // NAI is present

		if seg.RemoteAddr.IsValid() {
			// End.X or uA
			subo.NAIType = NAITypeSRv6IPv6AdjacencyGlobal
		} else {
			// End or uN
			subo.NAIType = NAITypeSRv6IPv6Node
		}
	} else {
		subo.FFlag = true // SID is absent
		subo.NAIType = NAITypeSRv6Absent
	}

	length, err := subo.Len()
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
	ObjectTypeEndpointIPv4 ObjectType = 0x01
	ObjectTypeEndpointIPv6 ObjectType = 0x02
)

type EndpointsObject struct {
	ObjectType ObjectType
	SrcAddr    netip.Addr
	DstAddr    netip.Addr
}

func (o *EndpointsObject) Serialize() ([]uint8, error) {
	endpointsObjectLength, err := o.Len()
	if err != nil {
		return nil, err
	}
	endpointsObjectHeader := NewCommonObjectHeader(ObjectClassEndpoints, o.ObjectType, endpointsObjectLength)

	byteEroObjectHeader := endpointsObjectHeader.Serialize()
	byteEndpointsObject := AppendByteSlices(byteEroObjectHeader, o.SrcAddr.AsSlice(), o.DstAddr.AsSlice())
	return byteEndpointsObject, nil
}

func (o *EndpointsObject) Len() (uint16, error) {
	var length uint16
	if o.SrcAddr.Is4() && o.DstAddr.Is4() {
		// CommonObjectHeader(4byte) + srcIPv4 (4byte) + dstIPv4 (4byte)
		length = commonObjectHeaderLength + 4 + 4
	} else if o.SrcAddr.Is6() && o.DstAddr.Is6() {
		// CommonObjectHeader(4byte) + srcIPv4 (16byte) + dstIPv4 (16byte)
		length = commonObjectHeaderLength + 16 + 16
	} else {
		return uint16(0), fmt.Errorf("invalid endpoints address (Len()): src=%v dst=%v", o.SrcAddr, o.DstAddr)
	}
	return length, nil
}

func NewEndpointsObject(dstAddr netip.Addr, srcAddr netip.Addr) (*EndpointsObject, error) {
	var objectType ObjectType
	if dstAddr.Is4() && srcAddr.Is4() {
		objectType = ObjectTypeEndpointIPv4
	} else if dstAddr.Is6() && srcAddr.Is6() {
		objectType = ObjectTypeEndpointIPv6
	} else {
		return nil, fmt.Errorf("invalid endpoints address (NewEndpointsObject): dst=%v src=%v", dstAddr, srcAddr)
	}

	o := &EndpointsObject{
		ObjectType: objectType,
		DstAddr:    dstAddr,
		SrcAddr:    srcAddr,
	}
	return o, nil
}

// ASSOCIATION Object (RFC8697 6.)
const (
	ObjectTypeAssociationIPv4 ObjectType = 0x01
	ObjectTypeAssociationIPv6 ObjectType = 0x02
)

const (
	AssociationTypeSRPolicyAssociation        AssocType = 0x06
	AssociationTypeSRPolicyAssociationCisco   AssocType = 0x14
	AssociationTypeSRPolicyAssociationJuniper AssocType = 0xffe1 // Juniper specific TLV (deprecated)
)

const (
	CiscoLegacy PccType = iota
	JuniperLegacy
	RFCCompliant
)

// Determine PCC type from capability
func DeterminePccType(caps []CapabilityInterface) (pccType PccType) {
	pccType = RFCCompliant
	for _, cap := range caps {
		if t, ok := cap.(*AssocTypeList); ok {
			for _, v := range t.AssocTypes {
				if v == AssociationTypeSRPolicyAssociationCisco {
					pccType = CiscoLegacy
				} else if v == AssociationTypeSRPolicyAssociationJuniper {
					pccType = JuniperLegacy
					break
				}
			}
		}
	}
	return
}

type AssociationObject struct {
	ObjectType ObjectType
	RFlag      bool
	AssocType  AssocType
	AssocID    uint16
	AssocSrc   netip.Addr
	TLVs       []TLVInterface
}

func (o *AssociationObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.RFlag = (objectBody[3] & 0x01) != 0
	o.AssocType = AssocType(binary.BigEndian.Uint16(objectBody[4:6]))
	o.AssocID = uint16(binary.BigEndian.Uint16(objectBody[6:8]))

	switch o.ObjectType {
	case ObjectTypeAssociationIPv4:
		assocSrcBytes, _ := netip.AddrFromSlice(objectBody[8:12])
		o.AssocSrc = assocSrcBytes
		if len(objectBody) > 12 {
			byteTLVs := objectBody[12:]
			var err error
			if o.TLVs, err = DecodeTLVs(byteTLVs); err != nil {
				return err
			}
		}
	case ObjectTypeAssociationIPv6:
		o.AssocSrc, _ = netip.AddrFromSlice(objectBody[8:24])
		if len(objectBody) > 24 {
			byteTLVs := objectBody[24:]
			var err error
			if o.TLVs, err = DecodeTLVs(byteTLVs); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid association source address (DecodeFromBytes)")
	}

	return nil
}

func (o *AssociationObject) Serialize() ([]uint8, error) {
	associationObjectLength, err := o.Len()
	if err != nil {
		return nil, err
	}
	associationObjectHeader := NewCommonObjectHeader(ObjectClassAssociation, o.ObjectType, associationObjectLength)

	byteAssociationObjectHeader := associationObjectHeader.Serialize()

	buf := make([]uint8, 4)

	if o.RFlag {
		buf[4] = buf[4] | 0x01
	}

	assocType := Uint16ToByteSlice(o.AssocType)
	assocID := Uint16ToByteSlice(o.AssocID)

	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		byteTLVs = append(byteTLVs, tlv.Serialize()...)
	}

	byteAssociationObject := AppendByteSlices(
		byteAssociationObjectHeader, buf, assocType, assocID, o.AssocSrc.AsSlice(), byteTLVs,
	)
	return byteAssociationObject, nil
}

func (o AssociationObject) Len() (uint16, error) {
	tlvsByteLength := uint16(0)
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	var associationObjectBodyLength uint16
	if o.AssocSrc.Is4() {
		// Reserved(2byte) + Flags(2byte) + Assoc Type(2byte) + Assoc ID(2byte) + IPv4 Assoc Src(4byte)
		associationObjectBodyLength = uint16(12) + tlvsByteLength
	} else if o.AssocSrc.Is6() {
		// Reserved(2byte) + Flags(2byte) + Assoc Type(2byte) + Assoc ID(2byte) + IPv6 Assoc Src(16byte)
		associationObjectBodyLength = uint16(24) + tlvsByteLength
	} else {
		return uint16(0), errors.New("invalid association source address (Len())")
	}
	return (commonObjectHeaderLength + associationObjectBodyLength), nil
}

func NewAssociationObject(srcAddr netip.Addr, dstAddr netip.Addr, color uint32, preference uint32, opt ...Opt) (*AssociationObject, error) {
	opts := optParams{
		pccType: RFCCompliant,
	}

	for _, o := range opt {
		o(&opts)
	}
	var objectType ObjectType
	if dstAddr.Is4() && srcAddr.Is4() {
		objectType = ObjectTypeEndpointIPv4
	} else if dstAddr.Is6() && srcAddr.Is6() {
		objectType = ObjectTypeEndpointIPv6
	} else {
		return nil, fmt.Errorf("invalid endpoints address (NewAssociationObject): src=%v dst=%v", srcAddr, dstAddr)
	}
	o := &AssociationObject{
		ObjectType: objectType,
		RFlag:      false,
		TLVs:       []TLVInterface{},
		AssocSrc:   srcAddr,
	}
	if opts.pccType == JuniperLegacy {
		o.AssocID = 0
		o.AssocType = AssociationTypeSRPolicyAssociationJuniper
		associationObjectTLVs := []TLVInterface{
			&UndefinedTLV{
				Typ:    TLVExtendedAssociationIDIPv4Juniper,
				Length: TLVExtendedAssociationIDIPv4ValueLength, // JuniperLegacy has only IPv4 implementation
				Value: AppendByteSlices(
					Uint32ToByteSlice(color), dstAddr.AsSlice(),
				),
			},
			&UndefinedTLV{
				Typ:    TLVSRPolicyCPathIDJuniper,
				Length: TLVSRPolicyCPathIDValueLength,
				Value: []uint8{
					0x00,             // protocol origin
					0x00, 0x00, 0x00, // mbz
					0x00, 0x00, 0x00, 0x00, // Originator ASN
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Originator Address
					0x00, 0x00, 0x00, 0x00, //discriminator
				},
			},
			&UndefinedTLV{
				Typ:    TLVSRPolicyCPathPreferenceJuniper,
				Length: TLVSRPolicyCPathPreferenceValueLength,
				Value:  Uint32ToByteSlice(preference),
			},
		}
		o.TLVs = append(o.TLVs, associationObjectTLVs...)
	} else {
		o.AssocID = 1                                    // (I.D. pce-segment-routing-policy-cp-07 5.1)
		o.AssocType = AssociationTypeSRPolicyAssociation // (I.D. pce-segment-routing-policy-cp-07 5.1)
		associationObjectTLVs := []TLVInterface{
			&ExtendedAssociationID{
				Color:    color,
				Endpoint: dstAddr,
			},
			&SRPolicyCandidatePathIdentifier{
				OriginatorAddr: dstAddr,
			},
			&SRPolicyCandidatePathPreference{
				Preference: preference,
			},
		}
		o.TLVs = append(o.TLVs, associationObjectTLVs...)
	}

	return o, nil
}

// (I.D. pce-segment-routing-policy-cp-08 5.1)
func (o *AssociationObject) Color() uint32 {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*UndefinedTLV); ok {
			if t.Type() == TLVExtendedAssociationIDIPv4Juniper {
				return uint32(binary.BigEndian.Uint32(t.Value[:4]))
			}
		} else if t, ok := tlv.(*ExtendedAssociationID); ok {
			return t.Color
		}

	}
	return 0
}

// (I.D. pce-segment-routing-policy-cp-08 5.1)
func (o *AssociationObject) Preference() uint32 {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*UndefinedTLV); ok {
			if t.Type() == TLVSRPolicyCPathPreferenceJuniper {
				return uint32(binary.BigEndian.Uint32(t.Value))
			}
		} else if t, ok := tlv.(*SRPolicyCandidatePathPreference); ok {
			return t.Preference
		}
	}
	return 0
}

func (o *AssociationObject) Endpoint() netip.Addr {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*ExtendedAssociationID); ok {
			return t.Endpoint
		}
	}
	return netip.Addr{}
}

// VENDOR-INFORMATION Object (RFC7470 4)
const (
	ObjectTypeVendorSpecificConstraints ObjectType = 0x01
)

const (
	EnterpriseNumberCisco uint32 = 9
)

type VendorInformationObject struct {
	ObjectType       ObjectType // vendor specific constraints: 1
	EnterpriseNumber uint32
	TLVs             []TLVInterface
}

func (o *VendorInformationObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	o.EnterpriseNumber = binary.BigEndian.Uint32(objectBody[0:4])
	if len(objectBody) > 4 {
		byteTLVs := objectBody[4:]
		var err error
		if o.TLVs, err = DecodeTLVs(byteTLVs); err != nil {
			return err
		}

	}
	return nil
}

func (o *VendorInformationObject) Serialize() []uint8 {
	vendorInformationObjectHeader := NewCommonObjectHeader(ObjectClassVendorInformation, o.ObjectType, o.Len())
	byteVendorInformationObjectHeader := vendorInformationObjectHeader.Serialize()

	enterpriseNumber := Uint32ToByteSlice(o.EnterpriseNumber)

	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		byteTLVs = append(byteTLVs, tlv.Serialize()...)
	}

	byteVendorInformationObject := AppendByteSlices(
		byteVendorInformationObjectHeader, enterpriseNumber, byteTLVs,
	)
	return byteVendorInformationObject
}

func (o VendorInformationObject) Len() uint16 {
	// TODO: Expantion for IPv6 Endpoint
	// CommonObjectHeader(4byte) + Enterprise Number (4byte) + colorTLV (8byte) + preferenceTLV (8byte)
	return uint16(commonObjectHeaderLength + 4 + 8 + 8)
}

func NewVendorInformationObject(vendor PccType, color uint32, preference uint32) (*VendorInformationObject, error) {
	o := &VendorInformationObject{ // for Cisco PCC
		ObjectType: ObjectTypeVendorSpecificConstraints, // (RFC7470 4)
		TLVs:       []TLVInterface{},
	}
	if vendor == CiscoLegacy {
		o.EnterpriseNumber = EnterpriseNumberCisco
		vendorInformationObjectTLVs := []TLVInterface{
			&UndefinedTLV{
				Typ:    SubTLVColorCisco,
				Length: SubTLVColorCiscoValueLength, // TODO: 20 if ipv6 endpoint
				Value: AppendByteSlices(
					Uint32ToByteSlice(color),
				),
			},
			&UndefinedTLV{
				Typ:    SubTLVPreferenceCisco,
				Length: SubTLVPreferenceCiscoValueLength,
				Value:  Uint32ToByteSlice(preference),
			},
		}
		o.TLVs = append(o.TLVs, vendorInformationObjectTLVs...)
	} else {
		return nil, errors.New("unknown vender information object type")
	}
	return o, nil
}

func (o *VendorInformationObject) Color() uint32 {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*UndefinedTLV); ok {
			if t.Type() == SubTLVColorCisco {
				return uint32(binary.BigEndian.Uint32(t.Value))
			}
		}
	}
	return 0
}

func (o *VendorInformationObject) Preference() uint32 {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*UndefinedTLV); ok {
			if t.Type() == SubTLVPreferenceCisco {
				return uint32(binary.BigEndian.Uint32(t.Value))
			}
		}
	}
	return 0
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
