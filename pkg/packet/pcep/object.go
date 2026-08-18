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

	"github.com/nttcom/pola/pkg/table"
)

// PccType represents the type of PCC (Path Computation Client).
type PccType int

const commonObjectHeaderLength uint16 = 4

// ObjectClass is a PCEP object class code (1 byte). Ref: https://www.iana.org/assignments/pcep/pcep.xhtml#pcep-objects
type ObjectClass uint8

// ObjectType is a PCEP object type code.
type ObjectType uint8

// SubobjectType is a PCEP subobject type code.
type SubobjectType uint8

// PCEP object classes.
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

// StringWithReference returns a human-readable representation of the object class with reference.
func (c ObjectClass) StringWithReference() string {
	if desc, ok := objectClassDescriptions[c]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, c, desc.Reference)
	}
	return fmt.Sprintf("Unknown Object Class (0x%02x)", uint8(c))
}

// CommonObjectHeader is the common header of a PCEP object (RFC 5440 §7.2).
type CommonObjectHeader struct { // RFC 5440 §7.2
	ObjectClass  ObjectClass
	ObjectType   ObjectType
	ResFlags     uint8 // MUST be set to zero
	PFlag        bool  // 0: optional, 1: MUST
	IFlag        bool  // 0: processed, 1: ignored
	ObjectLength uint16
}

// Object header flag masks (RFC 5440 §7.2).
const (
	// IFlagMask is the mask for the I-flag in the object flags.
	IFlagMask uint8 = 0x01
	// PFlagMask is the mask for the P-flag in the object flags.
	PFlagMask uint8 = 0x02
)

// DecodeFromBytes decodes the given bytes into the CommonObjectHeader.
func (h *CommonObjectHeader) DecodeFromBytes(objectHeader []uint8) error {
	if len(objectHeader) < int(commonObjectHeaderLength) {
		return fmt.Errorf("object header too short: got %d bytes, need at least %d", len(objectHeader), commonObjectHeaderLength)

	}

	h.ObjectClass = ObjectClass(objectHeader[0])
	h.ObjectType = ObjectType((objectHeader[1] & 0xf0) >> 4)
	h.ResFlags = (objectHeader[1] & 0x0c) >> 2
	h.PFlag = (objectHeader[1] & PFlagMask) != 0
	h.IFlag = (objectHeader[1] & IFlagMask) != 0
	h.ObjectLength = binary.BigEndian.Uint16(objectHeader[2:4])
	return nil
}

// Serialize encodes the CommonObjectHeader into bytes.
func (h *CommonObjectHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	buf = append(buf, uint8(h.ObjectClass))
	Flagbyte := uint8(h.ObjectType)<<4 | h.ResFlags<<2
	if h.PFlag {
		Flagbyte |= PFlagMask
	}
	if h.IFlag {
		Flagbyte |= IFlagMask
	}
	buf = append(buf, Flagbyte)
	buf = append(buf, Uint16ToByteSlice(h.ObjectLength)...)
	return buf
}

// NewCommonObjectHeader creates a new CommonObjectHeader.
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

func objectLength(body ...[]uint8) (uint16, error) {
	total := int(commonObjectHeaderLength)
	for _, b := range body {
		total += len(b)
	}
	if total > math.MaxUint16 {
		return 0, fmt.Errorf("PCEP object length %d exceeds %d", total, math.MaxUint16)
	}
	return uint16(total), nil
}

// OPEN Object (RFC 5440 §7.3)
const (
	// ObjectTypeOpenOpen is the object type for OPEN.
	ObjectTypeOpenOpen ObjectType = 0x01
)

// OpenObject is a PCEP Open object.
type OpenObject struct {
	ObjectType ObjectType
	Version    uint8
	Flag       uint8
	Keepalive  uint8
	Deadtime   uint8
	Sid        uint8
	Caps       []CapabilityInterface
}

// DecodeFromBytes decodes the given bytes into the OpenObject.
func (o *OpenObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 4 {
		return fmt.Errorf("OPEN object body too short: got %d bytes, need at least 4", len(objectBody))
	}

	o.ObjectType = typ
	o.Version = objectBody[0] >> 5
	if o.Version != PCEPVersion {
		return fmt.Errorf("unsupported PCEP version %d in OPEN object", o.Version)
	}
	o.Flag = objectBody[0] & 0x1f
	o.Keepalive = objectBody[1]
	o.Deadtime = objectBody[2]
	o.Sid = objectBody[3]

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

// Serialize encodes the OpenObject into bytes.
func (o *OpenObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 4)
	buf[0] = (o.Version << 5) | (o.Flag & 0x1f)
	buf[1] = o.Keepalive
	buf[2] = o.Deadtime
	buf[3] = o.Sid

	byteTLVs := []uint8{}
	for _, cap := range o.Caps {
		b, err := cap.Serialize()
		if err != nil {
			return nil, err
		}
		byteTLVs = append(byteTLVs, b...)
	}

	length, err := objectLength(buf, byteTLVs)
	if err != nil {
		return nil, err
	}
	openObjectHeader := NewCommonObjectHeader(ObjectClassOpen, o.ObjectType, length)

	return AppendByteSlices(openObjectHeader.Serialize(), buf, byteTLVs), nil
}

// Len returns the wire length of the OpenObject.
func (o *OpenObject) Len() int {
	tlvsByteLength := 0
	for _, cap := range o.Caps {
		tlvsByteLength += cap.Len()
	}
	// CommonObjectHeader(4byte) + openObject(4byte) + tlvslength(variable)
	return int(commonObjectHeaderLength) + 4 + tlvsByteLength
}

// NewOpenObject creates a new OpenObject.
func NewOpenObject(sessionID uint8, keepalive uint8, capabilities []CapabilityInterface) *OpenObject {
	return &OpenObject{
		ObjectType: ObjectTypeOpenOpen,
		Version:    uint8(1), // PCEP version. Current version is 1
		Flag:       uint8(0),
		Keepalive:  keepalive,
		Deadtime:   DeadTimerFor(keepalive),
		Sid:        sessionID,
		Caps:       capabilities,
	}
}

const deadTimerMultiplier = 4

// DeadTimerFor returns the DeadTimer value for the given Keepalive interval, clamped to 8-bit.
func DeadTimerFor(keepalive uint8) uint8 {
	d := int(keepalive) * deadTimerMultiplier
	if d > math.MaxUint8 {
		return math.MaxUint8
	}
	return uint8(d)
}

// BandwidthObject is a PCEP Bandwidth object (RFC 5440 §7.7).
type BandwidthObject struct {
	ObjectType ObjectType
	Bandwidth  uint32
}

// DecodeFromBytes decodes the given bytes into the BandwidthObject.
func (o *BandwidthObject) DecodeFromBytes(objectType ObjectType, objectBody []uint8) error {
	if len(objectBody) < 4 {
		return fmt.Errorf("BANDWIDTH object body too short: got %d bytes, need at least 4", len(objectBody))
	}

	o.ObjectType = objectType
	o.Bandwidth = binary.BigEndian.Uint32(objectBody)
	return nil
}

// MetricObject is a PCEP Metric object (RFC 5440 §7.8).
type MetricObject struct {
	ObjectType  ObjectType
	CFlag       bool
	BFlag       bool
	MetricType  uint8
	MetricValue float32
}

// DecodeFromBytes decodes the given bytes into the MetricObject.
func (o *MetricObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 8 {
		return fmt.Errorf("METRIC object body too short: got %d bytes, need at least 8", len(objectBody))
	}

	o.ObjectType = typ
	o.CFlag = (objectBody[2] & 0x02) != 0
	o.BFlag = (objectBody[2] & 0x01) != 0
	o.MetricType = objectBody[3]
	// RFC 5440 §7.8 specifies metric-value as a 32-bit IEEE floating-point value.
	o.MetricValue = math.Float32frombits(binary.BigEndian.Uint32(objectBody[4:8]))
	return nil
}

// Serialize encodes the MetricObject into bytes.
func (o *MetricObject) Serialize() []uint8 {
	metricObjectHeader := NewCommonObjectHeader(ObjectClassMetric, o.ObjectType, o.Len())
	byteMetricObjectHeader := metricObjectHeader.Serialize()

	buf := make([]uint8, 8)
	if o.CFlag {
		buf[2] |= 0x02
	}
	if o.BFlag {
		buf[2] |= 0x01
	}
	buf[3] = o.MetricType
	binary.BigEndian.PutUint32(buf[4:8], math.Float32bits(o.MetricValue))
	byteMetricObject := AppendByteSlices(byteMetricObjectHeader, buf)
	return byteMetricObject
}

// Len returns the wire length of the MetricObject.
func (o *MetricObject) Len() uint16 {
	// CommonObjectHeader(4byte) + Reserved, Flags, Metric-Type, Metric-Value(8byte)
	return commonObjectHeaderLength + 8
}

// NewMetricObject creates a new MetricObject.
func NewMetricObject() *MetricObject {
	return &MetricObject{
		ObjectType:  ObjectType(1),
		MetricType:  uint8(2),
		MetricValue: float32(30),
	}
}

// LSPAObject is a PCEP LSPA (Link, Shared Risk Link Groups, Attribute) object (RFC 5440 §7.11).
type LSPAObject struct {
	ObjectType      ObjectType
	ExcludeAny      uint32
	IncludeAny      uint32
	IncludeAll      uint32
	SetupPriority   uint8
	HoldingPriority uint8
	LFlag           bool
}

// DecodeFromBytes decodes the given bytes into the LSPAObject.
func (o *LSPAObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 15 {
		return fmt.Errorf("LSPA object body too short: got %d bytes, need at least 15", len(objectBody))
	}

	o.ObjectType = typ
	o.ExcludeAny = binary.BigEndian.Uint32(objectBody[0:4])
	o.IncludeAny = binary.BigEndian.Uint32(objectBody[4:8])
	o.IncludeAll = binary.BigEndian.Uint32(objectBody[8:12])
	o.SetupPriority = objectBody[12]
	o.HoldingPriority = objectBody[13]
	o.LFlag = (objectBody[14] & 0x01) != 0
	return nil
}

// Serialize encodes the LSPAObject into bytes.
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
		buf[14] |= 0x01
	}

	byteLSPAObject := AppendByteSlices(byteLSPAObjectHeader, buf)
	return byteLSPAObject
}

// Len returns the wire length of the LSPAObject.
func (o *LSPAObject) Len() uint16 {
	// CommonObjectHeader(4byte) + Exclude/Include-any/Include-all, Setup and Holding Priority, Flags(16byte)
	return commonObjectHeaderLength + 16
}

// NewLSPAObject creates a new LSPAObject.
func NewLSPAObject() *LSPAObject {
	return &LSPAObject{
		ObjectType:      ObjectType(1),
		SetupPriority:   uint8(7),
		HoldingPriority: uint8(7),
		LFlag:           true,
	}
}

// PCEP Error Object (RFC 5440 §7.15)
const (
	ObjectTypeErrorError ObjectType = 0x01
)

// ErrorObject represents a PCEP Error object containing error type, value, and optional TLVs.
type ErrorObject struct {
	ObjectType ObjectType
	ErrorType  uint8
	ErrorValue uint8
	Tlvs       []TLVInterface
}

// DecodeFromBytes decodes the given bytes into the ErrorObject.
func (o *ErrorObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 4 {
		return fmt.Errorf("PCEP-ERROR object body too short: got %d bytes, need at least 4", len(objectBody))
	}
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

// Serialize encodes the ErrorObject into bytes.
func (o *ErrorObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 4)

	buf[2] = o.ErrorType
	buf[3] = o.ErrorValue

	byteTlvs := []uint8{}
	for _, tlv := range o.Tlvs {
		b, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		byteTlvs = append(byteTlvs, b...)
	}

	length, err := objectLength(buf, byteTlvs)
	if err != nil {
		return nil, err
	}
	pcepErrorObjectHeader := NewCommonObjectHeader(ObjectClassPCEPError, o.ObjectType, length)

	return AppendByteSlices(pcepErrorObjectHeader.Serialize(), buf, byteTlvs), nil
}

// Len returns the wire length of the ErrorObject.
func (o *ErrorObject) Len() int {
	tlvsByteLength := 0
	for _, tlv := range o.Tlvs {
		tlvsByteLength += tlv.Len()
	}
	// CommonObjectHeader(4byte) + Flags,Error-Type,Error-value(4byte) + tlvslength(variable)
	return int(commonObjectHeaderLength) + 4 + tlvsByteLength
}

// NewErrorObject creates a new ErrorObject.
func NewErrorObject(errorType uint8, errorValue uint8, tlvs []TLVInterface) *ErrorObject {
	return &ErrorObject{
		ObjectType: ObjectTypeErrorError,
		ErrorType:  errorType,
		ErrorValue: errorValue,
		Tlvs:       tlvs,
	}
}

// Close Object (RFC 5440 §7.17)
const (
	// ObjectTypeCloseClose is the object type for CLOSE.
	ObjectTypeCloseClose ObjectType = 0x01
)

// CloseReason is a PCEP close reason code.
type CloseReason uint8

// PCEP close reason codes.
const (
	// CloseReasonNoExplanationProvided is close reason for no explanation.
	CloseReasonNoExplanationProvided CloseReason = 0x01
	// CloseReasonDeadTimerExpired is close reason for dead timer expired.
	CloseReasonDeadTimerExpired CloseReason = 0x02
	// CloseReasonMalformedPCEPMessage is close reason for malformed message.
	CloseReasonMalformedPCEPMessage CloseReason = 0x03
	// CloseReasonTooManyUnknownRequestsReplies is close reason for too many unknown requests/replies.
	CloseReasonTooManyUnknownRequestsReplies CloseReason = 0x04
	// CloseReasonTooManyUnrecognizedPCEPMessages is close reason for too many unrecognized messages.
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

// StringWithReference returns a human-readable representation of the close reason with reference.
func (r CloseReason) StringWithReference() string {
	if desc, ok := closeReasonDescriptions[r]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, r, desc.Reference)
	}
	return fmt.Sprintf("Unknown Close Reason (0x%02x)", uint8(r))
}

// CloseObject is a PCEP Close object (RFC 5440 §7.17).
type CloseObject struct {
	ObjectType ObjectType
	Reason     CloseReason
}

// DecodeFromBytes decodes the given bytes into the CloseObject.
func (o *CloseObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 4 {
		return fmt.Errorf("CLOSE object body too short: got %d bytes, need at least 4", len(objectBody))
	}

	o.ObjectType = typ
	o.Reason = CloseReason(objectBody[3])
	return nil
}

// Serialize encodes the CloseObject into bytes.
func (o *CloseObject) Serialize() []uint8 {
	closeObjectHeader := NewCommonObjectHeader(ObjectClassClose, o.ObjectType, o.Len())
	byteCloseObjectHeader := closeObjectHeader.Serialize()

	buf := make([]uint8, 4)

	buf[3] = uint8(o.Reason)
	byteCloseObject := AppendByteSlices(byteCloseObjectHeader, buf)
	return byteCloseObject
}

// Len returns the wire length of the CloseObject.
func (o *CloseObject) Len() uint16 {
	// CommonObjectHeader(4byte) + CloseObjectBody(4byte)
	return commonObjectHeaderLength + 4
}

// NewCloseObject creates a new CloseObject.
func NewCloseObject(reason CloseReason) *CloseObject {
	return &CloseObject{
		ObjectType: ObjectTypeCloseClose,
		Reason:     reason,
	}
}

// SRP Object (RFC 8231 §7.2)
const (
	// ObjectTypeSRPSRP is the object type for SRP.
	ObjectTypeSRPSRP ObjectType = 0x01
)

// SrpObject is a PCEP SRP (Stateful PCE Request Parameters) object (RFC 8231 §7.2).
type SrpObject struct {
	ObjectType ObjectType
	RFlag      bool
	SrpID      uint32 // 0x00000000 and 0xFFFFFFFF are reserved.
	TLVs       []TLVInterface
}

// DecodeFromBytes decodes the given bytes into the SrpObject.
func (o *SrpObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 8 {
		return fmt.Errorf("SRP object body too short: got %d bytes, need at least 8", len(objectBody))
	}

	o.ObjectType = typ
	o.RFlag = (objectBody[3] & 0x01) != 0
	o.SrpID = binary.BigEndian.Uint32(objectBody[4:8])

	if len(objectBody) > 8 {
		byteTLVs := objectBody[8:]

		tlvs, err := DecodeTLVs(byteTLVs)
		if err != nil {
			return err
		}

		o.TLVs = tlvs
	}

	return nil
}

// Serialize encodes the SrpObject into bytes.
func (o *SrpObject) Serialize() ([]uint8, error) {
	byteFlags := make([]uint8, 4)
	if o.RFlag {
		byteFlags[3] |= 0x01
	}
	byteSrpID := make([]uint8, 4)
	binary.BigEndian.PutUint32(byteSrpID, o.SrpID)

	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		b, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		byteTLVs = append(byteTLVs, b...)
	}

	length, err := objectLength(byteFlags, byteSrpID, byteTLVs)
	if err != nil {
		return nil, err
	}
	srpObjectHeader := NewCommonObjectHeader(ObjectClassSRP, o.ObjectType, length)

	return AppendByteSlices(srpObjectHeader.Serialize(), byteFlags, byteSrpID, byteTLVs), nil
}

// Len returns the wire length of the SrpObject.
func (o *SrpObject) Len() int {
	tlvsByteLength := 0
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	// CommonObjectHeader(4byte) + Flags, SRP-ID(8byte)
	return int(commonObjectHeaderLength) + 8 + tlvsByteLength
}

// NewSrpObject creates a new SrpObject.
func NewSrpObject(segs []table.Segment, srpID uint32, isRemove bool) (*SrpObject, error) {
	o := &SrpObject{
		ObjectType: ObjectTypeSRPSRP,
		RFlag:      isRemove, // RFC 8281 §5.2
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

// LSP Object (RFC 8281 §5.3.1)
const (
	// ObjectTypeLSPLSP is the object type for LSP.
	ObjectTypeLSPLSP ObjectType = 0x01
)

// LSPObject is a PCEP LSP (Label Switched Path) object (RFC 8281 §5.3.1).
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

// DecodeFromBytes decodes the given bytes into the LSPObject.
func (o *LSPObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 4 {
		return fmt.Errorf("LSP object body too short: got %d bytes, need at least 4", len(objectBody))
	}

	o.ObjectType = typ
	o.PlspID = binary.BigEndian.Uint32(objectBody[0:4]) >> 12 // 20 bits from top
	o.CFlag = (objectBody[3] & 0x80) != 0
	o.OFlag = objectBody[3] & 0x0070 >> 4
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

// Serialize encodes the LSPObject into bytes.
func (o *LSPObject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 4)
	binary.BigEndian.PutUint32(buf, (o.PlspID&0xFFFFF)<<12|uint32(o.OFlag&0x07)<<4)
	if o.CFlag {
		buf[3] |= 0x80
	}
	if o.AFlag {
		buf[3] |= 0x08
	}
	if o.RFlag {
		buf[3] |= 0x04
	}
	if o.SFlag {
		buf[3] |= 0x02
	}
	if o.DFlag {
		buf[3] |= 0x01
	}
	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		b, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		byteTLVs = AppendByteSlices(byteTLVs, b)
	}

	length, err := objectLength(buf, byteTLVs)
	if err != nil {
		return nil, err
	}
	lspObjectHeader := NewCommonObjectHeader(ObjectClassLSP, o.ObjectType, length)

	return AppendByteSlices(lspObjectHeader.Serialize(), buf, byteTLVs), nil
}

// Len returns the wire length of the LSPObject.
func (o *LSPObject) Len() int {
	tlvsByteLength := 0
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	// PLSP-ID, Flags (4byte) + tlvslength(variable)
	lspObjectBodyLength := 4 + tlvsByteLength
	// CommonObjectHeader(4byte) + LSP object body
	return int(commonObjectHeaderLength) + lspObjectBodyLength
}

// NewLSPObject creates a new LSPObject.
func NewLSPObject(lspName string, color *uint32, plspID uint32) *LSPObject {
	o := &LSPObject{
		ObjectType: ObjectTypeLSPLSP,
		Name:       lspName,
		PlspID:     plspID,
		CFlag:      true,     // (RFC 8281 §5.3.1)
		OFlag:      uint8(1), // UP (RFC 8231 §7.3)
		AFlag:      true,     // desired operational state is active (RFC 8231 §7.3)
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
	return o
}

// Color returns the color value from the LSPObject's Color TLV, or 0 if not present.
func (o *LSPObject) Color() uint32 {
	for _, tlv := range o.TLVs {
		if t, ok := tlv.(*Color); ok {
			return t.Color
		}

	}
	return 0
}

// ERO Object (RFC 5440 §7.9)
const (
	ObjectTypeEROExplicitRoute ObjectType = 0x01
)

// EroObject represents a PCEP Explicit Route (ERO) object (RFC 5440 §7.9).
type EroObject struct {
	ObjectType    ObjectType
	EroSubobjects []EroSubobject
}

// DecodeFromBytes decodes the given bytes into the EroObject.
func (o *EroObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	o.ObjectType = typ
	if len(objectBody) == 0 {
		return nil
	}
	for {
		var eroSubobj EroSubobject
		switch SubobjectType(objectBody[0] & 0x7f) {
		case SubobjectTypeEROSR:
			eroSubobj = &SREroSubobject{}
		case SubobjectTypeEROSRv6:
			eroSubobj = &SRv6EroSubobject{}
		case SubobjectTypeEROIPv4Prefix:
			eroSubobj = &RSVPIPv4PrefixEroSubobject{}
		default:
			return errors.New("invalid Subobject type")
		}
		if err := eroSubobj.DecodeFromBytes(objectBody); err != nil {
			return err
		}
		o.EroSubobjects = append(o.EroSubobjects, eroSubobj)
		// DecodeFromBytes validates the subobject length before advancing objectBody.
		objByteLength, err := eroSubobj.Len()
		if err != nil {
			return err
		}
		if int(objByteLength) == len(objectBody) {
			break
		}
		objectBody = objectBody[objByteLength:]
	}
	return nil
}

// Serialize encodes the EroObject into bytes.
func (o EroObject) Serialize() ([]uint8, error) {
	byteEroSubobjects := []uint8{}
	for _, eroSubobject := range o.EroSubobjects {
		// Len() also validates flag/NAI-type combinations that Serialize() does not check itself.
		if _, err := eroSubobject.Len(); err != nil {
			return nil, err
		}
		buf, err := eroSubobject.Serialize()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize subobject: %w", err)
		}
		byteEroSubobjects = append(byteEroSubobjects, buf...)
	}

	length, err := objectLength(byteEroSubobjects)
	if err != nil {
		return nil, err
	}
	eroObjectHeader := NewCommonObjectHeader(ObjectClassERO, o.ObjectType, length)

	return AppendByteSlices(eroObjectHeader.Serialize(), byteEroSubobjects), nil
}

// Len returns the wire length of the EroObject.
func (o EroObject) Len() (int, error) {
	eroSubobjByteLength := 0
	for _, eroSubObj := range o.EroSubobjects {
		objByteLength, err := eroSubObj.Len()
		if err != nil {
			return 0, err
		}
		eroSubobjByteLength += int(objByteLength)
	}
	// CommonObjectHeader(4byte) + eroSubobjects(variable)
	return int(commonObjectHeaderLength) + eroSubobjByteLength, nil
}

// NewEroObject creates a new EroObject from a segment list.
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

// AddEroSubobjects appends ERO subobjects from the given segment list to the EroObject.
func (o *EroObject) AddEroSubobjects(segmentList []table.Segment) error {
	for _, segment := range segmentList {
		eroSubobject, err := NewEroSubobject(segment)
		if err != nil {
			return err
		}

		o.EroSubobjects = append(o.EroSubobjects, eroSubobject)
	}

	return nil
}

// ToSegmentList converts the EroObject's subobjects to a segment list.
func (o *EroObject) ToSegmentList() []table.Segment {
	sl := []table.Segment{}
	for _, so := range o.EroSubobjects {
		// Subobjects that do not map to an SR segment (e.g. RSVP IPv4 prefix
		// hops) return nil and must be skipped rather than injected as a
		// zero-value segment.
		if seg := so.ToSegment(); seg != nil {
			sl = append(sl, seg)
		}
	}
	return sl
}

// EroSubobject is an interface for PCEP ERO subobject types.
type EroSubobject interface {
	DecodeFromBytes([]uint8) error
	Len() (uint16, error)
	Serialize() ([]uint8, error)
	ToSegment() table.Segment
}

// NewEroSubobject creates an appropriate EroSubobject from the given segment.
func NewEroSubobject(seg table.Segment) (EroSubobject, error) {
	if v, ok := seg.(table.SegmentSRMPLS); ok {
		subo, err := NewSREroSubobject(v)
		if err != nil {
			return nil, err
		}
		return subo, nil
	} else if v, ok := seg.(table.SegmentSRv6); ok {
		subo, err := NewSRv6EroSubobject(v)
		if err != nil {
			return nil, err
		}
		return subo, nil
	}
	return nil, errors.New("invalid Segment type")
}

// SR-ERO Subobject (RFC 8664 §4.3.1)
const (
	SubobjectTypeEROSR SubobjectType = 0x24
)

// NAITypeSR is the NAI type of an SR-ERO subobject (RFC §8664).
type NAITypeSR uint8

// NAI types for SR-ERO subobjects (RFC 8664 §4.3.1).
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

// StringWithReference returns a human-readable representation with reference.
func (nt NAITypeSR) StringWithReference() string {
	if desc, ok := naiTypeSRDescriptions[nt]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, uint8(nt), desc.Reference)
	}
	return fmt.Sprintf("Unknown NAI Type (0x%02x)", uint8(nt))
}

// SREroSubobject is an SR-ERO subobject carrying an SR-MPLS segment (RFC 8664 §4.3.1).
type SREroSubobject struct {
	LFlag         bool
	SubobjectType SubobjectType
	Length        uint8
	NAIType       NAITypeSR
	FFlag         bool
	SFlag         bool
	CFlag         bool
	MFlag         bool
	Segment       table.SegmentSRMPLS
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (o *SREroSubobject) DecodeFromBytes(subobject []uint8) error {
	if len(subobject) < 4 {
		return errors.New("SREroSubobject: subobject too short")
	}

	o.LFlag = (subobject[0] & 0x80) != 0
	o.SubobjectType = SubobjectType(subobject[0] & 0x7f)
	o.Length = subobject[1]
	o.NAIType = NAITypeSR(subobject[2] >> 4)
	o.FFlag = (subobject[3] & 0x08) != 0
	o.SFlag = (subobject[3] & 0x04) != 0
	o.CFlag = (subobject[3] & 0x02) != 0
	o.MFlag = (subobject[3] & 0x01) != 0

	if o.SFlag && o.FFlag {
		return errors.New("SREroSubobject: both SID and NAI are absent")
	}
	// Bound reads to the declared length to prevent consuming the next subobject.
	if int(o.Length) < 4 || len(subobject) < int(o.Length) {
		return errors.New("SREroSubobject: invalid subobject length")
	}
	subobject = subobject[:o.Length]

	off, err := o.decodeSID(subobject)
	if err != nil {
		return err
	}

	off, err = o.decodeNAI(subobject, off)
	if err != nil {
		return err
	}

	if off != len(subobject) {
		return errors.New("SREroSubobject: declared length does not match S/F flags")
	}
	return nil
}

func (o *SREroSubobject) decodeSID(subobject []uint8) (int, error) {
	if o.SFlag {
		o.Segment = table.SegmentSRMPLS{}
		return 4, nil
	}
	if len(subobject) < 8 {
		return 0, errors.New("SREroSubobject: subobject too short")
	}
	sidWord := binary.BigEndian.Uint32(subobject[4:8])
	o.Segment = table.NewSegmentSRMPLS(sidWord >> 12)
	if o.CFlag {
		// Per RFC 8664 §4.3.1: when C=1, TC/S/TTL of the MPLS LSE are set by the PCE.
		o.Segment.TC = uint8((sidWord >> 9) & 0x07)
		o.Segment.S = (sidWord & (uint32(1) << 8)) != 0
		o.Segment.TTL = uint8(sidWord & 0xFF)
	}
	return 8, nil
}

func (o *SREroSubobject) decodeNAI(subobject []uint8, off int) (int, error) {
	if o.FFlag {
		return off, nil
	}
	naiLength, err := o.NAIType.naiLength()
	if err != nil {
		return 0, err
	}
	if naiLength > 0 && len(subobject) < off+int(naiLength) {
		return 0, fmt.Errorf("SREroSubobject: truncated NAI (%s)", o.NAIType)
	}
	switch o.NAIType {
	case NAITypeSRIPv4Node, NAITypeSRIPv6Node:
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subobject[off : off+int(naiLength)])
	case NAITypeSRIPv4Adjacency, NAITypeSRIPv6AdjacencyGlobal:
		half := off + int(naiLength)/2
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subobject[off:half])
		o.Segment.RemoteAddr, _ = netip.AddrFromSlice(subobject[half : off+int(naiLength)])
	}
	return off + int(naiLength), nil
}

// serializeNAI encodes the NAI following the SID, or nil when it is absent.
func (o *SREroSubobject) serializeNAI() ([]uint8, error) {
	if o.FFlag {
		return nil, nil
	}

	local, remote := o.Segment.LocalAddr.Unmap(), o.Segment.RemoteAddr.Unmap()
	switch o.NAIType {
	case NAITypeSRAbsent:
		return nil, nil
	case NAITypeSRIPv4Node:
		if !local.Is4() {
			return nil, errors.New("SREroSubobject: IPv4 node NAI requires an IPv4 LocalAddr")
		}
		return local.AsSlice(), nil
	case NAITypeSRIPv6Node:
		if !local.Is6() {
			return nil, errors.New("SREroSubobject: IPv6 node NAI requires an IPv6 LocalAddr")
		}
		return local.AsSlice(), nil
	case NAITypeSRIPv4Adjacency:
		if !local.Is4() || !remote.Is4() {
			return nil, errors.New("SREroSubobject: IPv4 adjacency NAI requires IPv4 LocalAddr and RemoteAddr")
		}
		return AppendByteSlices(local.AsSlice(), remote.AsSlice()), nil
	case NAITypeSRIPv6AdjacencyGlobal:
		if !local.Is6() || !remote.Is6() {
			return nil, errors.New("SREroSubobject: IPv6 adjacency NAI requires IPv6 LocalAddr and RemoteAddr")
		}
		return AppendByteSlices(local.AsSlice(), remote.AsSlice()), nil
	default:
		return nil, errors.New("unsupported naitype")
	}
}

// Serialize encodes the receiver into bytes.
func (o *SREroSubobject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 4)
	buf[0] = uint8(o.SubobjectType)
	if o.LFlag {
		buf[0] |= 0x80
	}
	buf[1] = o.Length
	buf[2] = uint8(o.NAIType) * 16
	if o.FFlag {
		buf[3] |= 0x08
	}
	if o.SFlag {
		buf[3] |= 0x04
	}
	if o.CFlag {
		buf[3] |= 0x02
	}
	if o.MFlag {
		buf[3] |= 0x01
	}

	var byteSid []uint8
	if !o.SFlag {
		sidWord := (o.Segment.Sid & 0xFFFFF) << 12
		if o.CFlag {
			sidWord |= uint32(o.Segment.TC&0x07) << 9
			if o.Segment.S {
				sidWord |= uint32(1) << 8
			}
			sidWord |= uint32(o.Segment.TTL)
		}
		byteSid = make([]uint8, 4)
		binary.BigEndian.PutUint32(byteSid, sidWord)
	}

	byteNAI, err := o.serializeNAI()
	if err != nil {
		return nil, err
	}

	return AppendByteSlices(buf, byteSid, byteNAI), nil
}

func (nt NAITypeSR) naiLength() (uint16, error) {
	switch nt {
	case NAITypeSRAbsent:
		return 0, nil
	case NAITypeSRIPv4Node:
		return 4, nil
	case NAITypeSRIPv6Node:
		return 16, nil
	case NAITypeSRIPv4Adjacency:
		return 8, nil
	case NAITypeSRIPv6AdjacencyGlobal:
		return 32, nil
	default:
		// Unnumbered and link-local adjacency NAIs are not supported by the decoder.
		return 0, errors.New("unsupported naitype")
	}
}

// Len returns the wire length of the receiver.
func (o *SREroSubobject) Len() (uint16, error) {
	length := uint16(4)
	if !o.SFlag {
		length += 4
	}
	if o.FFlag {
		return length, nil
	}
	naiLength, err := o.NAIType.naiLength()
	if err != nil {
		return uint16(0), err
	}
	return length + naiLength, nil
}

// naiTypeSRFor derives the NAI type from LocalAddr and RemoteAddr
// according to RFC 8664 §4.3.1.
func naiTypeSRFor(seg table.SegmentSRMPLS) (NAITypeSR, error) {
	local, remote := seg.LocalAddr.Unmap(), seg.RemoteAddr.Unmap()
	if !local.IsValid() {
		if remote.IsValid() {
			return NAITypeSRAbsent, errors.New("SegmentSRMPLS: RemoteAddr requires LocalAddr")
		}
		return NAITypeSRAbsent, nil
	}
	if !remote.IsValid() {
		if local.Is4() {
			return NAITypeSRIPv4Node, nil
		}
		return NAITypeSRIPv6Node, nil
	}
	if local.Is4() != remote.Is4() {
		return NAITypeSRAbsent, errors.New("SegmentSRMPLS: LocalAddr and RemoteAddr must be of the same address family")
	}
	if local.Is4() {
		return NAITypeSRIPv4Adjacency, nil
	}
	if local.IsLinkLocalUnicast() || remote.IsLinkLocalUnicast() {
		return NAITypeSRAbsent, errors.New("SegmentSRMPLS: link-local IPv6 adjacency NAI is unsupported")
	}
	return NAITypeSRIPv6AdjacencyGlobal, nil
}

// NewSREroSubobject creates and returns a new SREroSubobject.
func NewSREroSubobject(seg table.SegmentSRMPLS) (*SREroSubobject, error) {
	naiType, err := naiTypeSRFor(seg)
	if err != nil {
		return nil, err
	}

	subo := &SREroSubobject{
		LFlag:         false,
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       naiType,
		FFlag:         naiType == NAITypeSRAbsent, // F=1: NAI is absent
		SFlag:         false,
		CFlag:         seg.HasMPLSStackEntryAttrs(),
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

// ToSegment converts the receiver to a Segment.
func (o *SREroSubobject) ToSegment() table.Segment {
	return o.Segment
}

// SRv6-ERO Subobject (RFC 9603 §4.3.1)
const (
	SubobjectTypeEROSRv6 SubobjectType = 0x28
)

// NAITypeSRv6 is the NAI type of an SRv6-ERO subobject (RFC 9603).
type NAITypeSRv6 uint8

// NAI types for SRv6-ERO subobjects (RFC 9603 §4.3.1).
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

// StringWithReference returns a human-readable representation with reference.
func (nt NAITypeSRv6) StringWithReference() string {
	if desc, ok := naiTypeSRv6Descriptions[nt]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, uint8(nt), desc.Reference)
	}
	return fmt.Sprintf("Unknown NAI Type (0x%02x)", uint8(nt))
}

// SRv6EroSubobject is an SRv6-ERO subobject carrying an SRv6 segment (RFC 9603 §4.3.1).
type SRv6EroSubobject struct {
	LFlag         bool
	SubobjectType SubobjectType
	Length        uint8
	NAIType       NAITypeSRv6
	VFlag         bool
	TFlag         bool
	FFlag         bool
	SFlag         bool
	Segment       table.SegmentSRv6
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (o *SRv6EroSubobject) DecodeFromBytes(subobject []uint8) error {
	if len(subobject) < 8 {
		return errors.New("SRv6EroSubobject: subobject too short")
	}

	o.LFlag = (subobject[0] & 0x80) != 0
	o.SubobjectType = SubobjectType(subobject[0] & 0x7f)
	o.Length = subobject[1]
	o.NAIType = NAITypeSRv6(subobject[2] >> 4)
	o.VFlag = (subobject[3] & 0x08) != 0
	o.TFlag = (subobject[3] & 0x04) != 0
	o.FFlag = (subobject[3] & 0x02) != 0
	o.SFlag = (subobject[3] & 0x01) != 0

	if o.SFlag && o.FFlag {
		return errors.New("SRv6EroSubobject: both SID and NAI are absent")
	}
	// Bound reads to the declared length to prevent consuming the next subobject.
	if int(o.Length) < 8 || len(subobject) < int(o.Length) {
		return errors.New("SRv6EroSubobject: invalid subobject length")
	}
	subobject = subobject[:o.Length]

	behavior := binary.BigEndian.Uint16(subobject[6:8])

	off, err := o.decodeSID(subobject, 8)
	if err != nil {
		return err
	}

	if !o.FFlag {
		off, err = o.decodeNAI(subobject, off)
		if err != nil {
			return err
		}
	}

	if o.TFlag {
		if len(subobject) < off+8 {
			return errors.New("SRv6EroSubobject: truncated SID-Structure")
		}
		o.Segment.Structure = []uint8{
			subobject[off+0],
			subobject[off+1],
			subobject[off+2],
			subobject[off+3],
		}
		if err := o.Segment.Structure.Validate(); err != nil {
			return err
		}
		off += 8
	}

	if off != len(subobject) {
		return errors.New("SRv6EroSubobject: declared length does not match V/T/F/S flags")
	}

	if table.IsUSidBehavior(behavior) {
		o.Segment.USid = true
	}

	return nil
}

func (o *SRv6EroSubobject) decodeSID(subobject []uint8, off int) (int, error) {
	if o.SFlag {
		o.Segment = table.SegmentSRv6{}
		return off, nil
	}
	if len(subobject) < off+16 {
		return off, errors.New("SRv6EroSubobject: truncated SID")
	}
	sid, _ := netip.AddrFromSlice(subobject[off : off+16])
	o.Segment = table.NewSegmentSRv6(sid)
	return off + 16, nil
}

func (o *SRv6EroSubobject) decodeNAI(subobject []uint8, off int) (int, error) {
	switch o.NAIType {
	case NAITypeSRv6IPv6Node:
		if len(subobject) < off+16 {
			return off, errors.New("SRv6EroSubobject: truncated NAI (Node)")
		}
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subobject[off : off+16])
		return off + 16, nil
	case NAITypeSRv6IPv6AdjacencyGlobal:
		if len(subobject) < off+32 {
			return off, errors.New("SRv6EroSubobject: truncated NAI (AdjGlobal)")
		}
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subobject[off : off+16])
		o.Segment.RemoteAddr, _ = netip.AddrFromSlice(subobject[off+16 : off+32])
		return off + 32, nil
	case NAITypeSRv6IPv6AdjacencyLinkLocal:
		if len(subobject) < off+40 {
			return off, errors.New("SRv6EroSubobject: truncated NAI (AdjLinkLocal)")
		}
		o.Segment.LocalAddr, _ = netip.AddrFromSlice(subobject[off : off+16])
		// subobject[off+16 : off+20] — Local Interface ID (not parsed)
		o.Segment.RemoteAddr, _ = netip.AddrFromSlice(subobject[off+20 : off+36])
		// subobject[off+36 : off+40] — Remote Interface ID (not parsed)
		return off + 40, nil
	default:
		return off, nil
	}
}

// Serialize encodes the receiver into bytes.
func (o *SRv6EroSubobject) Serialize() ([]uint8, error) {
	buf := make([]uint8, 4)
	buf[0] = uint8(o.SubobjectType)
	if o.LFlag {
		buf[0] |= 0x80
	}
	buf[1] = o.Length
	buf[2] = uint8(o.NAIType) * 16
	if o.VFlag {
		buf[3] |= 0x08
	}
	if o.TFlag {
		buf[3] |= 0x04
	}
	if o.FFlag {
		buf[3] |= 0x02
	}
	if o.SFlag {
		buf[3] |= 0x01
	}

	reserved := make([]uint8, 2)

	behaviorBytes := Uint16ToByteSlice(o.Segment.Behavior())

	byteSid := o.Segment.Sid.AsSlice()

	byteNAI := o.Segment.LocalAddr.AsSlice()
	if o.Segment.RemoteAddr.IsValid() {
		byteNAI = append(byteNAI, o.Segment.RemoteAddr.AsSlice()...)
	}

	byteSidStructure := []uint8{}
	if o.Segment.Structure != nil {
		byteSidStructure = append(byteSidStructure, o.Segment.Structure...)
		byteSidStructure = append(byteSidStructure, make([]uint8, 4)...)
	}

	byteSRv6EroSubobject := AppendByteSlices(buf, reserved, behaviorBytes, byteSid, byteNAI, byteSidStructure)
	return byteSRv6EroSubobject, nil
}

// Len returns the wire length of the receiver.
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

// NewSRv6EroSubobject creates and returns a new SRv6EroSubobject.
func NewSRv6EroSubobject(seg table.SegmentSRv6) (*SRv6EroSubobject, error) {
	subo := &SRv6EroSubobject{
		SubobjectType: SubobjectTypeEROSRv6,
		Segment:       seg,
	}

	if err := seg.Structure.Validate(); err != nil {
		return nil, fmt.Errorf("SegmentSRv6: invalid SID structure: %w", err)
	}
	if len(seg.Structure) == 0 {
		subo.Segment.Structure = nil
	}
	subo.TFlag = len(subo.Segment.Structure) > 0

	local, remote := seg.LocalAddr.Unmap(), seg.RemoteAddr.Unmap()
	switch {
	case !local.IsValid():
		if remote.IsValid() {
			return nil, errors.New("SegmentSRv6: RemoteAddr requires LocalAddr")
		}
		subo.FFlag = true
		subo.NAIType = NAITypeSRv6Absent
	case !local.Is6():
		return nil, errors.New("SegmentSRv6: NAI LocalAddr must be IPv6")
	case remote.IsValid() && !remote.Is6():
		return nil, errors.New("SegmentSRv6: NAI RemoteAddr must be IPv6")
	case local.IsLinkLocalUnicast() || remote.IsLinkLocalUnicast():
		// Link-local adjacencies require NAITypeSRv6IPv6AdjacencyLinkLocal
		// (RFC 9603 §4.3.1), which is not yet supported for encoding.
		return nil, errors.New("SegmentSRv6: link-local IPv6 adjacency NAI is unsupported")
	case remote.IsValid():
		subo.FFlag = false
		subo.NAIType = NAITypeSRv6IPv6AdjacencyGlobal
	default:
		subo.FFlag = false
		subo.NAIType = NAITypeSRv6IPv6Node
	}

	length, err := subo.Len()
	if err != nil {
		return subo, err
	}
	subo.Length = uint8(length)
	return subo, nil
}

// ToSegment converts the receiver to a Segment.
func (o *SRv6EroSubobject) ToSegment() table.Segment {
	return o.Segment
}

const (
	// SubobjectTypeEROIPv4Prefix is the RSVP IPv4 Prefix ERO subobject (RFC 3209, §4.3.3.1).
	SubobjectTypeEROIPv4Prefix SubobjectType = 0x01

	// rsvpIPv4PrefixEroSubobjectLength is the fixed on-wire length:
	// L|Type(1) + Length(1) + IPv4(4) + Prefix(1) + Reserved(1).
	rsvpIPv4PrefixEroSubobjectLength uint8 = 8

	maxIPv4PrefixLen uint8 = 32
)

// RSVPIPv4PrefixEroSubobject is an RSVP IPv4 prefix ERO subobject (RFC 3209 §4.3.3.1).
type RSVPIPv4PrefixEroSubobject struct {
	LFlag         bool
	SubobjectType SubobjectType
	Length        uint8
	Address       netip.Addr
	PrefixLen     uint8
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (o *RSVPIPv4PrefixEroSubobject) DecodeFromBytes(subobject []uint8) error {
	if len(subobject) < int(rsvpIPv4PrefixEroSubobjectLength) {
		return fmt.Errorf("RSVPIPv4PrefixEroSubobject: subobject too short: %d", len(subobject))
	}

	// RFC 3209 §4.3.3.1 defines a fixed length of 8 bytes for this subobject.
	// Validate it to prevent malformed input from desynchronizing the ERO decode loop.
	if subobject[1] != rsvpIPv4PrefixEroSubobjectLength {
		return fmt.Errorf("RSVPIPv4PrefixEroSubobject: invalid length field: %d", subobject[1])
	}

	o.LFlag = (subobject[0] & 0x80) != 0
	o.SubobjectType = SubobjectType(subobject[0] & 0x7f)
	o.Length = subobject[1]

	var addr [4]byte
	copy(addr[:], subobject[2:6])
	o.Address = netip.AddrFrom4(addr)

	o.PrefixLen = subobject[6]
	if o.PrefixLen > maxIPv4PrefixLen {
		return fmt.Errorf("RSVPIPv4PrefixEroSubobject: invalid prefix length: %d", o.PrefixLen)
	}

	return nil
}

// Serialize encodes the receiver into bytes.
func (o *RSVPIPv4PrefixEroSubobject) Serialize() ([]uint8, error) {
	if !o.Address.Is4() {
		return nil, fmt.Errorf("RSVPIPv4PrefixEroSubobject: address is not IPv4: %v", o.Address)
	}
	if o.PrefixLen > maxIPv4PrefixLen {
		return nil, fmt.Errorf("RSVPIPv4PrefixEroSubobject: invalid prefix length: %d", o.PrefixLen)
	}

	buf := make([]uint8, rsvpIPv4PrefixEroSubobjectLength)
	buf[0] = uint8(o.SubobjectType)

	if o.LFlag {
		buf[0] |= 0x80
	}

	buf[1] = rsvpIPv4PrefixEroSubobjectLength

	a := o.Address.As4()
	copy(buf[2:6], a[:])

	buf[6] = o.PrefixLen
	buf[7] = 0 // Reserved: MUST be sent as zero (RFC 3209 §4.3.3.1).

	return buf, nil
}

// Len returns the wire length of the receiver.
func (o *RSVPIPv4PrefixEroSubobject) Len() (uint16, error) {
	return uint16(rsvpIPv4PrefixEroSubobjectLength), nil
}

// NewRSVPIPv4PrefixEroSubobject creates and returns a new RSVPIPv4PrefixEroSubobject.
func NewRSVPIPv4PrefixEroSubobject(address netip.Addr, prefixLen uint8) (*RSVPIPv4PrefixEroSubobject, error) {
	if !address.Is4() {
		return nil, fmt.Errorf("RSVPIPv4PrefixEroSubobject: address is not IPv4: %v", address)
	}
	if prefixLen > maxIPv4PrefixLen {
		return nil, fmt.Errorf("RSVPIPv4PrefixEroSubobject: invalid prefix length: %d", prefixLen)
	}

	return &RSVPIPv4PrefixEroSubobject{
		SubobjectType: SubobjectTypeEROIPv4Prefix,
		Length:        rsvpIPv4PrefixEroSubobjectLength,
		Address:       address,
		PrefixLen:     prefixLen,
	}, nil
}

// ToSegment returns nil because an RSVP IPv4 prefix hop does not map to an SR segment.
func (o *RSVPIPv4PrefixEroSubobject) ToSegment() table.Segment {
	return nil
}

// END-POINTS Object (RFC 5440 §7.6)
const (
	ObjectTypeEndpointIPv4 ObjectType = 0x01
	ObjectTypeEndpointIPv6 ObjectType = 0x02
)

// EndpointsObject is a PCEP END-POINTS object carrying the source and
// destination addresses of a path (RFC 5440 §7.6).
type EndpointsObject struct {
	ObjectType ObjectType
	SrcAddr    netip.Addr
	DstAddr    netip.Addr
}

// Serialize encodes the receiver into bytes.
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

// Len returns the wire length of the receiver.
func (o *EndpointsObject) Len() (uint16, error) {
	var length uint16
	switch {
	case o.SrcAddr.Is4() && o.DstAddr.Is4():
		// CommonObjectHeader(4byte) + srcIPv4 (4byte) + dstIPv4 (4byte)
		length = commonObjectHeaderLength + 4 + 4
	case o.SrcAddr.Is6() && o.DstAddr.Is6():
		// CommonObjectHeader(4byte) + srcIPv6 (16byte) + dstIPv6 (16byte)
		length = commonObjectHeaderLength + 16 + 16
	default:
		return uint16(0), fmt.Errorf("invalid endpoint addresses (Len()): source and destination must be both IPv4 or both IPv6: src=%v dst=%v", o.SrcAddr, o.DstAddr)
	}
	return length, nil
}

// NewEndpointsObject creates and returns a new EndpointsObject.
func NewEndpointsObject(dstAddr netip.Addr, srcAddr netip.Addr) (*EndpointsObject, error) {
	var objectType ObjectType
	switch {
	case dstAddr.Is4() && srcAddr.Is4():
		objectType = ObjectTypeEndpointIPv4
	case dstAddr.Is6() && srcAddr.Is6():
		objectType = ObjectTypeEndpointIPv6
	default:
		return nil, fmt.Errorf("invalid endpoint addresses (NewEndpointsObject): source and destination must be both IPv4 or both IPv6 (dst=%v src=%v)", dstAddr, srcAddr)
	}

	o := &EndpointsObject{
		ObjectType: objectType,
		DstAddr:    dstAddr,
		SrcAddr:    srcAddr,
	}
	return o, nil
}

// ASSOCIATION Object (RFC 8697 §6.)
const (
	ObjectTypeAssociationIPv4 ObjectType = 0x01
	ObjectTypeAssociationIPv6 ObjectType = 0x02
)

// Association types for SR Policy associations, including legacy PCC values.
const (
	AssociationTypeSRPolicyAssociation        AssocType = 0x06   // standard
	AssociationTypeSRPolicyAssociationCisco   AssocType = 0x14   // Cisco-specific
	AssociationTypeSRPolicyAssociationJuniper AssocType = 0xffe1 // Juniper-specific (deprecated)
)

// PccType values, selecting how SR Policy attributes are encoded towards a PCC.
const (
	// CiscoLegacy encodes color and preference in a Cisco VENDOR-INFORMATION object.
	CiscoLegacy PccType = iota
	// JuniperLegacy encodes the SR Policy association with Juniper vendor-specific TLVs.
	JuniperLegacy
	// RFCCompliant encodes the SR Policy association as specified by the IETF.
	RFCCompliant
)

// DeterminePccType determines the PCC type from the given capabilities.
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

// AssociationObject is a PCEP ASSOCIATION object carrying the SR Policy association and its TLVs (RFC 8697 §6).
type AssociationObject struct {
	ObjectType ObjectType
	RFlag      bool
	AssocType  AssocType
	AssocID    uint16
	AssocSrc   netip.Addr
	TLVs       []TLVInterface
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (o *AssociationObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < 8 {
		return fmt.Errorf("ASSOCIATION object body too short: got %d bytes, need at least 8", len(objectBody))
	}

	o.ObjectType = typ
	o.RFlag = (objectBody[3] & 0x01) != 0
	o.AssocType = AssocType(binary.BigEndian.Uint16(objectBody[4:6]))
	o.AssocID = binary.BigEndian.Uint16(objectBody[6:8])

	switch o.ObjectType {
	case ObjectTypeAssociationIPv4:
		if len(objectBody) < 12 {
			return fmt.Errorf("ASSOCIATION (IPv4) object body too short: got %d bytes, need at least 12", len(objectBody))
		}
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
		if len(objectBody) < 24 {
			return fmt.Errorf("ASSOCIATION (IPv6) object body too short: got %d bytes, need at least 24", len(objectBody))
		}
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

// Serialize encodes the receiver into bytes.
func (o *AssociationObject) Serialize() ([]uint8, error) {
	if !o.AssocSrc.Is4() && !o.AssocSrc.Is6() {
		return nil, errors.New("invalid association source address (Serialize)")
	}

	buf := make([]uint8, 4)

	if o.RFlag {
		buf[3] |= 0x01
	}

	assocType := Uint16ToByteSlice(o.AssocType)
	assocID := Uint16ToByteSlice(o.AssocID)
	assocSrc := o.AssocSrc.AsSlice()

	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		b, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		byteTLVs = append(byteTLVs, b...)
	}

	length, err := objectLength(buf, assocType, assocID, assocSrc, byteTLVs)
	if err != nil {
		return nil, err
	}
	associationObjectHeader := NewCommonObjectHeader(ObjectClassAssociation, o.ObjectType, length)

	return AppendByteSlices(
		associationObjectHeader.Serialize(), buf, assocType, assocID, assocSrc, byteTLVs,
	), nil
}

// Len returns the wire length of the receiver.
func (o AssociationObject) Len() (int, error) {
	tlvsByteLength := 0
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	var associationObjectBodyLength int
	switch {
	case o.AssocSrc.Is4():
		// Reserved(2byte) + Flags(2byte) + Assoc Type(2byte) + Assoc ID(2byte) + IPv4 Assoc Src(4byte)
		associationObjectBodyLength = 12 + tlvsByteLength
	case o.AssocSrc.Is6():
		// Reserved(2byte) + Flags(2byte) + Assoc Type(2byte) + Assoc ID(2byte) + IPv6 Assoc Src(16byte)
		associationObjectBodyLength = 24 + tlvsByteLength
	default:
		return 0, errors.New("invalid association source address (Len())")
	}
	return int(commonObjectHeaderLength) + associationObjectBodyLength, nil
}

// NewAssociationObject creates and returns a new AssociationObject.
func NewAssociationObject(srcAddr netip.Addr, dstAddr netip.Addr, color uint32, preference uint32, opt ...Opt) (*AssociationObject, error) {
	opts := optParams{
		pccType: RFCCompliant,
	}

	for _, o := range opt {
		o(&opts)
	}
	var objectType ObjectType
	switch {
	case dstAddr.Is4() && srcAddr.Is4():
		objectType = ObjectTypeAssociationIPv4
	case dstAddr.Is6() && srcAddr.Is6():
		objectType = ObjectTypeAssociationIPv6
	default:
		return nil, fmt.Errorf("invalid endpoints address (NewAssociationObject): src=%v dst=%v", srcAddr, dstAddr)
	}
	o := &AssociationObject{
		ObjectType: objectType,
		RFlag:      false,
		TLVs:       []TLVInterface{},
		AssocSrc:   srcAddr,
	}
	if opts.pccType == JuniperLegacy {
		if !dstAddr.Is4() {
			return nil, fmt.Errorf("invalid endpoint address for JuniperLegacy (NewAssociationObject): only IPv4 is supported, got dst=%v", dstAddr)
		}
		o.AssocID = 0
		o.AssocType = AssociationTypeSRPolicyAssociationJuniper
		associationObjectTLVs := []TLVInterface{
			&ExtendedAssociationIDIPv4Juniper{
				ExtendedAssociationID: ExtendedAssociationID{
					Color:    color,
					Endpoint: dstAddr, // JuniperLegacy has only IPv4 implementation
				},
			},
			&SRPolicyCandidatePathIdentifierJuniper{
				// Juniper legacy CPATH-ID TLV uses a zero-filled IPv4 Originator Address.
				SRPolicyCandidatePathIdentifier: SRPolicyCandidatePathIdentifier{
					ProtocolOrigin: ProtocolOriginPCEP,
					OriginatorASN:  opts.originatorASN,
					OriginatorAddr: netip.IPv4Unspecified(),
					Discriminator:  1,
				},
			},
			&SRPolicyCandidatePathPreferenceJuniper{
				SRPolicyCandidatePathPreference: SRPolicyCandidatePathPreference{
					Preference: preference,
				},
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
				ProtocolOrigin: ProtocolOriginPCEP, // this PCE originates the candidate path
				OriginatorASN:  opts.originatorASN,
				OriginatorAddr: dstAddr,
				Discriminator:  1, // keep existing wire value
			},
			&SRPolicyCandidatePathPreference{
				Preference: preference,
			},
		}
		o.TLVs = append(o.TLVs, associationObjectTLVs...)
	}

	return o, nil
}

// Color returns the SR Policy color, or 0 if it is not present.
func (o *AssociationObject) Color() uint32 {
	for _, tlv := range o.TLVs {
		switch t := tlv.(type) {
		case *ExtendedAssociationIDIPv4Juniper:
			return t.Color

		case *ExtendedAssociationID:
			return t.Color

		case *UnknownTLV:
			if t.Type() == TLVExtendedAssociationIDIPv4Juniper && len(t.Value) >= 4 {
				return binary.BigEndian.Uint32(t.Value[:4])
			}
		}
	}
	return 0
}

// Preference returns the SR Policy candidate path preference, or 0 if it is not present.
func (o *AssociationObject) Preference() uint32 {
	for _, tlv := range o.TLVs {
		switch t := tlv.(type) {
		case *SRPolicyCandidatePathPreferenceJuniper:
			return t.Preference

		case *SRPolicyCandidatePathPreference:
			return t.Preference

		case *UnknownTLV:
			if t.Type() == TLVSRPolicyCPathPreferenceJuniper && len(t.Value) >= 4 {
				return binary.BigEndian.Uint32(t.Value)
			}
		}
	}
	return 0
}

// Endpoint returns the SR Policy endpoint address, or the zero Addr if it is not present.
func (o *AssociationObject) Endpoint() netip.Addr {
	for _, tlv := range o.TLVs {
		switch t := tlv.(type) {
		case *ExtendedAssociationIDIPv4Juniper:
			return t.Endpoint
		case *ExtendedAssociationID:
			return t.Endpoint
		}
	}
	return netip.Addr{}
}

// VENDOR-INFORMATION Object (RFC 7470 §4)
const (
	ObjectTypeVendorSpecificConstraints ObjectType = 0x01
)

// VendorInformationObject is a PCEP VENDOR-INFORMATION object carrying Cisco legacy color and preference sub-TLVs (RFC 7470 §4).
type VendorInformationObject struct {
	ObjectType       ObjectType // vendor specific constraints: 1
	EnterpriseNumber EnterpriseNumber
	TLVs             []TLVInterface
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (o *VendorInformationObject) DecodeFromBytes(typ ObjectType, objectBody []uint8) error {
	if len(objectBody) < int(EnterpriseNumberLength) {
		return fmt.Errorf("vendor information object: too short (got %d bytes, want ≥ %d)", len(objectBody), EnterpriseNumberLength)
	}

	o.ObjectType = typ
	o.EnterpriseNumber = EnterpriseNumber(binary.BigEndian.Uint32(objectBody[:EnterpriseNumberLength]))
	if len(objectBody) > int(EnterpriseNumberLength) {
		byteTLVs := objectBody[EnterpriseNumberLength:]
		var err error
		if o.TLVs, err = DecodeVendorTLVs(byteTLVs); err != nil {
			return err
		}

	}
	return nil
}

// Serialize encodes the receiver into bytes.
func (o *VendorInformationObject) Serialize() ([]uint8, error) {
	enterpriseNumber := Uint32ToByteSlice(uint32(o.EnterpriseNumber))

	byteTLVs := []uint8{}
	for _, tlv := range o.TLVs {
		b, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		byteTLVs = append(byteTLVs, b...)
	}

	length, err := objectLength(enterpriseNumber, byteTLVs)
	if err != nil {
		return nil, err
	}
	vendorInformationObjectHeader := NewCommonObjectHeader(ObjectClassVendorInformation, o.ObjectType, length)

	return AppendByteSlices(vendorInformationObjectHeader.Serialize(), enterpriseNumber, byteTLVs), nil
}

// Len returns the wire length of the receiver.
func (o *VendorInformationObject) Len() int {
	tlvsByteLength := 0
	for _, tlv := range o.TLVs {
		tlvsByteLength += tlv.Len()
	}
	// CommonObjectHeader(4byte) + Enterprise Number (4byte) + TLVs (variable)
	return int(commonObjectHeaderLength) + int(EnterpriseNumberLength) + tlvsByteLength
}

// NewVendorInformationObject creates and returns a new VendorInformationObject.
func NewVendorInformationObject(vendor PccType, color uint32, preference uint32) (*VendorInformationObject, error) {
	o := &VendorInformationObject{ // for Cisco PCC
		ObjectType: ObjectTypeVendorSpecificConstraints, // (RFC 7470 §4)
		TLVs:       []TLVInterface{},
	}
	if vendor == CiscoLegacy {
		o.EnterpriseNumber = EnterpriseNumberCisco
		vendorInformationObjectTLVs := []TLVInterface{
			&UnknownTLV{
				Typ:   SubTLVColorCisco,
				Value: Uint32ToByteSlice(color), // TODO: 20 if ipv6 endpoint
			},
			&UnknownTLV{
				Typ:   SubTLVPreferenceCisco,
				Value: Uint32ToByteSlice(preference),
			},
		}
		o.TLVs = append(o.TLVs, vendorInformationObjectTLVs...)
	} else {
		return nil, errors.New("unknown vendor information object type")
	}
	return o, nil
}

// Color returns the SR Policy color from the Cisco color sub-TLV, or 0 if it is not present.
func (o *VendorInformationObject) Color() uint32 {
	return o.subTLVUint32(SubTLVColorCisco)
}

// Preference returns the candidate path preference from the Cisco preference sub-TLV, or 0 if it is not present.
func (o *VendorInformationObject) Preference() uint32 {
	return o.subTLVUint32(SubTLVPreferenceCisco)
}

// subTLVUint32 returns the leading uint32 of the first sub-TLV of the given type, or 0 if it is absent or too short to hold one.
func (o *VendorInformationObject) subTLVUint32(typ TLVType) uint32 {
	for _, tlv := range o.TLVs {
		t, ok := tlv.(*UnknownTLV)
		if !ok || t.Type() != typ {
			continue
		}
		if len(t.Value) < 4 {
			return 0
		}
		return binary.BigEndian.Uint32(t.Value[:4])
	}
	return 0
}

type optParams struct {
	pccType       PccType
	originatorASN uint32
}

// Opt is a functional option for constructors that build SR Policy objects and messages.
type Opt func(*optParams)

// VendorSpecific returns an Opt that selects the encoding for the given PCC type instead of the default RFC-compliant encoding.
func VendorSpecific(pt PccType) Opt {
	return func(op *optParams) {
		op.pccType = pt
	}
}

// OriginatorASN returns an Opt that sets the originator ASN in the SR Policy Candidate Path Identifier TLV.
func OriginatorASN(asn uint32) Opt {
	return func(op *optParams) {
		op.originatorASN = asn
	}
}
