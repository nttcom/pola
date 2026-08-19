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

	"github.com/nttcom/pola/pkg/table"
)

// CommonHeaderLength is the wire length of a PCEP common header.
const CommonHeaderLength uint16 = 4

// PCEPVersion is the current PCEP protocol version.
const PCEPVersion uint8 = 1

// MessageType is a PCEP message type code.
type MessageType uint8

// PCEP message types.
const (
	MessageTypeOpen         MessageType = 0x01
	MessageTypeKeepalive    MessageType = 0x02
	MessageTypePcreq        MessageType = 0x03
	MessageTypePcrep        MessageType = 0x04
	MessageTypeNotification MessageType = 0x05
	MessageTypeError        MessageType = 0x06
	MessageTypeClose        MessageType = 0x07
	MessageTypePcmReq       MessageType = 0x08
	MessageTypePcmRep       MessageType = 0x09
	MessageTypeReport       MessageType = 0x0a
	MessageTypeUpdate       MessageType = 0x0b
	MessageTypeLSPInitReq   MessageType = 0x0c
	MessageTypeStartTLS     MessageType = 0x0d
)

var messageTypeDescriptions = map[MessageType]struct {
	Description string
	Reference   string
}{
	MessageTypeOpen:         {"Open", "RFC5440"},
	MessageTypeKeepalive:    {"Keepalive", "RFC5440"},
	MessageTypePcreq:        {"Path Computation Request", "RFC5440"},
	MessageTypePcrep:        {"Path Computation Reply", "RFC5440"},
	MessageTypeNotification: {"Notification", "RFC5440"},
	MessageTypeError:        {"Error", "RFC5440"},
	MessageTypeClose:        {"Close", "RFC5440"},
	MessageTypePcmReq:       {"Path Computation Monitoring Request", "RFC5886"},
	MessageTypePcmRep:       {"Path Computation Monitoring Reply", "RFC5886"},
	MessageTypeReport:       {"Report", "RFC8231"},
	MessageTypeUpdate:       {"Update", "RFC8281"},
	MessageTypeLSPInitReq:   {"LSP Initiate Request", "RFC8281"},
	MessageTypeStartTLS:     {"StartTLS", "RFC8253"},
}

func (t MessageType) String() string {
	if desc, ok := messageTypeDescriptions[t]; ok {
		return fmt.Sprintf("%s (0x%02x)", desc.Description, uint8(t))
	}
	return fmt.Sprintf("Unknown MessageType (0x%02x)", uint8(t))
}

// StringWithReference returns a human-readable representation of the message type with reference.
func (t MessageType) StringWithReference() string {
	if desc, ok := messageTypeDescriptions[t]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, uint8(t), desc.Reference)
	}
	return fmt.Sprintf("Unknown MessageType (0x%02x)", uint8(t))
}

// CommonHeader is the common header of a PCEP message (RFC 5440 §6.1).
type CommonHeader struct { // RFC 5440 §6.1
	Version       uint8 // Current version is 1
	Flag          uint8
	MessageType   MessageType
	MessageLength uint16
}

// DecodeFromBytes decodes the given bytes into the CommonHeader.
func (h *CommonHeader) DecodeFromBytes(header []uint8) error {
	if len(header) < int(CommonHeaderLength) {
		return fmt.Errorf("PCEP common header too short: got %d bytes, need %d", len(header), CommonHeaderLength)
	}
	h.Version = header[0] >> 5
	h.Flag = header[0] & 0x1f
	h.MessageType = MessageType(header[1])
	h.MessageLength = binary.BigEndian.Uint16(header[2:4])

	if h.Version != PCEPVersion {
		return fmt.Errorf("unsupported PCEP version %d", h.Version)
	}
	// RFC 5440 §6.1 requires Message-Length to include the common header.
	if h.MessageLength < CommonHeaderLength {
		return fmt.Errorf("invalid PCEP message length %d", h.MessageLength)
	}
	if h.MessageType == MessageTypeKeepalive && h.MessageLength != CommonHeaderLength {
		return fmt.Errorf("invalid Keepalive message length %d, must be %d", h.MessageLength, CommonHeaderLength)
	}
	return nil
}

// Serialize encodes the CommonHeader into bytes.
func (h *CommonHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	verFlag := h.Version<<5 | h.Flag
	buf = append(buf, verFlag)
	buf = append(buf, uint8(h.MessageType))
	buf = append(buf, Uint16ToByteSlice(h.MessageLength)...)
	return buf
}

// NewCommonHeader creates a new CommonHeader.
func NewCommonHeader(messageType MessageType, messageLength uint16) *CommonHeader {
	h := &CommonHeader{
		Version:       PCEPVersion,
		Flag:          uint8(0),
		MessageType:   messageType,
		MessageLength: messageLength,
	}
	return h
}

// messageLength returns the total PCEP message length, which must fit in the
// 16-bit Message-Length field.
func messageLength(objects ...[]uint8) (uint16, error) {
	total := int(CommonHeaderLength)
	for _, o := range objects {
		total += len(o)
	}
	if total > math.MaxUint16 {
		return 0, fmt.Errorf("PCEP message length %d exceeds %d", total, math.MaxUint16)
	}
	return uint16(total), nil
}

// Message is a common interface for all PCEP messages.
type Message interface {
	Serialize() ([]uint8, error)
}

var (
	_ Message = (*OpenMessage)(nil)
	_ Message = (*KeepaliveMessage)(nil)
	_ Message = (*PCErrMessage)(nil)
	_ Message = (*CloseMessage)(nil)
	_ Message = (*PCInitiateMessage)(nil)
	_ Message = (*PCUpdMessage)(nil)
)

func objectBody(messageBody []uint8, h *CommonObjectHeader) ([]uint8, error) {
	if h.ObjectLength < commonObjectHeaderLength || h.ObjectLength%4 != 0 {
		return nil, fmt.Errorf("invalid object length %d", h.ObjectLength)
	}
	if int(h.ObjectLength) > len(messageBody) {
		return nil, fmt.Errorf("object body extends past message (len=%d, total=%d)", h.ObjectLength, len(messageBody))
	}
	return messageBody[commonObjectHeaderLength:h.ObjectLength], nil
}

// OpenMessage is a PCEP Open message.
type OpenMessage struct {
	OpenObject *OpenObject
}

// DecodeFromBytes decodes the given bytes into the OpenMessage.
func (m *OpenMessage) DecodeFromBytes(messageBody []uint8) error {
	var commonObjectHeader CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
		return fmt.Errorf("failed to decode common object header: %w", err)
	}

	if commonObjectHeader.ObjectClass != ObjectClassOpen {
		return fmt.Errorf("unsupported ObjectClass: %d", commonObjectHeader.ObjectClass)
	}
	if commonObjectHeader.ObjectType != ObjectTypeOpenOpen {
		return fmt.Errorf("unsupported ObjectType: %d", commonObjectHeader.ObjectType)
	}

	body, err := objectBody(messageBody, &commonObjectHeader)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	if int(commonObjectHeader.ObjectLength) != len(messageBody) {
		return fmt.Errorf("open: %d trailing bytes after OPEN object", len(messageBody)-int(commonObjectHeader.ObjectLength))
	}

	openObject := &OpenObject{}
	if err := openObject.DecodeFromBytes(commonObjectHeader.ObjectType, body); err != nil {
		return fmt.Errorf("failed to decode OpenObject: %w", err)
	}
	m.OpenObject = openObject

	return nil
}

// Serialize encodes the OpenMessage into bytes.
func (m *OpenMessage) Serialize() ([]uint8, error) {
	byteOpenObject, err := m.OpenObject.Serialize()
	if err != nil {
		return nil, err
	}
	openMessageLength, err := messageLength(byteOpenObject)
	if err != nil {
		return nil, err
	}
	openHeader := NewCommonHeader(MessageTypeOpen, openMessageLength)
	byteOpenHeader := openHeader.Serialize()
	byteOpenMessage := AppendByteSlices(byteOpenHeader, byteOpenObject)
	return byteOpenMessage, nil
}

// NewOpenMessage creates a new OpenMessage.
func NewOpenMessage(sessionID uint8, keepalive uint8, deadTimer uint8, capabilities []CapabilityInterface) *OpenMessage {
	return &OpenMessage{
		OpenObject: NewOpenObject(sessionID, keepalive, deadTimer, capabilities),
	}
}

// KeepaliveMessage is a PCEP Keepalive message.
type KeepaliveMessage struct {
}

// Serialize encodes the KeepaliveMessage into bytes.
func (m *KeepaliveMessage) Serialize() ([]uint8, error) {
	keepaliveMessageLength := CommonHeaderLength
	keepaliveHeader := NewCommonHeader(MessageTypeKeepalive, keepaliveMessageLength)
	byteKeepaliveHeader := keepaliveHeader.Serialize()
	byteKeepaliveMessage := byteKeepaliveHeader
	return byteKeepaliveMessage, nil
}

// NewKeepaliveMessage creates a new KeepaliveMessage.
func NewKeepaliveMessage() *KeepaliveMessage {
	return &KeepaliveMessage{}
}

// PCErrMessage represents a PCEP Error message containing error objects and SRP objects.
type PCErrMessage struct {
	Errors []*ErrorObject
	SRPs   []*SrpObject
	Open   *OpenObject
}

// DecodeFromBytes decodes the given bytes into the PCErrMessage.
func (m *PCErrMessage) DecodeFromBytes(messageBody []uint8) error {
	for offset := 0; offset < len(messageBody); {
		if len(messageBody)-offset < int(commonObjectHeaderLength) {
			return fmt.Errorf("PCErr: truncated object header at offset %d", offset)
		}
		var commonObjectHeader CommonObjectHeader
		if err := commonObjectHeader.DecodeFromBytes(messageBody[offset : offset+int(commonObjectHeaderLength)]); err != nil {
			return err
		}
		body, err := objectBody(messageBody[offset:], &commonObjectHeader)
		if err != nil {
			return fmt.Errorf("PCErr: %w", err)
		}

		switch commonObjectHeader.ObjectClass {
		case ObjectClassPCEPError:
			errObj := &ErrorObject{}
			if err := errObj.DecodeFromBytes(commonObjectHeader.ObjectType, body); err != nil {
				return err
			}
			m.Errors = append(m.Errors, errObj)
		case ObjectClassSRP:
			srp := &SrpObject{}
			if err := srp.DecodeFromBytes(commonObjectHeader.ObjectType, body); err != nil {
				return err
			}
			m.SRPs = append(m.SRPs, srp)
		case ObjectClassOpen:
			openObj := &OpenObject{}
			if err := openObj.DecodeFromBytes(commonObjectHeader.ObjectType, body); err != nil {
				return err
			}
			m.Open = openObj
		}
		offset += int(commonObjectHeader.ObjectLength)
	}
	// RFC 5440 §6.7 requires at least one PCEP-ERROR object per PCErr message.
	if len(m.Errors) == 0 {
		return errors.New("PCErr: message carries no PCEP-ERROR object")
	}
	return nil
}

// Serialize encodes the PCErrMessage into bytes.
func (m *PCErrMessage) Serialize() ([]uint8, error) {
	objects := make([][]uint8, 0, len(m.SRPs)+len(m.Errors)+1)
	for _, srp := range m.SRPs {
		b, err := srp.Serialize()
		if err != nil {
			return nil, err
		}
		objects = append(objects, b)
	}
	for _, errObj := range m.Errors {
		b, err := errObj.Serialize()
		if err != nil {
			return nil, err
		}
		objects = append(objects, b)
	}
	if m.Open != nil {
		b, err := m.Open.Serialize()
		if err != nil {
			return nil, err
		}
		objects = append(objects, b)
	}
	length, err := messageLength(objects...)
	if err != nil {
		return nil, err
	}
	parts := make([][]uint8, 0, len(objects)+1)
	parts = append(parts, NewCommonHeader(MessageTypeError, length).Serialize())
	parts = append(parts, objects...)
	return AppendByteSlices(parts...), nil
}

// SRPIDs returns the SRP-IDs in wire order.
func (m *PCErrMessage) SRPIDs() []uint32 {
	if len(m.SRPs) == 0 {
		return nil
	}
	ids := make([]uint32, 0, len(m.SRPs))
	for _, srp := range m.SRPs {
		ids = append(ids, srp.SrpID)
	}
	return ids
}

// NewPCErrMessage creates a new PCErrMessage.
func NewPCErrMessage(errorType uint8, errorValue uint8, tlvs []TLVInterface) *PCErrMessage {
	return &PCErrMessage{
		Errors: []*ErrorObject{NewErrorObject(errorType, errorValue, tlvs)},
	}
}

// NewPCErrMessageWithOpen creates a PCErrMessage with an attached OPEN object.
func NewPCErrMessageWithOpen(errorType uint8, errorValue uint8, openObject *OpenObject) *PCErrMessage {
	return &PCErrMessage{
		Errors: []*ErrorObject{NewErrorObject(errorType, errorValue, nil)},
		Open:   openObject,
	}
}

// CloseMessage is a PCEP Close message.
type CloseMessage struct {
	CloseObject *CloseObject
}

// DecodeFromBytes decodes the given bytes into the CloseMessage.
func (m *CloseMessage) DecodeFromBytes(messageBody []uint8) error {
	var commonObjectHeader CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
		return err
	}
	if commonObjectHeader.ObjectClass != ObjectClassClose {
		return fmt.Errorf("unsupported ObjectClass: %d", commonObjectHeader.ObjectClass)
	}
	if commonObjectHeader.ObjectType != ObjectTypeCloseClose {
		return fmt.Errorf("unsupported ObjectType: %d", commonObjectHeader.ObjectType)
	}
	body, err := objectBody(messageBody, &commonObjectHeader)
	if err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if int(commonObjectHeader.ObjectLength) != len(messageBody) {
		return fmt.Errorf("close: %d trailing bytes after CLOSE object", len(messageBody)-int(commonObjectHeader.ObjectLength))
	}
	closeObject := &CloseObject{}
	if err := closeObject.DecodeFromBytes(commonObjectHeader.ObjectType, body); err != nil {
		return err
	}
	m.CloseObject = closeObject
	return nil
}

// Serialize encodes the CloseMessage into bytes.
func (m *CloseMessage) Serialize() ([]uint8, error) {
	byteCloseObject := m.CloseObject.Serialize()
	closeMessageLength, err := messageLength(byteCloseObject)
	if err != nil {
		return nil, err
	}
	closeHeader := NewCommonHeader(MessageTypeClose, closeMessageLength)
	byteCloseHeader := closeHeader.Serialize()
	byteCloseMessage := AppendByteSlices(byteCloseHeader, byteCloseObject)
	return byteCloseMessage, nil
}

// NewCloseMessage creates a new CloseMessage.
func NewCloseMessage(reason CloseReason) *CloseMessage {
	return &CloseMessage{
		CloseObject: NewCloseObject(reason),
	}
}

// StateReport is a state report carried in a PCRpt message.
type StateReport struct {
	SrpObject               *SrpObject
	LSPObject               *LSPObject
	EroObject               *EroObject
	LSPAObject              *LSPAObject
	MetricObjects           []*MetricObject
	BandwidthObjects        []*BandwidthObject
	AssociationObject       *AssociationObject
	VendorInformationObject *VendorInformationObject
}

// NewStateReport creates a new StateReport.
func NewStateReport() *StateReport {
	return &StateReport{
		SrpObject:               &SrpObject{},
		LSPObject:               &LSPObject{},
		EroObject:               &EroObject{},
		LSPAObject:              &LSPAObject{},
		MetricObjects:           []*MetricObject{},
		BandwidthObjects:        []*BandwidthObject{},
		AssociationObject:       &AssociationObject{},
		VendorInformationObject: &VendorInformationObject{},
	}
}

func (r *StateReport) decodeBandwidthObject(objectType ObjectType, objectBody []uint8) error {
	bandwidthObject := &BandwidthObject{}
	if err := bandwidthObject.DecodeFromBytes(objectType, objectBody); err != nil {
		return err
	}
	r.BandwidthObjects = append(r.BandwidthObjects, bandwidthObject)
	return nil
}

func (r *StateReport) decodeMetricObject(objectType ObjectType, objectBody []uint8) error {
	metricObject := &MetricObject{}
	if err := metricObject.DecodeFromBytes(objectType, objectBody); err != nil {
		return err
	}
	r.MetricObjects = append(r.MetricObjects, metricObject)
	return nil
}

func (r *StateReport) decodeEroObject(objectType ObjectType, objectBody []uint8) error {
	return r.EroObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeLSPAObject(objectType ObjectType, objectBody []uint8) error {
	return r.LSPAObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeLSPObject(objectType ObjectType, objectBody []uint8) error {
	return r.LSPObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeSrpObject(objectType ObjectType, objectBody []uint8) error {
	srpObject := &SrpObject{}
	if err := srpObject.DecodeFromBytes(objectType, objectBody); err != nil {
		return err
	}
	r.SrpObject = srpObject
	return nil
}

func (r *StateReport) decodeAssociationObject(objectType ObjectType, objectBody []uint8) error {
	return r.AssociationObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeVendorInformationObject(objectType ObjectType, objectBody []uint8) error {
	return r.VendorInformationObject.DecodeFromBytes(objectType, objectBody)
}

// PCRptMessage represents a PCEP Report message containing state reports.
type PCRptMessage struct {
	StateReports []*StateReport
}

var decodeFuncs = map[ObjectClass]func(*StateReport, ObjectType, []uint8) error{
	ObjectClassBandwidth:         (*StateReport).decodeBandwidthObject,
	ObjectClassMetric:            (*StateReport).decodeMetricObject,
	ObjectClassERO:               (*StateReport).decodeEroObject,
	ObjectClassLSPA:              (*StateReport).decodeLSPAObject,
	ObjectClassLSP:               (*StateReport).decodeLSPObject,
	ObjectClassSRP:               (*StateReport).decodeSrpObject,
	ObjectClassAssociation:       (*StateReport).decodeAssociationObject,
	ObjectClassVendorInformation: (*StateReport).decodeVendorInformationObject,
}

// DecodeFromBytes decodes the given bytes into the PCRptMessage.
func (m *PCRptMessage) DecodeFromBytes(messageBody []uint8) error {
	var previousObjectClass ObjectClass
	var sr *StateReport
	var lspDecoded bool
	for len(messageBody) > 0 {
		var commonObjectHeader CommonObjectHeader
		if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
			return err
		}
		body, err := objectBody(messageBody, &commonObjectHeader)
		if err != nil {
			return fmt.Errorf("PCRpt: %w", err)
		}

		decodeFunc, ok := decodeFuncs[commonObjectHeader.ObjectClass]
		if !ok {
			messageBody = messageBody[commonObjectHeader.ObjectLength:]
			continue
		}
		if (previousObjectClass != ObjectClassSRP && commonObjectHeader.ObjectClass == ObjectClassLSP) || commonObjectHeader.ObjectClass == ObjectClassSRP {
			if sr != nil {
				if !lspDecoded {
					return errors.New("PCRpt: state report missing LSP object")
				}
				m.StateReports = append(m.StateReports, sr)
			}

			sr = NewStateReport()
			lspDecoded = false
		}
		if sr == nil {
			return fmt.Errorf("PCRpt: object class %d received before SRP/LSP object", commonObjectHeader.ObjectClass)
		}
		if err := decodeFunc(sr, commonObjectHeader.ObjectType, body); err != nil {
			return err
		}
		if commonObjectHeader.ObjectClass == ObjectClassLSP {
			lspDecoded = true
		}
		previousObjectClass = commonObjectHeader.ObjectClass
		messageBody = messageBody[commonObjectHeader.ObjectLength:]
	}
	if sr == nil {
		return errors.New("PCRpt: no state report")
	}
	if !lspDecoded {
		return errors.New("PCRpt: state report missing LSP object")
	}
	m.StateReports = append(m.StateReports, sr)

	return nil
}

// NewPCRptMessage creates a new PCRptMessage.
func NewPCRptMessage() *PCRptMessage {
	return &PCRptMessage{
		StateReports: []*StateReport{},
	}
}

// PCInitiateMessage is a PCEP LSP Initiate Request message.
type PCInitiateMessage struct {
	SrpObject               *SrpObject
	LSPObject               *LSPObject
	EndpointsObject         *EndpointsObject
	EroObject               *EroObject
	AssociationObject       *AssociationObject
	VendorInformationObject *VendorInformationObject
}

// Serialize encodes the PCInitiateMessage into bytes.
func (m *PCInitiateMessage) Serialize() ([]uint8, error) {
	byteSrpObject, err := m.SrpObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteLSPObject, err := m.LSPObject.Serialize()
	if err != nil {
		return nil, err
	}

	var byteEndpointsObject []uint8
	if m.EndpointsObject != nil {
		if byteEndpointsObject, err = m.EndpointsObject.Serialize(); err != nil {
			return nil, err
		}
	}
	var byteEroObject []uint8
	if m.EroObject != nil {
		if byteEroObject, err = m.EroObject.Serialize(); err != nil {
			return nil, err
		}
	}

	var byteAssociationObject []uint8
	if m.AssociationObject != nil {
		if byteAssociationObject, err = m.AssociationObject.Serialize(); err != nil {
			return nil, err
		}
	}
	var byteVendorInformationObject []uint8
	if m.VendorInformationObject != nil {
		if byteVendorInformationObject, err = m.VendorInformationObject.Serialize(); err != nil {
			return nil, err
		}
	}

	pcinitiateMessageLength, err := messageLength(
		byteSrpObject, byteLSPObject, byteEndpointsObject, byteEroObject, byteAssociationObject, byteVendorInformationObject,
	)
	if err != nil {
		return nil, err
	}

	pcinitiateHeader := NewCommonHeader(MessageTypeLSPInitReq, pcinitiateMessageLength)
	bytePCInitiateHeader := pcinitiateHeader.Serialize()
	bytePCInitiateMessage := AppendByteSlices(
		bytePCInitiateHeader, byteSrpObject, byteLSPObject, byteEndpointsObject, byteEroObject, byteAssociationObject, byteVendorInformationObject,
	)
	return bytePCInitiateMessage, nil
}

// NewPCInitiateMessage creates a PCInitiateMessage that instantiates srPolicy
// as a new LSP. Use NewPCInitiateDeleteMessage to remove one.
func NewPCInitiateMessage(srpID uint32, srPolicy table.SRPolicy, opt ...Opt) (*PCInitiateMessage, error) {
	opts := optParams{
		pccType: RFCCompliant,
	}

	for _, o := range opt {
		o(&opts)
	}

	m := &PCInitiateMessage{}
	var err error

	if m.SrpObject, err = NewSrpObject(srPolicy.SegmentList, srpID, false); err != nil {
		return nil, err
	}

	// PLSP-ID is 0 on instantiation; the PCC assigns it (RFC 8281 §5.3.1).
	m.LSPObject = NewLSPObject(srPolicy.Name, &srPolicy.Color, 0)
	if m.EndpointsObject, err = NewEndpointsObject(srPolicy.DstAddr, srPolicy.SrcAddr); err != nil {
		return nil, err
	}
	if m.EroObject, err = NewEroObject(srPolicy.SegmentList); err != nil {
		return nil, err
	}

	switch opts.pccType {
	case JuniperLegacy:
		if m.AssociationObject, err = NewAssociationObject(srPolicy.SrcAddr, srPolicy.DstAddr, srPolicy.Color, srPolicy.Preference, VendorSpecific(opts.pccType), OriginatorASN(opts.originatorASN)); err != nil {
			return nil, err
		}
	case CiscoLegacy:
		if m.VendorInformationObject, err = NewVendorInformationObject(CiscoLegacy, srPolicy.Color, srPolicy.Preference); err != nil {
			return nil, err
		}
	case RFCCompliant:
		if m.AssociationObject, err = NewAssociationObject(srPolicy.SrcAddr, srPolicy.DstAddr, srPolicy.Color, srPolicy.Preference, OriginatorASN(opts.originatorASN)); err != nil {
			return nil, err
		}
		if m.VendorInformationObject, err = NewVendorInformationObject(CiscoLegacy, srPolicy.Color, srPolicy.Preference); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("undefined pcc type")
	}

	return m, nil
}

// NewPCInitiateDeleteMessage creates a PCInitiateMessage that removes the LSP
// identified by srPolicy.PlspID, flagged by the SRP R flag (RFC 8281 §5.2).
// Deletion carries only the SRP and LSP objects, so srPolicy's endpoints and
// vendor-specific attributes are not encoded; its segment list is still read to
// derive the PATH-SETUP-TYPE TLV.
func NewPCInitiateDeleteMessage(srpID uint32, srPolicy table.SRPolicy) (*PCInitiateMessage, error) {
	srpObject, err := NewSrpObject(srPolicy.SegmentList, srpID, true)
	if err != nil {
		return nil, err
	}

	return &PCInitiateMessage{
		SrpObject: srpObject,
		LSPObject: NewLSPObject(srPolicy.Name, &srPolicy.Color, srPolicy.PlspID),
	}, nil
}

// PCUpdMessage is a PCEP Update message.
type PCUpdMessage struct {
	SrpObject *SrpObject
	LSPObject *LSPObject
	EroObject *EroObject
}

// Serialize encodes the PCUpdMessage into bytes.
func (m *PCUpdMessage) Serialize() ([]uint8, error) {
	byteSrpObject, err := m.SrpObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteLSPObject, err := m.LSPObject.Serialize()
	if err != nil {
		return nil, err
	}
	byteEroObject, err := m.EroObject.Serialize()
	if err != nil {
		return nil, err
	}

	pcupdMessageLength, err := messageLength(byteSrpObject, byteLSPObject, byteEroObject)
	if err != nil {
		return nil, err
	}
	pcupdHeader := NewCommonHeader(MessageTypeUpdate, pcupdMessageLength)
	bytePCUpdHeader := pcupdHeader.Serialize()
	bytePCUpdMessage := AppendByteSlices(bytePCUpdHeader, byteSrpObject, byteLSPObject, byteEroObject)
	return bytePCUpdMessage, nil
}

// NewPCUpdMessage creates a PCUpdMessage that re-signals the LSP identified by
// srPolicy.PlspID with srPolicy's segment list.
func NewPCUpdMessage(srpID uint32, srPolicy table.SRPolicy) (*PCUpdMessage, error) {
	m := &PCUpdMessage{}
	var err error

	if m.SrpObject, err = NewSrpObject(srPolicy.SegmentList, srpID, false); err != nil {
		return nil, err
	}
	// A nil color omits the COLOR TLV, leaving the value set at instantiation.
	m.LSPObject = NewLSPObject(srPolicy.Name, nil, srPolicy.PlspID)
	if m.EroObject, err = NewEroObject(srPolicy.SegmentList); err != nil {
		return nil, err
	}
	return m, nil
}
