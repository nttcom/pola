// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/nttcom/pola/pkg/table"
)

const CommonHeaderLength uint16 = 4

const PCEPVersion uint8 = 1

// PCEP Message-Type (1 byte)
type MessageType uint8

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

func (t MessageType) StringWithReference() string {
	if desc, ok := messageTypeDescriptions[t]; ok {
		return fmt.Sprintf("%s (0x%02x) [%s]", desc.Description, uint8(t), desc.Reference)
	}
	return fmt.Sprintf("Unknown MessageType (0x%02x)", uint8(t))
}

// Common header of PCEP Message
type CommonHeader struct { // RFC5440 6.1
	Version       uint8 // Current version is 1
	Flag          uint8
	MessageType   MessageType
	MessageLength uint16
}

func (h *CommonHeader) DecodeFromBytes(header []uint8) error {
	if len(header) < int(CommonHeaderLength) {
		return fmt.Errorf("PCEP common header too short: got %d bytes, need %d", len(header), CommonHeaderLength)
	}
	h.Version = uint8(header[0] >> 5)
	h.Flag = uint8(header[0] & 0x1f)
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

func (h *CommonHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	verFlag := uint8(h.Version<<5 | h.Flag)
	buf = append(buf, verFlag)
	buf = append(buf, uint8(h.MessageType))
	buf = append(buf, Uint16ToByteSlice(h.MessageLength)...)
	return buf
}

func NewCommonHeader(messageType MessageType, messageLength uint16) *CommonHeader {
	h := &CommonHeader{
		Version:       PCEPVersion,
		Flag:          uint8(0),
		MessageType:   messageType,
		MessageLength: messageLength,
	}
	return h
}

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

// Open Message
type OpenMessage struct {
	OpenObject *OpenObject
}

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

func (m *OpenMessage) Serialize() ([]uint8, error) {
	byteOpenObject := m.OpenObject.Serialize()
	openMessageLength := CommonHeaderLength + m.OpenObject.Len()
	openHeader := NewCommonHeader(MessageTypeOpen, openMessageLength)
	byteOpenHeader := openHeader.Serialize()
	byteOpenMessage := AppendByteSlices(byteOpenHeader, byteOpenObject)
	return byteOpenMessage, nil
}

func NewOpenMessage(sessionID uint8, keepalive uint8, capabilities []CapabilityInterface) *OpenMessage {
	return &OpenMessage{
		OpenObject: NewOpenObject(sessionID, keepalive, capabilities),
	}
}

// Keepalive Message
type KeepaliveMessage struct {
}

func (m *KeepaliveMessage) Serialize() ([]uint8, error) {
	keepaliveMessageLength := CommonHeaderLength
	keepaliveHeader := NewCommonHeader(MessageTypeKeepalive, keepaliveMessageLength)
	byteKeepaliveHeader := keepaliveHeader.Serialize()
	byteKeepaliveMessage := byteKeepaliveHeader
	return byteKeepaliveMessage, nil
}

func NewKeepaliveMessage() *KeepaliveMessage {
	return &KeepaliveMessage{}
}

// PCErr Message
type PCErrMessage struct {
	Errors []*PCEPErrorObject
	SRPs   []*SrpObject
}

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
			errObj := &PCEPErrorObject{}
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
		}
		offset += int(commonObjectHeader.ObjectLength)
	}
	// RFC 5440 §6.7 requires at least one PCEP-ERROR object per PCErr message.
	if len(m.Errors) == 0 {
		return errors.New("PCErr: message carries no PCEP-ERROR object")
	}
	return nil
}

func (m *PCErrMessage) Serialize() ([]uint8, error) {
	length := CommonHeaderLength
	for _, srp := range m.SRPs {
		length += srp.Len()
	}
	for _, errObj := range m.Errors {
		length += errObj.Len()
	}
	buf := NewCommonHeader(MessageTypeError, length).Serialize()
	for _, srp := range m.SRPs {
		buf = AppendByteSlices(buf, srp.Serialize())
	}
	for _, errObj := range m.Errors {
		buf = AppendByteSlices(buf, errObj.Serialize())
	}
	return buf, nil
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

func NewPCErrMessage(errorType uint8, errorValue uint8, tlvs []TLVInterface) *PCErrMessage {
	return &PCErrMessage{
		Errors: []*PCEPErrorObject{NewPCEPErrorObject(errorType, errorValue, tlvs)},
	}
}

// Close Message
type CloseMessage struct {
	CloseObject *CloseObject
}

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

func (m *CloseMessage) Serialize() ([]uint8, error) {
	closeMessageLength := CommonHeaderLength + m.CloseObject.Len()
	closeHeader := NewCommonHeader(MessageTypeClose, closeMessageLength)
	byteCloseHeader := closeHeader.Serialize()
	byteCloseObject := m.CloseObject.Serialize()
	byteCloseMessage := AppendByteSlices(byteCloseHeader, byteCloseObject)
	return byteCloseMessage, nil
}

func NewCloseMessage(reason CloseReason) *CloseMessage {
	return &CloseMessage{
		CloseObject: NewCloseObject(reason),
	}
}

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

// PCRpt Message
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
					return fmt.Errorf("PCRpt: state report missing LSP object")
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
		return fmt.Errorf("PCRpt: no state report")
	}
	if !lspDecoded {
		return fmt.Errorf("PCRpt: state report missing LSP object")
	}
	m.StateReports = append(m.StateReports, sr)

	return nil
}

func NewPCRptMessage() *PCRptMessage {
	return &PCRptMessage{
		StateReports: []*StateReport{},
	}
}

// PCInitiate Message
type PCInitiateMessage struct {
	SrpObject               *SrpObject
	LSPObject               *LSPObject
	EndpointsObject         *EndpointsObject
	EroObject               *EroObject
	AssociationObject       *AssociationObject
	VendorInformationObject *VendorInformationObject
}

func (m *PCInitiateMessage) Serialize() ([]uint8, error) {
	var err error

	byteSrpObject := m.SrpObject.Serialize()
	byteLSPObject := m.LSPObject.Serialize()

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
		byteVendorInformationObject = m.VendorInformationObject.Serialize()
	}

	// Use the serialized lengths to keep the message length consistent with
	// the bytes appended below.
	pcinitiateMessageLength := CommonHeaderLength +
		m.SrpObject.Len() +
		m.LSPObject.Len() +
		uint16(len(byteEndpointsObject)) +
		uint16(len(byteEroObject)) +
		uint16(len(byteAssociationObject)) +
		uint16(len(byteVendorInformationObject))

	pcinitiateHeader := NewCommonHeader(MessageTypeLSPInitReq, pcinitiateMessageLength)
	bytePCInitiateHeader := pcinitiateHeader.Serialize()
	bytePCInitiateMessage := AppendByteSlices(
		bytePCInitiateHeader, byteSrpObject, byteLSPObject, byteEndpointsObject, byteEroObject, byteAssociationObject, byteVendorInformationObject,
	)
	return bytePCInitiateMessage, nil
}

func NewPCInitiateMessage(srpID uint32, lspName string, lspDelete bool, plspID uint32, segmentList []table.Segment, color uint32, preference uint32, srcAddr netip.Addr, dstAddr netip.Addr, opt ...Opt) (*PCInitiateMessage, error) {
	opts := optParams{
		pccType: RFCCompliant,
	}

	for _, o := range opt {
		o(&opts)
	}

	m := &PCInitiateMessage{}
	var err error

	if m.SrpObject, err = NewSrpObject(segmentList, srpID, lspDelete); err != nil {
		return nil, err
	}

	if lspDelete {
		m.LSPObject = NewLSPObject(lspName, &color, plspID)
		return m, nil
	}

	m.LSPObject = NewLSPObject(lspName, &color, 0)
	if m.EndpointsObject, err = NewEndpointsObject(dstAddr, srcAddr); err != nil {
		return nil, err
	}
	if m.EroObject, err = NewEroObject(segmentList); err != nil {
		return m, err
	}

	switch opts.pccType {
	case JuniperLegacy:
		if m.AssociationObject, err = NewAssociationObject(srcAddr, dstAddr, color, preference, VendorSpecific(opts.pccType), OriginatorASN(opts.originatorASN)); err != nil {
			return nil, err
		}
	case CiscoLegacy:
		if m.VendorInformationObject, err = NewVendorInformationObject(CiscoLegacy, color, preference); err != nil {
			return nil, err
		}
	case RFCCompliant:
		if m.AssociationObject, err = NewAssociationObject(srcAddr, dstAddr, color, preference, OriginatorASN(opts.originatorASN)); err != nil {
			return nil, err
		}
		if m.VendorInformationObject, err = NewVendorInformationObject(CiscoLegacy, color, preference); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("undefined pcc type")
	}

	return m, nil
}

// PCUpdate Message
type PCUpdMessage struct {
	SrpObject *SrpObject
	LSPObject *LSPObject
	EroObject *EroObject
}

func (m *PCUpdMessage) Serialize() ([]uint8, error) {
	byteSrpObject := m.SrpObject.Serialize()
	byteLSPObject := m.LSPObject.Serialize()
	byteEroObject, err := m.EroObject.Serialize()
	if err != nil {
		return nil, err
	}

	// Use the serialized lengths to keep the message length consistent with
	// the bytes appended below.
	pcupdMessageLength := CommonHeaderLength + m.SrpObject.Len() + m.LSPObject.Len() + uint16(len(byteEroObject))
	pcupdHeader := NewCommonHeader(MessageTypeUpdate, pcupdMessageLength)
	bytePCUpdHeader := pcupdHeader.Serialize()
	bytePCUpdMessage := AppendByteSlices(bytePCUpdHeader, byteSrpObject, byteLSPObject, byteEroObject)
	return bytePCUpdMessage, nil
}

func NewPCUpdMessage(srpID uint32, lspName string, plspID uint32, segmentList []table.Segment) (*PCUpdMessage, error) {
	m := &PCUpdMessage{}
	var err error

	if m.SrpObject, err = NewSrpObject(segmentList, srpID, false); err != nil {
		return nil, err
	}
	m.LSPObject = NewLSPObject(lspName, nil, plspID)
	if m.EroObject, err = NewEroObject(segmentList); err != nil {
		return nil, err
	}
	return m, nil
}
