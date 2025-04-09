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

	"github.com/nttcom/pola/internal/pkg/table"
)

const CommonHeaderLength uint16 = 4

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
	h.Version = uint8(header[0] >> 5)
	h.Flag = uint8(header[0] & 0x1f)
	h.MessageType = MessageType(header[1])
	h.MessageLength = binary.BigEndian.Uint16(header[2:4])
	return nil
}

func (h *CommonHeader) Serialize() []uint8 {
	buf := make([]uint8, 0, 4)
	verFlag := uint8(h.Version<<5 | h.Flag)
	buf = append(buf, verFlag)
	buf = append(buf, uint8(h.MessageType))
	messageLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(messageLength, h.MessageLength)
	buf = append(buf, messageLength...)
	return buf
}

func NewCommonHeader(messageType MessageType, messageLength uint16) *CommonHeader {
	h := &CommonHeader{
		Version:       uint8(1),
		Flag:          uint8(0),
		MessageType:   messageType,
		MessageLength: messageLength,
	}
	return h
}

type Message interface {
	Serialize() ([]uint8, error)
}

// Open Message
type OpenMessage struct {
	OpenObject *OpenObject
}

func (m *OpenMessage) DecodeFromBytes(messageBody []uint8) error {
	var commonObjectHeader CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
		return err
	}

	if commonObjectHeader.ObjectClass != OC_OPEN {
		return fmt.Errorf("unsupported ObjectClass: %d", commonObjectHeader.ObjectClass)
	}
	if commonObjectHeader.ObjectType != OT_OPEN_OPEN {
		return fmt.Errorf("unsupported ObjectType: %d", commonObjectHeader.ObjectType)
	}

	openObject := &OpenObject{}
	err := openObject.DecodeFromBytes(commonObjectHeader.ObjectType, messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	if err != nil {
		return err
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

func NewOpenMessage(sessionID uint8, keepalive uint8, capabilities []CapabilityInterface) (*OpenMessage, error) {
	oo, err := NewOpenObject(sessionID, keepalive, capabilities)
	if err != nil {
		return nil, err
	}
	m := &OpenMessage{
		OpenObject: oo,
	}
	return m, nil
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

func NewKeepaliveMessage() (*KeepaliveMessage, error) {
	m := &KeepaliveMessage{}
	return m, nil
}

// PCErr Message
type PCErrMessage struct {
	PcepErrorObject *PcepErrorObject
}

func (m *PCErrMessage) DecodeFromBytes(messageBody []uint8) error {
	var commonObjectHeader CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
		return err
	}
	pcepErrorObject := &PcepErrorObject{}
	if err := pcepErrorObject.DecodeFromBytes(commonObjectHeader.ObjectType, messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
		return err
	}
	m.PcepErrorObject = pcepErrorObject
	return nil
}

func (m *PCErrMessage) Serialize() []uint8 {
	pcerrMessageLength := CommonHeaderLength + m.PcepErrorObject.Len()
	pcerrHeader := NewCommonHeader(MessageTypeError, pcerrMessageLength)
	bytePCErrHeader := pcerrHeader.Serialize()
	bytePcepErrorObject := m.PcepErrorObject.Serialize()
	bytePCErrMessage := AppendByteSlices(bytePCErrHeader, bytePcepErrorObject)
	return bytePCErrMessage
}

func NewPCErrMessage(errorType uint8, errorValue uint8, tlvs []TLVInterface) (*PCErrMessage, error) {
	o, err := NewPcepErrorObject(errorType, errorValue, tlvs)
	if err != nil {
		return nil, err
	}
	m := &PCErrMessage{
		PcepErrorObject: o,
	}
	return m, nil
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
	closeObject := &CloseObject{}
	if err := closeObject.DecodeFromBytes(commonObjectHeader.ObjectType, messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
		return err
	}
	m.CloseObject = closeObject
	return nil
}

func (m *CloseMessage) Serialize() []uint8 {
	closeMessageLength := CommonHeaderLength + m.CloseObject.Len()
	closeHeader := NewCommonHeader(MessageTypeClose, closeMessageLength)
	byteCloseHeader := closeHeader.Serialize()
	byteCloseObject := m.CloseObject.Serialize()
	byteCloseMessage := AppendByteSlices(byteCloseHeader, byteCloseObject)
	return byteCloseMessage
}

func NewCloseMessage(reason uint8) (*CloseMessage, error) {
	o, err := NewCloseObject(reason)
	if err != nil {
		return nil, err
	}
	m := &CloseMessage{
		CloseObject: o,
	}
	return m, nil
}

type StateReport struct {
	SrpObject               *SrpObject
	LspObject               *LspObject
	EroObject               *EroObject
	LspaObject              *LspaObject
	MetricObjects           []*MetricObject
	BandwidthObjects        []*BandwidthObject
	AssociationObject       *AssociationObject
	VendorInformationObject *VendorInformationObject
}

func NewStateReport() (*StateReport, error) {
	sr := &StateReport{
		SrpObject:               &SrpObject{},
		LspObject:               &LspObject{},
		EroObject:               &EroObject{},
		LspaObject:              &LspaObject{},
		MetricObjects:           []*MetricObject{},
		BandwidthObjects:        []*BandwidthObject{},
		AssociationObject:       &AssociationObject{},
		VendorInformationObject: &VendorInformationObject{},
	}
	return sr, nil
}

func (r *StateReport) decodeBandwidthObject(objectType uint8, objectBody []uint8) error {
	bandwidthObject := &BandwidthObject{}
	if err := bandwidthObject.DecodeFromBytes(objectType, objectBody); err != nil {
		return err
	}
	r.BandwidthObjects = append(r.BandwidthObjects, bandwidthObject)
	return nil
}

func (r *StateReport) decodeMetricObject(objectType uint8, objectBody []uint8) error {
	metricObject := &MetricObject{}
	if err := metricObject.DecodeFromBytes(objectType, objectBody); err != nil {
		return err
	}
	r.MetricObjects = append(r.MetricObjects, metricObject)
	return nil
}

func (r *StateReport) decodeEroObject(objectType uint8, objectBody []uint8) error {
	return r.EroObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeLspaObject(objectType uint8, objectBody []uint8) error {
	return r.LspaObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeLspObject(objectType uint8, objectBody []uint8) error {
	return r.LspObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeSrpObject(objectType uint8, objectBody []uint8) error {
	srpObject := &SrpObject{}
	if err := srpObject.DecodeFromBytes(objectType, objectBody); err != nil {
		return err
	}
	r.SrpObject = srpObject
	return nil
}

func (r *StateReport) decodeAssociationObject(objectType uint8, objectBody []uint8) error {
	return r.AssociationObject.DecodeFromBytes(objectType, objectBody)
}

func (r *StateReport) decodeVendorInformationObject(objectType uint8, objectBody []uint8) error {
	return r.VendorInformationObject.DecodeFromBytes(objectType, objectBody)
}

// PCRpt Message
type PCRptMessage struct {
	StateReports []*StateReport
}

var decodeFuncs = map[uint8]func(*StateReport, uint8, []uint8) error{
	OC_BANDWIDTH:          (*StateReport).decodeBandwidthObject,
	OC_METRIC:             (*StateReport).decodeMetricObject,
	OC_ERO:                (*StateReport).decodeEroObject,
	OC_LSPA:               (*StateReport).decodeLspaObject,
	OC_LSP:                (*StateReport).decodeLspObject,
	OC_SRP:                (*StateReport).decodeSrpObject,
	OC_ASSOCIATION:        (*StateReport).decodeAssociationObject,
	OC_VENDOR_INFORMATION: (*StateReport).decodeVendorInformationObject,
}

func (m *PCRptMessage) DecodeFromBytes(messageBody []uint8) error {
	// previousOC: To determine the delimitation of StateReports from the order of object classes
	var previousOC uint8
	var sr *StateReport
	for len(messageBody) > 0 {
		var commonObjectHeader CommonObjectHeader
		if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
			return err
		}
		decodeFunc, ok := decodeFuncs[commonObjectHeader.ObjectClass]
		if !ok {
			// Skip if object class not registered in decodeFunc
			messageBody = messageBody[commonObjectHeader.ObjectLength:]
			continue
		}
		if (previousOC != OC_SRP && commonObjectHeader.ObjectClass == OC_LSP) || commonObjectHeader.ObjectClass == OC_SRP {
			// If sr is not zero value, this StateReport is already updated.
			var err error
			if sr != nil {
				m.StateReports = append(m.StateReports, sr)
			}
			sr, err = NewStateReport()
			if err != nil {
				return err
			}
		}
		if err := decodeFunc(sr, commonObjectHeader.ObjectType, messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
		previousOC = commonObjectHeader.ObjectClass
		messageBody = messageBody[commonObjectHeader.ObjectLength:]
	}
	if sr != nil {
		m.StateReports = append(m.StateReports, sr)
	}
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
	LspObject               *LspObject
	EndpointsObject         *EndpointsObject
	EroObject               *EroObject
	AssociationObject       *AssociationObject
	VendorInformationObject *VendorInformationObject
}

func (m *PCInitiateMessage) Serialize() ([]uint8, error) {
	var eroObjectLength uint16
	var err error
	if m.EroObject != nil {
		eroObjectLength, err = m.EroObject.Len()
		if err != nil {
			return nil, err
		}
	}

	var endpointsObjectLength uint16
	if m.EndpointsObject != nil {
		endpointsObjectLength, err = m.EndpointsObject.Len()
		if err != nil {
			return nil, err
		}
	}
	pcinitiateMessageLength := CommonHeaderLength +
		m.SrpObject.Len() +
		m.LspObject.Len() +
		endpointsObjectLength +
		eroObjectLength

	byteSrpObject := m.SrpObject.Serialize()
	byteLspObject := m.LspObject.Serialize()

	byteEndpointsObject := []uint8{}
	if m.EndpointsObject != nil {
		byteEndpointsObject, err = m.EndpointsObject.Serialize()
		if err != nil {
			return nil, err
		}
	}
	byteEroObject := []uint8{}
	if m.EroObject != nil {
		byteEroObject, err = m.EroObject.Serialize()
		if err != nil {
			return nil, err
		}
	}

	byteVendorInformationObject := []uint8{}
	byteAssociationObject := []uint8{}

	if m.AssociationObject != nil {
		byteAssociationObject, err = m.AssociationObject.Serialize()
		if err != nil {
			return nil, err
		}
		associationObjectLength, err := m.AssociationObject.Len()
		if err != nil {
			return nil, err
		}
		pcinitiateMessageLength += associationObjectLength
	}
	if m.VendorInformationObject != nil {
		byteVendorInformationObject = append(byteVendorInformationObject, m.VendorInformationObject.Serialize()...)
		pcinitiateMessageLength += m.VendorInformationObject.Len()
	}

	pcinitiateHeader := NewCommonHeader(MessageTypeLSPInitReq, pcinitiateMessageLength)
	bytePCInitiateHeader := pcinitiateHeader.Serialize()
	bytePCInitiateMessage := AppendByteSlices(
		bytePCInitiateHeader, byteSrpObject, byteLspObject, byteEndpointsObject, byteEroObject, byteAssociationObject, byteVendorInformationObject,
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
		if m.LspObject, err = NewLspObject(lspName, &color, plspID); err != nil {
			return nil, err
		}
		return m, nil
	} else {
		if m.LspObject, err = NewLspObject(lspName, &color, 0); err != nil {
			return nil, err
		}
	}

	if m.EndpointsObject, err = NewEndpointsObject(dstAddr, srcAddr); err != nil {
		return nil, err
	}
	if m.EroObject, err = NewEroObject(segmentList); err != nil {
		return m, err
	}

	switch opts.pccType {
	case JuniperLegacy:
		if m.AssociationObject, err = NewAssociationObject(srcAddr, dstAddr, color, preference, VendorSpecific(opts.pccType)); err != nil {
			return nil, err
		}
	case CiscoLegacy:
		if m.VendorInformationObject, err = NewVendorInformationObject(CiscoLegacy, color, preference); err != nil {
			return nil, err
		}
	case RFCCompliant:
		if m.AssociationObject, err = NewAssociationObject(srcAddr, dstAddr, color, preference); err != nil {
			return nil, err
		}
		// FRRouting is considered RFC compliant
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
	LspObject *LspObject
	EroObject *EroObject
}

func (m *PCUpdMessage) Serialize() ([]uint8, error) {
	byteSrpObject := m.SrpObject.Serialize()
	byteLspObject := m.LspObject.Serialize()
	byteEroObject, err := m.EroObject.Serialize()
	if err != nil {
		return nil, err
	}

	eroObjectLength, err := m.EroObject.Len()
	if err != nil {
		return nil, err
	}
	pcupdMessageLength := CommonHeaderLength + m.SrpObject.Len() + m.LspObject.Len() + eroObjectLength
	pcupdHeader := NewCommonHeader(MessageTypeUpdate, pcupdMessageLength)
	bytePCUpdHeader := pcupdHeader.Serialize()
	bytePCUpdMessage := AppendByteSlices(bytePCUpdHeader, byteSrpObject, byteLspObject, byteEroObject)
	return bytePCUpdMessage, err
}

func NewPCUpdMessage(srpID uint32, lspName string, plspID uint32, segmentList []table.Segment) (*PCUpdMessage, error) {
	m := &PCUpdMessage{}
	var err error

	if m.SrpObject, err = NewSrpObject(segmentList, srpID, false); err != nil {
		return nil, err
	}
	if m.LspObject, err = NewLspObject(lspName, nil, plspID); err != nil {
		return nil, err
	}
	if m.EroObject, err = NewEroObject(segmentList); err != nil {
		return nil, err
	}
	return m, nil
}
