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

// Common header of PCEP Message
type CommonHeader struct { // RFC5440 6.1
	Version       uint8 // Current version is 1
	Flag          uint8
	MessageType   uint8
	MessageLength uint16
}

func (h *CommonHeader) DecodeFromBytes(header []uint8) error {
	h.Version = uint8(header[0] >> 5)
	h.Flag = uint8(header[0] & 0x1f)
	h.MessageType = uint8(header[1])
	h.MessageLength = binary.BigEndian.Uint16(header[2:4])
	return nil
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

func NewCommonHeader(messageType uint8, messageLength uint16) *CommonHeader {
	h := &CommonHeader{
		Version:       uint8(1),
		Flag:          uint8(0),
		MessageType:   messageType,
		MessageLength: messageLength,
	}
	return h
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
	err := openObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	if err != nil {
		return err
	}
	m.OpenObject = openObject

	return nil
}

func (m *OpenMessage) Serialize() []uint8 {
	byteOpenObject := m.OpenObject.Serialize()
	openMessageLength := COMMON_HEADER_LENGTH + m.OpenObject.getByteLength()
	openHeader := NewCommonHeader(MT_OPEN, openMessageLength)
	byteOpenHeader := openHeader.Serialize()
	byteOpenMessage := AppendByteSlices(byteOpenHeader, byteOpenObject)
	return byteOpenMessage
}

func NewOpenMessage(sessionID uint8, keepalive uint8) (*OpenMessage, error) {
	oo, err := NewOpenObject(sessionID, keepalive)
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

func (m *KeepaliveMessage) Serialize() []uint8 {
	keepaliveMessageLength := COMMON_HEADER_LENGTH
	keepaliveHeader := NewCommonHeader(MT_KEEPALIVE, keepaliveMessageLength)
	byteKeepaliveHeader := keepaliveHeader.Serialize()
	byteKeepaliveMessage := byteKeepaliveHeader
	return byteKeepaliveMessage
}

func NewKeepaliveMessage() (*KeepaliveMessage, error) {
	m := &KeepaliveMessage{}
	return m, nil
}

// PCRpt Message
type PCRptMessage struct {
	SrpObject               *SrpObject
	LspObject               *LspObject
	EroObject               *EroObject
	LspaObject              *LspaObject
	MetricObjects           []*MetricObject
	BandwidthObjects        []*BandwidthObject
	AssociationObject       *AssociationObject
	VendorInformationObject *VendorInformationObject
}

func (m *PCRptMessage) DecodeFromBytes(messageBody []uint8) error {
	// TODO: Supports multiple <state-report>'s stacked PCRpt Message.
	// https://datatracker.ietf.org/doc/html/rfc8231#section-6.1
	// Currently, when more than 2 <state-report> come in, One object has multiple object information.
	var commonObjectHeader CommonObjectHeader
	if err := commonObjectHeader.DecodeFromBytes(messageBody); err != nil {
		return err
	}

	switch commonObjectHeader.ObjectClass {
	case OC_BANDWIDTH:
		bandwidthObject := &BandwidthObject{}
		if err := bandwidthObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
		m.BandwidthObjects = append(m.BandwidthObjects, bandwidthObject)
	case OC_METRIC:
		metricObject := &MetricObject{}
		if err := metricObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
		m.MetricObjects = append(m.MetricObjects, metricObject)
	case OC_ERO:
		if err := m.EroObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
	case OC_LSPA:
		if err := m.LspaObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
	case OC_LSP:
		if err := m.LspObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
	case OC_SRP:
		if err := m.SrpObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
	case OC_ASSOCIATION:
		if err := m.AssociationObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
	case OC_VENDOR_INFORMATION:
		if err := m.VendorInformationObject.DecodeFromBytes(messageBody[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength]); err != nil {
			return err
		}
	default:
	}

	if int(commonObjectHeader.ObjectLength) < len(messageBody) {
		if err := m.DecodeFromBytes(messageBody[commonObjectHeader.ObjectLength:]); err != nil {
			return err
		}
	}
	return nil
}

func NewPCRptMessage() *PCRptMessage {
	m := &PCRptMessage{
		SrpObject:               &SrpObject{},
		LspObject:               &LspObject{},
		EroObject:               &EroObject{},
		LspaObject:              &LspaObject{},
		MetricObjects:           []*MetricObject{},
		BandwidthObjects:        []*BandwidthObject{},
		AssociationObject:       &AssociationObject{},
		VendorInformationObject: &VendorInformationObject{},
	}
	return m
}

func (m *PCRptMessage) ToSRPolicy(pcc PccType) table.SRPolicy {
	srPolicy := table.SRPolicy{
		PlspId:      m.LspObject.PlspId,
		Name:        m.LspObject.Name,
		SegmentList: []table.Segment{},
		SrcAddr:     m.LspObject.SrcAddr,
		DstAddr:     m.LspObject.DstAddr,
	}
	if pcc == CISCO_LEGACY {
		srPolicy.Color = m.VendorInformationObject.Color()
		srPolicy.Preference = m.VendorInformationObject.Preference()
	} else {
		srPolicy.Color = m.AssociationObject.Color()
		srPolicy.Preference = m.AssociationObject.Preference()
	}

	srPolicy.SegmentList = m.EroObject.ToSegmentList()

	return srPolicy
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
	eroObjectLength, err := m.EroObject.getByteLength()
	if err != nil {
		return nil, err
	}
	pcinitiateMessageLength := COMMON_HEADER_LENGTH +
		m.SrpObject.getByteLength() +
		m.LspObject.getByteLength() +
		m.EndpointsObject.getByteLength() +
		eroObjectLength

	byteSrpObject := m.SrpObject.Serialize()
	byteLspObject := m.LspObject.Serialize()
	byteEndpointsObject := m.EndpointsObject.Serialize()
	byteEroObject, err := m.EroObject.Serialize()
	if err != nil {
		return nil, err
	}

	byteVendorInformationObject := []uint8{}
	byteAssociationObject := []uint8{}

	if m.AssociationObject != nil {
		byteAssociationObject = append(byteAssociationObject, m.AssociationObject.Serialize()...)
		pcinitiateMessageLength += m.AssociationObject.getByteLength()
	}
	if m.VendorInformationObject != nil {
		byteVendorInformationObject = append(byteVendorInformationObject, m.VendorInformationObject.Serialize()...)
		pcinitiateMessageLength += m.VendorInformationObject.getByteLength()
	}

	pcinitiateHeader := NewCommonHeader(MT_LSPINITREQ, pcinitiateMessageLength)
	bytePCInitiateHeader := pcinitiateHeader.Serialize()
	bytePCInitiateMessage := AppendByteSlices(
		bytePCInitiateHeader, byteSrpObject, byteLspObject, byteEndpointsObject, byteEroObject, byteAssociationObject, byteVendorInformationObject,
	)
	return bytePCInitiateMessage, nil
}

func NewPCInitiateMessage(srpId uint32, lspName string, segmentList []table.Segment, color uint32, preference uint32, srcAddr netip.Addr, dstAddr netip.Addr, opt ...Opt) (*PCInitiateMessage, error) {
	opts := optParams{
		pccType: RFC_COMPLIANT,
	}

	for _, o := range opt {
		o(&opts)
	}

	m := &PCInitiateMessage{}
	var err error
	if m.SrpObject, err = NewSrpObject(srpId, false); err != nil {
		return nil, err
	}
	if m.LspObject, err = NewLspObject(lspName, 0); err != nil { // PLSP-ID = 0
		return nil, err
	}
	if m.EndpointsObject, err = NewEndpointsObject(OT_EP_IPV4, dstAddr, srcAddr); err != nil {
		return nil, err
	}
	if m.EroObject, err = NewEroObject(segmentList); err != nil {
		return m, err
	}
	if opts.pccType == JUNIPER_LEGACY {
		if m.AssociationObject, err = NewAssociationObject(srcAddr, dstAddr, color, preference, VendorSpecific(opts.pccType)); err != nil {
			return nil, err
		}
	} else if opts.pccType == CISCO_LEGACY {
		if m.VendorInformationObject, err = NewVendorInformationObject(CISCO_LEGACY, color, preference); err != nil {
			return nil, err
		}
	} else if opts.pccType == RFC_COMPLIANT {
		if m.AssociationObject, err = NewAssociationObject(srcAddr, dstAddr, color, preference); err != nil {
			return nil, err
		}
		// FRRouting is treated as an RFC compliant
		if m.VendorInformationObject, err = NewVendorInformationObject(CISCO_LEGACY, color, preference); err != nil {
			return nil, err
		}
	} else {
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

	eroObjectLength, err := m.EroObject.getByteLength()
	if err != nil {
		return nil, err
	}
	pcupdMessageLength := COMMON_HEADER_LENGTH + m.SrpObject.getByteLength() + m.LspObject.getByteLength() + eroObjectLength
	pcupdHeader := NewCommonHeader(MT_UPDATE, pcupdMessageLength)
	bytePCUpdHeader := pcupdHeader.Serialize()
	bytePCUpdMessage := AppendByteSlices(bytePCUpdHeader, byteSrpObject, byteLspObject, byteEroObject)
	return bytePCUpdMessage, err
}

func NewPCUpdMessage(srpId uint32, lspName string, plspId uint32, segmentList []table.Segment) (*PCUpdMessage, error) {

	m := &PCUpdMessage{}
	var err error

	if m.SrpObject, err = NewSrpObject(srpId, false); err != nil {
		return nil, err
	}
	if m.LspObject, err = NewLspObject(lspName, plspId); err != nil {
		return nil, err
	}
	if m.EroObject, err = NewEroObject(segmentList); err != nil {
		return nil, err
	}
	return m, nil
}
