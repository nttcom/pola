// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import "fmt"

// Open Message
type OpenMessage struct {
	OpenObject OpenObject
}

func NewOpenMessage(sessionID uint8, keepalive uint8) OpenMessage {
	var openMessage OpenMessage
	openMessage.OpenObject = NewOpenObject(sessionID, keepalive)
	return openMessage
}

func (m *OpenMessage) DecodeFromBytes(byteOpenObj []uint8) error {
	var commonObjectHeader CommonObjectHeader
	commonObjectHeader.DecodeFromBytes(byteOpenObj)

	if commonObjectHeader.ObjectClass != OC_OPEN {
		return fmt.Errorf("Unsupported ObjectClass: %d", commonObjectHeader.ObjectClass)
	}
	if commonObjectHeader.ObjectType != 1 {
		return fmt.Errorf("Unsupported ObjectType: %d", commonObjectHeader.ObjectType)
	}

	var openObject OpenObject
	err := openObject.DecodeFromBytes(byteOpenObj[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
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

// Keepalive Message
type KeepaliveMessage struct {
}

func NewKeepaliveMessage() KeepaliveMessage {
	var keepaliveMessage KeepaliveMessage
	return keepaliveMessage
}

func (m *KeepaliveMessage) Serialize() []uint8 {
	keepaliveMessageLength := COMMON_HEADER_LENGTH
	keepaliveHeader := NewCommonHeader(MT_KEEPALIVE, keepaliveMessageLength)
	byteKeepaliveHeader := keepaliveHeader.Serialize()
	byteKeepaliveMessage := byteKeepaliveHeader
	return byteKeepaliveMessage
}

// PCRpt Message
type PCRptMessage struct {
	SrpObject               *SrpObject
	LspObject               *LspObject
	EroObject               *EroObject
	LspaObject              *LspaObject
	MetricObjects           []*MetricObject
	BandwidthObjects        []*BandwidthObject
	VendorInformationObject *VendorInformationObject
}

func NewPCRptMessage() *PCRptMessage {
	pcrptMessage := &PCRptMessage{
		SrpObject:               &SrpObject{},
		LspObject:               &LspObject{},
		EroObject:               &EroObject{},
		LspaObject:              &LspaObject{},
		MetricObjects:           []*MetricObject{},
		BandwidthObjects:        []*BandwidthObject{},
		VendorInformationObject: &VendorInformationObject{},
	}
	return pcrptMessage
}

func (m *PCRptMessage) DecodeFromBytes(bytePcrptObject []uint8) error {
	// TODO: Supports multiple <state-report>'s stacked PCRpt Message.
	// https://datatracker.ietf.org/doc/html/rfc8231#section-6.1
	// Currently, when more than 2 <state-report> come in, One object has multiple object information.
	var commonObjectHeader CommonObjectHeader
	commonObjectHeader.DecodeFromBytes(bytePcrptObject)

	switch commonObjectHeader.ObjectClass {
	case OC_BANDWIDTH:
		bandwidthObject := &BandwidthObject{}
		bandwidthObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		m.BandwidthObjects = append(m.BandwidthObjects, bandwidthObject)
	case OC_METRIC:
		metricObject := &MetricObject{}
		metricObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		m.MetricObjects = append(m.MetricObjects, metricObject)
	case OC_ERO:
		err := m.EroObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		if err != nil {
			return err
		}
	case OC_LSPA:
		m.LspaObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	case OC_LSP:
		err := m.LspObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
		if err != nil {
			return err
		}
	case OC_SRP:
		m.SrpObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	case OC_VENDOR_INFORMATION:
		m.VendorInformationObject.DecodeFromBytes(bytePcrptObject[COMMON_OBJECT_HEADER_LENGTH:commonObjectHeader.ObjectLength])
	default:
	}

	if int(commonObjectHeader.ObjectLength) < len(bytePcrptObject) {
		err := m.DecodeFromBytes(bytePcrptObject[commonObjectHeader.ObjectLength:])
		if err != nil {
			return err
		}
	}
	return nil
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

func NewPCInitiateMessage(srpId uint32, lspName string, labels []Label, color uint32, preference uint32, srcIPv4 []uint8, dstIPv4 []uint8, opt ...Opt) (PCInitiateMessage, error) {
	opts := optParams{
		pccType: RFC_COMPLIANT,
	}

	for _, o := range opt {
		o(&opts)
	}

	var pcInitiateMessage PCInitiateMessage
	pcInitiateMessage.SrpObject = NewSrpObject(srpId, false)
	pcInitiateMessage.LspObject = NewLspObject(lspName, 0)                      // PLSP-ID = 0
	pcInitiateMessage.EndpointsObject = NewEndpointsObject(1, dstIPv4, srcIPv4) // objectType = 1 (IPv4)
	var err error
	pcInitiateMessage.EroObject, err = NewEroObject(labels)
	if err != nil {
		return pcInitiateMessage, err
	}
	if opts.pccType == JUNIPER_LEGACY {
		pcInitiateMessage.AssociationObject = NewAssociationObject(srcIPv4, dstIPv4, color, preference, VendorSpecific(opts.pccType))
	} else if opts.pccType == CISCO_LEGACY {
		pcInitiateMessage.VendorInformationObject = NewVendorInformationObject(CISCO_LEGACY, color, preference)
	} else if opts.pccType == RFC_COMPLIANT {
		pcInitiateMessage.AssociationObject = NewAssociationObject(srcIPv4, dstIPv4, color, preference)
		// FRRouting is treated as an RFC compliant
		pcInitiateMessage.VendorInformationObject = NewVendorInformationObject(CISCO_LEGACY, color, preference)
	}

	return pcInitiateMessage, nil
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

// PCUpdate Message
type PCUpdMessage struct {
	SrpObject *SrpObject
	LspObject *LspObject
	EroObject *EroObject
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
