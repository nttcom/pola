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
	"strings"

	"go.uber.org/zap/zapcore"
)

const ( // PCEP TLV
	TLV_RESERVED                              uint16 = 0x00 // RFC5440
	TLV_NO_PATH_VECTOR                        uint16 = 0x01 // RFC5440
	TLV_OVERLOAD_DURATION                     uint16 = 0x02 // RFC5440
	TLV_REQ_MISSING                           uint16 = 0x03 // RFC5440
	TLV_OF_LIST                               uint16 = 0x04 // RFC5541
	TLV_ORDER                                 uint16 = 0x05 // RFC5557
	TLV_P2MP_CAPABLE                          uint16 = 0x06 // RFC8306
	TLV_VENDOR_INFORMATION                    uint16 = 0x07 // RFC7470
	TLV_WAVELENGTH_SELECTION                  uint16 = 0x08 // RFC8780
	TLV_WAVELENGTH_RESTRICTION                uint16 = 0x09 // RFC8780
	TLV_WAVELENGTH_ALLOCATION                 uint16 = 0x0a // RFC8780
	TLV_OPTICAL_INTERFACE_CLASS_LIST          uint16 = 0x0b // RFC8780
	TLV_CLIENT_SIGNAL_INFORMATION             uint16 = 0x0c // RFC8780
	TLV_H_PCE_CAPABILITY                      uint16 = 0x0d // RFC8685
	TLV_DOMAIN_ID                             uint16 = 0x0e // RFC8685
	TLV_H_PCE_FLAG                            uint16 = 0x0f // RFC8685
	TLV_STATEFUL_PCE_CAPABILITY               uint16 = 0x10 // RFC8231
	TLV_SYMBOLIC_PATH_NAME                    uint16 = 0x11 // RFC8231
	TLV_IPV4_LSP_IDENTIFIERS                  uint16 = 0x12 // RFC8231
	TLV_IPV6_LSP_IDENTIFIERS                  uint16 = 0x13 // RFC8231
	TLV_LSP_ERROR_CODE                        uint16 = 0x14 // RFC8231
	TLV_RSVP_ERROR_SPEC                       uint16 = 0x15 // RFC8231
	TLV_LSP_DB_VERSION                        uint16 = 0x17 // RFC8232
	TLV_SPEAKER_ENTITY_ID                     uint16 = 0x18 // RFC8232
	TLV_SR_PCE_CAPABILITY                     uint16 = 0x1a // RFC8664
	TLV_PATH_SETUP_TYPE                       uint16 = 0x1c // RFC8408
	TLV_OPERATOR_CONFIGURED_ASSOCIATION_RANGE uint16 = 0x1d // RFC8697
	TLV_GLOBAL_ASSOCIATION_SOURCE             uint16 = 0x1e // RFC8697
	TLV_EXTENDED_ASSOCIATION_ID               uint16 = 0x1f // RFC8697
	TLV_P2MP_IPV4_LSP_IDENTIFIERS             uint16 = 0x20 // RFC8623
	TLV_P2MP_IPV6_LSP_IDENTIFIERS             uint16 = 0x21 // RFC8623
	TLV_PATH_SETUP_TYPE_CAPABILITY            uint16 = 0x22 // RFC8409
	TLV_ASSOC_TYPE_LIST                       uint16 = 0x23 // RFC8697
	TLV_AUTO_BANDWIDTH_CAPABILITY             uint16 = 0x24 // RFC8733
	TLV_AUTO_BANDWIDTH_ATTRIBUTES             uint16 = 0x25 // RFC8733
	TLV_PATH_PROTECTION_ASSOCIATION_GROUP_TLV uint16 = 0x26 // RFC8745
	TLV_IPV4_ADDRESS                          uint16 = 0x27 // RFC8779
	TLV_IPV6_ADDRESS                          uint16 = 0x28 // RFC8779
	TLV_UNNUMBERED_ENDPOINT                   uint16 = 0x29 // RFC8779
	TLV_LABEL_REQUEST                         uint16 = 0x2a // RFC8779
	TLV_LABEL_SET                             uint16 = 0x2b // RFC8779
	TLV_PROTECTION_ATTRIBUTE                  uint16 = 0x2c // RFC8779
	TLV_GMPLS_CAPABILITY                      uint16 = 0x2d // RFC8779
	TLV_DISJOINTNESS_CONFIGURATION            uint16 = 0x2e // RFC8800
	TLV_DISJOINTNESS_STATUS                   uint16 = 0x2f // RFC8800
	TLV_POLICY_PARAMETERSjTLV                 uint16 = 0x30 // RFC9005
	TLV_SCHED_LSP_ATTRIBUTE                   uint16 = 0x31 // RFC8934
	TLV_SCHED_PD_LSP_ATTRIBUTE                uint16 = 0x32 // RFC8934
	TLV_PCE_FLOWSPEC_CAPABILITY               uint16 = 0x33 // ietf-pce-pcep-flowspec-12
	TLV_FLOW_FILTER                           uint16 = 0x34 // ietf-pce-pcep-flowspec-12
	TLV_L2_FLOW_FILTER                        uint16 = 0x35 // ietf-pce-pcep-flowspec-12
	TLV_BIDIRECTIONAL_LSP_ASSOCIATION_GROUP   uint16 = 0x36 // RFC9059
	TLV_SRPOLICY_POL_NAME                     uint16 = 0x38 // ietf-pce-segment-routing-policy-cp-07
	TLV_SRPOLICY_CPATH_ID                     uint16 = 0x39 // ietf-pce-segment-routing-policy-cp-07
	TLV_SRPOLICY_CPATH_NAME                   uint16 = 0x3a // ietf-pce-segment-routing-policy-cp-07
	TLV_SRPOLICY_CPATH_PREFERENCE             uint16 = 0x3b // ietf-pce-segment-routing-policy-cp-07
)

const (
	TLV_STATEFUL_PCE_CAPABILITY_LENGTH   uint16 = 4
	TLV_SR_PCE_CAPABILITY_LENGTH         uint16 = 4
	TLV_PATH_SETUP_TYPE_LENGTH           uint16 = 4
	TLV_EXTENDED_ASSOCIATION_ID_LENGTH   uint16 = 8
	TLV_IPV4_LSP_IDENTIFIERS_LENGTH      uint16 = 16
	TLV_IPV6_LSP_IDENTIFIERS_LENGTH      uint16 = 52
	TLV_SRPOLICY_CPATH_ID_LENGTH         uint16 = 28
	TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH uint16 = 4
)

const TL_LENGTH = 4

type TlvInterface interface {
	DecodeFromBytes(data []uint8) error
	Serialize() []uint8
	MarshalLogObject(enc zapcore.ObjectEncoder) error
	Type() uint16
	Len() uint16
	GetByteLength() uint16
}

type StatefulPceCapability struct {
	LspUpdateCapability        bool
	IncludeDBVersion           bool
	LspInstantiationCapability bool
	TriggeredResync            bool
	DeltaLspSyncCapability     bool
	TriggeredInitialSync       bool
}

func (tlv *StatefulPceCapability) DecodeFromBytes(data []uint8) error {
	tlv.LspUpdateCapability = (data[7] & 0x01) != 0
	tlv.IncludeDBVersion = (data[7] & 0x02) != 0
	tlv.LspInstantiationCapability = (data[7] & 0x04) != 0
	tlv.TriggeredResync = (data[7] & 0x08) != 0
	tlv.DeltaLspSyncCapability = (data[7] & 0x10) != 0
	tlv.TriggeredInitialSync = (data[7] & 0x20) != 0

	return nil
}

func (tlv *StatefulPceCapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, tlv.Len())
	buf = append(buf, length...)

	val := make([]uint8, tlv.Len())
	if tlv.LspUpdateCapability {
		val[3] = val[3] | 0x01
	}
	if tlv.IncludeDBVersion {
		val[3] = val[3] | 0x02
	}
	if tlv.LspInstantiationCapability {
		val[3] = val[3] | 0x04
	}
	if tlv.TriggeredResync {
		val[3] = val[3] | 0x08
	}
	if tlv.DeltaLspSyncCapability {
		val[3] = val[3] | 0x10
	}
	if tlv.TriggeredInitialSync {
		val[3] = val[3] | 0x20
	}
	buf = append(buf, val...)

	return buf
}

func (tlv *StatefulPceCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *StatefulPceCapability) Type() uint16 {
	return TLV_STATEFUL_PCE_CAPABILITY
}

func (tlv *StatefulPceCapability) Len() uint16 {
	return TLV_STATEFUL_PCE_CAPABILITY_LENGTH
}

func (tlv *StatefulPceCapability) GetByteLength() uint16 {
	return TL_LENGTH + TLV_STATEFUL_PCE_CAPABILITY_LENGTH
}

type SymbolicPathName struct {
	Name string
}

func (tlv *SymbolicPathName) DecodeFromBytes(data []uint8) error {
	length := binary.BigEndian.Uint16(data[2:4])
	tlv.Name = string(data[4 : 4+length])
	return nil
}

func (tlv *SymbolicPathName) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, tlv.Len())
	buf = append(buf, length...)

	buf = append(buf, []uint8(tlv.Name)...)

	if tlv.Len()%4 != 0 {
		pad := make([]uint8, 4-tlv.Len()%4)
		buf = append(buf, pad...)
	}
	return buf
}

func (tlv *SymbolicPathName) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SymbolicPathName) Type() uint16 {
	return TLV_SYMBOLIC_PATH_NAME
}

func (tlv *SymbolicPathName) Len() uint16 {
	return uint16(len(tlv.Name))
}

func (tlv *SymbolicPathName) GetByteLength() uint16 {
	if tlv.Len()%4 == 0 {
		return TL_LENGTH + tlv.Len()
	} else {
		return TL_LENGTH + tlv.Len() + (4 - tlv.Len()%4) // padding
	}
}

type IPv4LspIdentifiers struct {
	IPv4TunnelSenderAddress   netip.Addr
	IPv4TunnelEndpointAddress netip.Addr
}

func (tlv *IPv4LspIdentifiers) DecodeFromBytes(data []uint8) error {
	var ok bool
	if tlv.IPv4TunnelSenderAddress, ok = netip.AddrFromSlice(data[12:16]); !ok {
		tlv.IPv4TunnelSenderAddress, _ = netip.AddrFromSlice(data[4:8])
	}
	tlv.IPv4TunnelEndpointAddress, _ = netip.AddrFromSlice(data[16:20])
	return nil
}

func (tlv *IPv4LspIdentifiers) Serialize() []uint8 {
	return nil
}

func (tlv *IPv4LspIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *IPv4LspIdentifiers) Type() uint16 {
	return TLV_IPV4_LSP_IDENTIFIERS
}

func (tlv *IPv4LspIdentifiers) Len() uint16 {
	return TLV_IPV4_LSP_IDENTIFIERS_LENGTH
}

func (tlv *IPv4LspIdentifiers) GetByteLength() uint16 {
	return TL_LENGTH + TLV_IPV4_LSP_IDENTIFIERS_LENGTH
}

type IPv6LspIdentifiers struct {
	IPv6TunnelSenderAddress   netip.Addr
	IPv6TunnelEndpointAddress netip.Addr
}

func (tlv *IPv6LspIdentifiers) DecodeFromBytes(data []uint8) error {
	tlv.IPv6TunnelSenderAddress, _ = netip.AddrFromSlice(data[4:20])
	tlv.IPv6TunnelEndpointAddress, _ = netip.AddrFromSlice(data[40:56])
	return nil
}

func (tlv *IPv6LspIdentifiers) Serialize() []uint8 {
	return nil
}

func (tlv *IPv6LspIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *IPv6LspIdentifiers) Type() uint16 {
	return TLV_IPV6_LSP_IDENTIFIERS
}

func (tlv *IPv6LspIdentifiers) Len() uint16 {
	return TLV_IPV6_LSP_IDENTIFIERS_LENGTH
}

func (tlv *IPv6LspIdentifiers) GetByteLength() uint16 {
	return TL_LENGTH + TLV_IPV6_LSP_IDENTIFIERS_LENGTH
}

type SrPceCapability struct {
	UnlimitedMSD    bool
	SupportNAI      bool
	MaximumSidDepth uint8
}

func (tlv *SrPceCapability) DecodeFromBytes(data []uint8) error {
	tlv.UnlimitedMSD = (data[6] & 0x01) != 0
	tlv.SupportNAI = (data[6] & 0x02) != 0
	tlv.MaximumSidDepth = data[7]
	return nil
}

func (tlv *SrPceCapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, tlv.Len())
	buf = append(buf, length...)

	val := make([]uint8, tlv.Len())
	if tlv.UnlimitedMSD {
		val[2] = val[2] | 0x01
	}
	if tlv.SupportNAI {
		val[2] = val[2] | 0x02
	}
	val[3] = tlv.MaximumSidDepth

	buf = append(buf, val...)
	return buf
}

func (tlv *SrPceCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SrPceCapability) Type() uint16 {
	return TLV_SR_PCE_CAPABILITY
}

func (tlv *SrPceCapability) Len() uint16 {
	return TLV_SR_PCE_CAPABILITY_LENGTH
}

func (tlv *SrPceCapability) GetByteLength() uint16 {
	return TL_LENGTH + TLV_SR_PCE_CAPABILITY_LENGTH
}

type Pst uint8

const (
	PST_RSVP_TE  Pst = 0x0
	PST_SR_TE    Pst = 0x1
	PST_PCECC_TE Pst = 0x2
	PST_SRV6_TE  Pst = 0x3
)

type Psts []Pst

func (ts Psts) MarshalJSON() ([]byte, error) {
	var result string
	if ts == nil {
		result = "null"
	} else {
		result = strings.Join(strings.Fields(fmt.Sprintf("%d", ts)), ",")
	}
	return []byte(result), nil
}

type PathSetupType struct {
	PathSetupType Pst
}

func (tlv *PathSetupType) DecodeFromBytes(data []uint8) error {
	tlv.PathSetupType = Pst(data[7])
	return nil
}

func (tlv *PathSetupType) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, tlv.Len())
	buf = append(buf, length...)

	val := make([]uint8, tlv.Len())
	val[3] = uint8(tlv.PathSetupType)

	buf = append(buf, val...)
	return buf
}

func (tlv *PathSetupType) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *PathSetupType) Type() uint16 {
	return TLV_PATH_SETUP_TYPE
}

func (tlv *PathSetupType) Len() uint16 {
	return TLV_PATH_SETUP_TYPE_LENGTH
}

func (tlv *PathSetupType) GetByteLength() uint16 {
	return TL_LENGTH + TLV_PATH_SETUP_TYPE_LENGTH
}

type PathSetupTypeCapability struct {
	Length         uint16
	PathSetupTypes Psts
	SubTlvs        []TlvInterface
}

func (tlv *PathSetupTypeCapability) DecodeFromBytes(data []uint8) error {
	tlv.Length = binary.BigEndian.Uint16(data[2:4])

	pstNum := int(data[7])
	for i := 0; i < pstNum; i++ {
		tlv.PathSetupTypes = append(tlv.PathSetupTypes, Pst(data[8+i]))
	}

	if pstNum%4 != 0 {
		pstNum += 4 - (pstNum % 4) // padding byte
	}
	var err error
	tlv.SubTlvs, err = DecodeTLVs(data[8+pstNum : TL_LENGTH+tlv.Length]) // 8 byte: Type&Length (4 byte) + Reserve&pstNum (4 byte)
	if err != nil {
		return err
	}
	return nil
}

func (tlv *PathSetupTypeCapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, tlv.Len())
	buf = append(buf, length...)

	pstNum := uint8(len(tlv.PathSetupTypes))

	var val []uint8
	if pstNum%4 == 0 {
		val = make([]uint8, 4+pstNum) // 4 byte: Reserve & Num of PST

	} else {
		val = make([]uint8, 4+pstNum+(4-(pstNum%4))) // 4 byte: Reserve & Num of PST
	}

	val[3] = pstNum
	for i, pst := range tlv.PathSetupTypes {
		val[4+i] = uint8(pst)
	}

	for _, subTlv := range tlv.SubTlvs {
		val = append(val, subTlv.Serialize()...)
	}
	buf = append(buf, val...)
	return buf
}

func (tlv *PathSetupTypeCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *PathSetupTypeCapability) Type() uint16 {
	return TLV_PATH_SETUP_TYPE_CAPABILITY
}

func (tlv *PathSetupTypeCapability) Len() uint16 {
	return tlv.Length
}

func (tlv *PathSetupTypeCapability) GetByteLength() uint16 {
	return TL_LENGTH + tlv.Length
}

type AssocType uint16

const (
	AT_RESERVED                                   AssocType = 0x00
	AT_PATH_PROTECTION_ASSOCIATION                AssocType = 0x01
	AT_DISCOINT_ASSOCIATION                       AssocType = 0x02
	AT_POLICY_ASSOCIATION                         AssocType = 0x03
	AT_SINGLE_SIDED_BIDIRECTIONAL_LSP_ASSOCIATION AssocType = 0x04
	AT_DOUBLE_SIDED_BIDIRECTIONAL_LSP_ASSOCIATION AssocType = 0x05
	AT_SR_POLICY_ASSOCIATION                      AssocType = 0x06
	AT_VN_ASSOCIATION_TYPE                        AssocType = 0x07
)

type AssocTypeList struct {
	AssocTypes []AssocType
}

func (tlv *AssocTypeList) DecodeFromBytes(data []uint8) error {
	AssocTypeNum := binary.BigEndian.Uint16(data[2:4]) / 2
	for i := 0; i < int(AssocTypeNum); i++ {
		at := binary.BigEndian.Uint16(data[4+2*i : 6+2*i])
		tlv.AssocTypes = append(tlv.AssocTypes, AssocType(at))
	}
	return nil
}

func (tlv *AssocTypeList) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, tlv.Len())
	buf = append(buf, length...)

	for _, at := range tlv.AssocTypes {
		binAt := make([]uint8, 2)
		binary.BigEndian.PutUint16(binAt, uint16(at))
		buf = append(buf, binAt...)
	}
	if tlv.Len()%4 != 0 {
		pad := make([]uint8, 4-(tlv.Len()%4))
		buf = append(buf, pad...)
	}
	return buf
}

func (tlv *AssocTypeList) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *AssocTypeList) Type() uint16 {
	return TLV_ASSOC_TYPE_LIST
}

func (tlv *AssocTypeList) Len() uint16 {
	return uint16(len(tlv.AssocTypes)) * 2
}
func (tlv *AssocTypeList) GetByteLength() uint16 {
	if tlv.Len()%4 == 0 {
		return TL_LENGTH + tlv.Len()
	} else {
		return TL_LENGTH + tlv.Len() + 2 // padding
	}
}

type UndefinedTlv struct {
	Typ    uint16
	Length uint16
	Value  []uint8
}

func (tlv *UndefinedTlv) DecodeFromBytes(data []uint8) error {
	tlv.Typ = binary.BigEndian.Uint16(data[0:2])
	tlv.Length = binary.BigEndian.Uint16(data[2:4])

	tlv.Value = data[4 : 4+tlv.Length]
	return nil
}

func (tlv *UndefinedTlv) Serialize() []uint8 {
	bytePcepTLV := []uint8{}

	byteTlvType := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTlvType, tlv.Typ)
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

func (c *UndefinedTlv) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *UndefinedTlv) Type() uint16 {
	return tlv.Typ
}

func (tlv *UndefinedTlv) Len() uint16 {
	return tlv.Length
}

func (tlv *UndefinedTlv) GetByteLength() uint16 {
	if tlv.Len()%4 == 0 {
		return TL_LENGTH + tlv.Len()
	} else {
		return TL_LENGTH + tlv.Len() + (4 - tlv.Len()%4) // padding
	}
}

func (tlv *UndefinedTlv) SetLength() {
	tlv.Length = uint16(len(tlv.Value))
}

func DecodeTLV(data []uint8) (TlvInterface, error) {
	var tlv TlvInterface
	switch binary.BigEndian.Uint16(data[0:2]) {
	case TLV_STATEFUL_PCE_CAPABILITY:
		tlv = &StatefulPceCapability{}

	case TLV_SYMBOLIC_PATH_NAME:
		tlv = &SymbolicPathName{}

	case TLV_IPV4_LSP_IDENTIFIERS:
		tlv = &IPv4LspIdentifiers{}

	case TLV_IPV6_LSP_IDENTIFIERS:
		tlv = &IPv6LspIdentifiers{}

	case TLV_SR_PCE_CAPABILITY:
		tlv = &SrPceCapability{}

	case TLV_PATH_SETUP_TYPE:
		tlv = &PathSetupType{}

	case TLV_PATH_SETUP_TYPE_CAPABILITY:
		tlv = &PathSetupTypeCapability{}

	case TLV_ASSOC_TYPE_LIST:
		tlv = &AssocTypeList{}

	default:
		tlv = &UndefinedTlv{}
	}
	if err := tlv.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return tlv, nil
}

func DecodeTLVs(data []uint8) ([]TlvInterface, error) {
	tlvs := []TlvInterface{}
	var tlv TlvInterface
	var err error

	for {
		if tlv, err = DecodeTLV(data); err != nil {
			return nil, err
		}
		tlvs = append(tlvs, tlv)
		if int(tlv.GetByteLength()) < len(data) {
			data = data[tlv.GetByteLength():]
		} else if int(tlv.GetByteLength()) == len(data) {
			break
		} else {
			return nil, errors.New("tlvs decode error")
		}
	}
	return tlvs, nil
}
