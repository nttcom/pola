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
	"slices"
	"strconv"
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
	TLV_PATH_SETUP_TYPE_CAPABILITY            uint16 = 0x22 // RFC8408
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
	TLV_PCE_FLOWSPEC_CAPABILITY               uint16 = 0x33 // RFC9168
	TLV_FLOW_FILTER                           uint16 = 0x34 // RFC9168
	TLV_BIDIRECTIONAL_LSP_ASSOCIATION_GROUP   uint16 = 0x36 // RFC9059
	TLV_TE_PATH_BINDING                       uint16 = 0x37 // RFC9604
	TLV_SRPOLICY_POL_NAME                     uint16 = 0x38 // ietf-pce-segment-routing-policy-cp-07
	TLV_SRPOLICY_CPATH_ID                     uint16 = 0x39 // ietf-pce-segment-routing-policy-cp-07
	TLV_SRPOLICY_CPATH_NAME                   uint16 = 0x3a // ietf-pce-segment-routing-policy-cp-07
	TLV_SRPOLICY_CPATH_PREFERENCE             uint16 = 0x3b // ietf-pce-segment-routing-policy-cp-07
	TLV_MULTIPATH_CAP                         uint16 = 0x3c // ietf-pce-pcep-multipath-07
	TLV_MULTIPATH_WIGHT                       uint16 = 0x3d // ietf-pce-pcep-multipath-07
	TLV_MULTIPATH_BACKUP                      uint16 = 0x3e // ietf-pce-pcep-multipath-07
	TLV_LSP_EXTENDED_FLAG                     uint16 = 0x3f // RFC9357
	TLV_VIRTUAL_NETWORK_TLV                   uint16 = 0x41 // RFC9358
	TLV_SR_ALGORITHM                          uint16 = 0x42 // ietf-pce-sid-algo-12
	TLV_COLOR                                 uint16 = 0x43 // ietf-pce-pcep-color-06
	TLV_COMPUTATION_PRIORITY                  uint16 = 0x44 // ietf-pce-segment-routing-policy-cp-14
	TLV_EXPLICIT_NULL_LABEL_POLICY            uint16 = 0x45 // draft-ietf-pce-segment-routing-policy-cp-14
	TLV_INVALIDATION                          uint16 = 0x4c // draft-ietf-pce-segment-routing-policy-cp-14
	TLV_SRPOLICY_CAPABILITY                   uint16 = 0x4d // draft-ietf-pce-segment-routing-policy-cp-14
	TLV_PATH_RECOMPUTATION                    uint16 = 0x4e // draft-ietf-pce-circuit-style-pcep-extensions-03
	TLV_SR_P2MP_POLICY_CAPABILITY             uint16 = 0x4f // draft-ietf-pce-sr-p2mp-policy-09
	TLV_IPV4_SR_P2MP_INSTANCE_ID              uint16 = 0x50 // draft-ietf-pce-sr-p2mp-policy-09
	TLV_IPV6_SR_P2MP_INSTANCE_ID              uint16 = 0x51 // draft-ietf-pce-sr-p2mp-policy-09
)

var tlvMap = map[uint16]func() TLVInterface{
	TLV_STATEFUL_PCE_CAPABILITY:    func() TLVInterface { return &StatefulPceCapability{} },
	TLV_SYMBOLIC_PATH_NAME:         func() TLVInterface { return &SymbolicPathName{} },
	TLV_IPV4_LSP_IDENTIFIERS:       func() TLVInterface { return &IPv4LspIdentifiers{} },
	TLV_IPV6_LSP_IDENTIFIERS:       func() TLVInterface { return &IPv6LspIdentifiers{} },
	TLV_LSP_DB_VERSION:             func() TLVInterface { return &LSPDBVersion{} },
	TLV_SR_PCE_CAPABILITY:          func() TLVInterface { return &SRPceCapability{} },
	TLV_PATH_SETUP_TYPE:            func() TLVInterface { return &PathSetupType{} },
	TLV_EXTENDED_ASSOCIATION_ID:    func() TLVInterface { return &ExtendedAssociationID{} },
	TLV_PATH_SETUP_TYPE_CAPABILITY: func() TLVInterface { return &PathSetupTypeCapability{} },
	TLV_ASSOC_TYPE_LIST:            func() TLVInterface { return &AssocTypeList{} },
	TLV_COLOR:                      func() TLVInterface { return &Color{} },
}

const (
	TLV_STATEFUL_PCE_CAPABILITY_LENGTH      uint16 = 4
	TLV_LSP_DB_VERSION_LENGTH               uint16 = 8
	TLV_SR_PCE_CAPABILITY_LENGTH            uint16 = 4
	TLV_PATH_SETUP_TYPE_LENGTH              uint16 = 4
	TLV_EXTENDED_ASSOCIATION_ID_IPV4_LENGTH uint16 = 8
	TLV_EXTENDED_ASSOCIATION_ID_IPV6_LENGTH uint16 = 20
	TLV_IPV4_LSP_IDENTIFIERS_LENGTH         uint16 = 16
	TLV_IPV6_LSP_IDENTIFIERS_LENGTH         uint16 = 52
	TLV_SRPOLICY_CPATH_ID_LENGTH            uint16 = 28
	TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH    uint16 = 4
	TLV_COLOR_LENGTH                        uint16 = 4
)

const TL_LENGTH = 4

type TLVInterface interface {
	DecodeFromBytes(data []uint8) error
	Serialize() []uint8
	MarshalLogObject(enc zapcore.ObjectEncoder) error
	Type() uint16
	Len() uint16 // Total length of Type, Length, and Value
}

type StatefulPceCapability struct {
	LspUpdateCapability            bool // 31
	IncludeDBVersion               bool // 30
	LspInstantiationCapability     bool // 29
	TriggeredResync                bool // 28
	DeltaLspSyncCapability         bool // 27
	TriggeredInitialSync           bool // 26
	P2mpCapability                 bool // 25
	P2mpLspUpdateCapability        bool // 24
	P2mpLspInstantiationCapability bool // 23
	LspSchedulingCapability        bool // 22
	PdLspCapability                bool // 21
	ColorCapability                bool // 20
	PathRecomputationCapability    bool // 19
	StrictPathCapability           bool // 18
	Relax                          bool // 17
}

const (
	LSP_UPDATE_CAPABILITY_BIT         uint8 = 0x01
	INCLUDE_DB_VERSION_CAPABILITY_BIT uint8 = 0x02
	LSP_INSTANTIATION_CAPABILITY_BIT  uint8 = 0x04
	TRIGGERED_RESYNC_CAPABILITY_BIT   uint8 = 0x08
	DELTA_LSP_SYNC_CAPABILITY_BIT     uint8 = 0x10
	TRIGGERED_INITIAL_SYNC_BIT        uint8 = 0x20
)

func (tlv *StatefulPceCapability) DecodeFromBytes(data []uint8) error {
	if len(data) < int(tlv.Len()) {
		return fmt.Errorf("data is too short: expected at least %d bytes, but got %d bytes for StatefulPceCapability", tlv.Len(), len(data))
	}

	flags := data[7]
	tlv.LspUpdateCapability = IsBitSet(flags, LSP_UPDATE_CAPABILITY_BIT)
	tlv.IncludeDBVersion = IsBitSet(flags, INCLUDE_DB_VERSION_CAPABILITY_BIT)
	tlv.LspInstantiationCapability = IsBitSet(flags, LSP_INSTANTIATION_CAPABILITY_BIT)
	tlv.TriggeredResync = IsBitSet(flags, TRIGGERED_RESYNC_CAPABILITY_BIT)
	tlv.DeltaLspSyncCapability = IsBitSet(flags, DELTA_LSP_SYNC_CAPABILITY_BIT)
	tlv.TriggeredInitialSync = IsBitSet(flags, TRIGGERED_INITIAL_SYNC_BIT)

	return nil
}

func (tlv *StatefulPceCapability) Serialize() []uint8 {
	buf := make([]uint8, 0, TLV_STATEFUL_PCE_CAPABILITY_LENGTH+4)
	buf = append(buf, Uint16ToByteSlice(tlv.Type())...)
	buf = append(buf, Uint16ToByteSlice(TLV_STATEFUL_PCE_CAPABILITY_LENGTH)...)

	var val uint32 = 0

	if tlv.LspUpdateCapability {
		val = SetBit(val, uint32(LSP_UPDATE_CAPABILITY_BIT))
	}
	if tlv.IncludeDBVersion {
		val = SetBit(val, uint32(INCLUDE_DB_VERSION_CAPABILITY_BIT))
	}
	if tlv.LspInstantiationCapability {
		val = SetBit(val, uint32(LSP_INSTANTIATION_CAPABILITY_BIT))
	}
	if tlv.TriggeredResync {
		val = SetBit(val, uint32(TRIGGERED_RESYNC_CAPABILITY_BIT))
	}
	if tlv.DeltaLspSyncCapability {
		val = SetBit(val, uint32(DELTA_LSP_SYNC_CAPABILITY_BIT))
	}
	if tlv.TriggeredInitialSync {
		val = SetBit(val, uint32(TRIGGERED_INITIAL_SYNC_BIT))
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, val)
	buf = append(buf, b...)

	return buf
}

func (tlv *StatefulPceCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("lspUpdateCapability", tlv.LspUpdateCapability)
	enc.AddBool("includeDBVersion", tlv.IncludeDBVersion)
	enc.AddBool("lspInstantiationCapability", tlv.LspInstantiationCapability)
	enc.AddBool("triggeredResync", tlv.TriggeredResync)
	enc.AddBool("deltaLspSyncCapability", tlv.DeltaLspSyncCapability)
	enc.AddBool("triggeredInitialSync", tlv.TriggeredInitialSync)
	return nil
}

func (tlv *StatefulPceCapability) Type() uint16 {
	return TLV_STATEFUL_PCE_CAPABILITY
}

func (tlv *StatefulPceCapability) Len() uint16 {
	return TL_LENGTH + TLV_STATEFUL_PCE_CAPABILITY_LENGTH
}

func (tlv *StatefulPceCapability) CapStrings() []string {
	ret := []string{"Stateful"}
	if tlv.LspUpdateCapability {
		ret = append(ret, "Update")
	}
	if tlv.IncludeDBVersion {
		ret = append(ret, "Include-DB-Ver")
	}
	if tlv.LspInstantiationCapability {
		ret = append(ret, "Initiate")
	}
	if tlv.TriggeredResync {
		ret = append(ret, "Triggered-Resync")
	}
	if tlv.DeltaLspSyncCapability {
		ret = append(ret, "Delta-LSP-Sync")
	}
	if tlv.TriggeredInitialSync {
		ret = append(ret, "Triggered-init-sync")
	}
	if tlv.ColorCapability {
		ret = append(ret, "Color")
	}
	return ret
}

func (tlv *StatefulPceCapability) FromBits(b uint8) {
	tlv.LspUpdateCapability = b&LSP_UPDATE_CAPABILITY_BIT != 0
	tlv.IncludeDBVersion = b&INCLUDE_DB_VERSION_CAPABILITY_BIT != 0
	tlv.LspInstantiationCapability = b&LSP_INSTANTIATION_CAPABILITY_BIT != 0
	tlv.TriggeredResync = b&TRIGGERED_RESYNC_CAPABILITY_BIT != 0
	tlv.DeltaLspSyncCapability = b&DELTA_LSP_SYNC_CAPABILITY_BIT != 0
	tlv.TriggeredInitialSync = b&TRIGGERED_INITIAL_SYNC_BIT != 0
}

func NewStatefulPceCapability(bits uint8) *StatefulPceCapability {
	tlv := &StatefulPceCapability{}
	tlv.FromBits(bits)
	return tlv
}

func (tlv *StatefulPceCapability) CapabilityBits() uint8 {
	var b uint8
	if tlv.LspUpdateCapability {
		b |= LSP_UPDATE_CAPABILITY_BIT
	}
	if tlv.IncludeDBVersion {
		b |= INCLUDE_DB_VERSION_CAPABILITY_BIT
	}
	if tlv.LspInstantiationCapability {
		b |= LSP_INSTANTIATION_CAPABILITY_BIT
	}
	if tlv.TriggeredResync {
		b |= TRIGGERED_RESYNC_CAPABILITY_BIT
	}
	if tlv.DeltaLspSyncCapability {
		b |= DELTA_LSP_SYNC_CAPABILITY_BIT
	}
	if tlv.TriggeredInitialSync {
		b |= TRIGGERED_INITIAL_SYNC_BIT
	}
	return b
}

type SymbolicPathName struct {
	Name string
}

func (tlv *SymbolicPathName) DecodeFromBytes(data []byte) error {
	if len(data) < TL_LENGTH {
		return fmt.Errorf("data is too short: expected at least %d bytes, but got %d bytes for SymbolicPathName", TL_LENGTH, len(data))
	}

	length := binary.BigEndian.Uint16(data[2:4])
	totalLen := int(TL_LENGTH + length)
	if len(data) != totalLen {
		return fmt.Errorf("data length mismatch: expected at %d bytes, but got %d bytes for SymbolicPathName", totalLen, len(data))
	}

	tlv.Name = string(data[TL_LENGTH:totalLen])
	return nil
}

func (tlv *SymbolicPathName) Serialize() []byte {
	nameLen := uint16(len(tlv.Name))
	padding := (4 - (nameLen % 4)) % 4 // Add padding for 4-byte alignment if needed

	buf := make([]byte, 0, TL_LENGTH+int(nameLen)+int(padding))
	buf = append(buf, Uint16ToByteSlice(tlv.Type())...)
	buf = append(buf, Uint16ToByteSlice(nameLen)...)
	buf = append(buf, []byte(tlv.Name)...)

	if padding > 0 {
		buf = append(buf, make([]byte, padding)...)
	}

	return buf
}

func (tlv *SymbolicPathName) Type() uint16 {
	return TLV_SYMBOLIC_PATH_NAME
}

func (tlv *SymbolicPathName) Len() uint16 {
	length := uint16(len(tlv.Name))
	padding := uint16(0)
	if mod := length % 4; mod != 0 {
		padding = 4 - mod
	}
	return TL_LENGTH + length + padding
}

func (tlv *SymbolicPathName) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("symbolicPathName", tlv.Name)
	return nil
}

func NewSymbolicPathName(name string) *SymbolicPathName {
	return &SymbolicPathName{Name: name}
}

type IPv4LspIdentifiers struct {
	IPv4TunnelSenderAddress   netip.Addr
	IPv4TunnelEndpointAddress netip.Addr
	LspID                     uint16
	TunnelID                  uint16
	ExtendedTunnelID          uint32
}

func (tlv *IPv4LspIdentifiers) DecodeFromBytes(data []uint8) error {
	if len(data) < TL_LENGTH+int(TLV_IPV4_LSP_IDENTIFIERS_LENGTH) {
		return fmt.Errorf("data length is insufficient for IPv4LspIdentifiers")
	}

	var ok bool
	if tlv.IPv4TunnelSenderAddress, ok = netip.AddrFromSlice(data[4:8]); !ok {
		return fmt.Errorf("failed to parse IPv4TunnelSenderAddress")
	}

	tlv.LspID = binary.BigEndian.Uint16(data[8:10])
	tlv.TunnelID = binary.BigEndian.Uint16(data[10:12])
	tlv.ExtendedTunnelID = binary.BigEndian.Uint32(data[12:16])

	if tlv.IPv4TunnelEndpointAddress, ok = netip.AddrFromSlice(data[16:20]); !ok {
		return fmt.Errorf("failed to parse IPv4TunnelEndpointAddress")
	}

	return nil
}

func (tlv *IPv4LspIdentifiers) Serialize() []uint8 {
	buf := make([]uint8, tlv.Len())

	binary.BigEndian.PutUint16(buf[0:2], tlv.Type())
	binary.BigEndian.PutUint16(buf[2:4], TLV_IPV4_LSP_IDENTIFIERS_LENGTH)
	copy(buf[4:8], tlv.IPv4TunnelSenderAddress.AsSlice())
	binary.BigEndian.PutUint16(buf[8:10], tlv.LspID)
	binary.BigEndian.PutUint16(buf[10:12], tlv.TunnelID)
	binary.BigEndian.PutUint32(buf[12:16], tlv.ExtendedTunnelID)
	copy(buf[16:20], tlv.IPv4TunnelEndpointAddress.AsSlice())

	return buf
}

func (tlv *IPv4LspIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *IPv4LspIdentifiers) Type() uint16 {
	return TLV_IPV4_LSP_IDENTIFIERS
}

func (tlv *IPv4LspIdentifiers) Len() uint16 {
	return TL_LENGTH + TLV_IPV4_LSP_IDENTIFIERS_LENGTH
}

func NewIPv4LspIdentifiers(senderAddr, endpointAddr netip.Addr, lspID, tunnelID uint16, extendedTunnelID uint32) *IPv4LspIdentifiers {
	return &IPv4LspIdentifiers{
		IPv4TunnelSenderAddress:   senderAddr,
		IPv4TunnelEndpointAddress: endpointAddr,
		LspID:                     lspID,
		TunnelID:                  tunnelID,
		ExtendedTunnelID:          extendedTunnelID,
	}
}

type IPv6LspIdentifiers struct {
	IPv6TunnelSenderAddress   netip.Addr
	IPv6TunnelEndpointAddress netip.Addr
	LspID                     uint16
	TunnelID                  uint16
	ExtendedTunnelID          [16]byte
}

func (tlv *IPv6LspIdentifiers) DecodeFromBytes(data []uint8) error {
	if len(data) < TL_LENGTH+int(TLV_IPV6_LSP_IDENTIFIERS_LENGTH) {
		return fmt.Errorf("data length is insufficient for IPv6LspIdentifiers")
	}

	var ok bool
	if tlv.IPv6TunnelSenderAddress, ok = netip.AddrFromSlice(data[4:20]); !ok {
		return fmt.Errorf("failed to parse IPv6TunnelSenderAddress")
	}

	tlv.LspID = binary.BigEndian.Uint16(data[20:22])
	tlv.TunnelID = binary.BigEndian.Uint16(data[22:24])
	copy(tlv.ExtendedTunnelID[:], data[24:40])

	if tlv.IPv6TunnelEndpointAddress, ok = netip.AddrFromSlice(data[40:56]); !ok {
		return fmt.Errorf("failed to parse IPv6TunnelEndpointAddress")
	}

	return nil
}

func (tlv *IPv6LspIdentifiers) Serialize() []uint8 {
	buf := make([]uint8, tlv.Len())

	binary.BigEndian.PutUint16(buf[0:2], tlv.Type())
	binary.BigEndian.PutUint16(buf[2:4], 56)
	copy(buf[4:20], tlv.IPv6TunnelSenderAddress.AsSlice())
	binary.BigEndian.PutUint16(buf[20:22], tlv.LspID)
	binary.BigEndian.PutUint16(buf[22:24], tlv.TunnelID)
	copy(buf[24:40], tlv.ExtendedTunnelID[:])
	copy(buf[40:56], tlv.IPv6TunnelEndpointAddress.AsSlice())

	return buf
}

func (tlv *IPv6LspIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *IPv6LspIdentifiers) Type() uint16 {
	return TLV_IPV6_LSP_IDENTIFIERS
}

func (tlv *IPv6LspIdentifiers) Len() uint16 {
	return TL_LENGTH + TLV_IPV6_LSP_IDENTIFIERS_LENGTH
}

func NewIPv6LspIdentifiers(senderAddr, endpointAddr netip.Addr, lspID, tunnelID uint16, extendedTunnelID [16]byte) *IPv6LspIdentifiers {
	return &IPv6LspIdentifiers{
		IPv6TunnelSenderAddress:   senderAddr,
		IPv6TunnelEndpointAddress: endpointAddr,
		LspID:                     lspID,
		TunnelID:                  tunnelID,
		ExtendedTunnelID:          extendedTunnelID,
	}
}

type LSPDBVersion struct {
	VersionNumber uint64
}

func (tlv *LSPDBVersion) DecodeFromBytes(data []uint8) error {
	tlv.VersionNumber = binary.BigEndian.Uint64(data[4:12])
	return nil
}

func (tlv *LSPDBVersion) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLV_LSP_DB_VERSION_LENGTH)
	buf = append(buf, length...)

	val := make([]uint8, TLV_LSP_DB_VERSION_LENGTH)
	binary.BigEndian.PutUint64(val, tlv.VersionNumber)

	buf = append(buf, val...)
	return buf
}

func (tlv *LSPDBVersion) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *LSPDBVersion) Type() uint16 {
	return TLV_LSP_DB_VERSION
}

func (tlv *LSPDBVersion) Len() uint16 {
	return TL_LENGTH + TLV_LSP_DB_VERSION_LENGTH
}

func (tlv *LSPDBVersion) CapStrings() []string {
	return []string{"LSP-DB-VERSION"}
}

type SRPceCapability struct {
	UnlimitedMSD    bool
	SupportNAI      bool
	MaximumSidDepth uint8
}

func (tlv *SRPceCapability) DecodeFromBytes(data []uint8) error {
	tlv.UnlimitedMSD = (data[6] & 0x01) != 0
	tlv.SupportNAI = (data[6] & 0x02) != 0
	tlv.MaximumSidDepth = data[7]
	return nil
}

func (tlv *SRPceCapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLV_SR_PCE_CAPABILITY_LENGTH)
	buf = append(buf, length...)

	val := make([]uint8, TLV_SR_PCE_CAPABILITY_LENGTH)
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

func (tlv *SRPceCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SRPceCapability) Type() uint16 {
	return TLV_SR_PCE_CAPABILITY
}

func (tlv *SRPceCapability) Len() uint16 {
	return TL_LENGTH + TLV_SR_PCE_CAPABILITY_LENGTH
}

func (tlv *SRPceCapability) CapStrings() []string {
	return []string{"SR-TE"}
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
	binary.BigEndian.PutUint16(length, TLV_PATH_SETUP_TYPE_LENGTH)
	buf = append(buf, length...)

	val := make([]uint8, TLV_PATH_SETUP_TYPE_LENGTH)
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
	return TL_LENGTH + TLV_PATH_SETUP_TYPE_LENGTH
}

type ExtendedAssociationID struct {
	Color    uint32
	Endpoint netip.Addr
}

func (tlv *ExtendedAssociationID) DecodeFromBytes(data []uint8) error {
	length := binary.BigEndian.Uint16(data[2:4])

	tlv.Color = binary.BigEndian.Uint32(data[4:8])

	switch length {
	case TLV_EXTENDED_ASSOCIATION_ID_IPV4_LENGTH:
		tlv.Endpoint, _ = netip.AddrFromSlice(data[8:12])
	case TLV_EXTENDED_ASSOCIATION_ID_IPV6_LENGTH:
		tlv.Endpoint, _ = netip.AddrFromSlice(data[8:24])
	}

	return nil
}

func (tlv *ExtendedAssociationID) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	if tlv.Endpoint.Is4() {
		binary.BigEndian.PutUint16(length, TLV_EXTENDED_ASSOCIATION_ID_IPV4_LENGTH)
	} else if tlv.Endpoint.Is6() {
		binary.BigEndian.PutUint16(length, TLV_EXTENDED_ASSOCIATION_ID_IPV6_LENGTH)
	}
	buf = append(buf, length...)

	color := make([]uint8, 4)
	binary.BigEndian.PutUint32(color, tlv.Color)
	buf = append(buf, color...)

	buf = append(buf, tlv.Endpoint.AsSlice()...)
	return buf
}

func (tlv *ExtendedAssociationID) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *ExtendedAssociationID) Type() uint16 {
	return TLV_EXTENDED_ASSOCIATION_ID
}

func (tlv *ExtendedAssociationID) Len() uint16 {
	if tlv.Endpoint.Is4() {
		return TL_LENGTH + TLV_EXTENDED_ASSOCIATION_ID_IPV4_LENGTH
	} else if tlv.Endpoint.Is6() {
		return TL_LENGTH + TLV_EXTENDED_ASSOCIATION_ID_IPV6_LENGTH
	}
	return 0

}

type PathSetupTypeCapability struct {
	PathSetupTypes Psts
	SubTLVs        []TLVInterface
}

func (tlv *PathSetupTypeCapability) DecodeFromBytes(data []uint8) error {
	length := binary.BigEndian.Uint16(data[2:4])

	pstNum := int(data[7])
	for i := 0; i < pstNum; i++ {
		tlv.PathSetupTypes = append(tlv.PathSetupTypes, Pst(data[8+i]))
	}

	if pstNum%4 != 0 {
		pstNum += 4 - (pstNum % 4) // padding byte
	}
	var err error
	tlv.SubTLVs, err = DecodeTLVs(data[8+pstNum : TL_LENGTH+length]) // 8 byte: Type&Length (4 byte) + Reserve&pstNum (4 byte)
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

	numOfPst := uint16(len(tlv.PathSetupTypes))

	length := uint16(4) // 4 byte: reserve & num of PSTs field
	length += numOfPst
	if numOfPst%4 != 0 {
		length += 4 - (numOfPst % 4)
	}
	for _, subTLV := range tlv.SubTLVs {
		length += subTLV.Len()
	}
	lengthBytes := make([]uint8, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)
	buf = append(buf, lengthBytes...)

	var val []uint8
	if numOfPst%4 == 0 {
		val = make([]uint8, 4+numOfPst) // 4 byte: Reserve & Num of PST

	} else {
		val = make([]uint8, 4+numOfPst+(4-(numOfPst%4))) // 4 byte: Reserve & Num of PST
	}

	val[3] = uint8(numOfPst)
	for i, pst := range tlv.PathSetupTypes {
		val[4+i] = uint8(pst)
	}

	for _, subTLV := range tlv.SubTLVs {
		val = append(val, subTLV.Serialize()...)
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
	length := uint16(4) // 4 byte: reserve & num of PSTs field
	numOfPst := uint16(len(tlv.PathSetupTypes))
	length += numOfPst
	if numOfPst%4 != 0 {
		length += 4 - (numOfPst % 4)
	}
	for _, subTLV := range tlv.SubTLVs {
		length += subTLV.Len()
	}
	return TL_LENGTH + length
}

func (tlv *PathSetupTypeCapability) CapStrings() []string {
	ret := []string{}
	if slices.Contains(tlv.PathSetupTypes, PST_SR_TE) {
		ret = append(ret, "SR-TE")
	}
	if slices.Contains(tlv.PathSetupTypes, PST_SRV6_TE) {
		ret = append(ret, "SRv6-TE")
	}
	return ret
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

	length := uint16(len(tlv.AssocTypes)) * 2
	lengthBytes := make([]uint8, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)
	buf = append(buf, lengthBytes...)

	for _, at := range tlv.AssocTypes {
		binAt := make([]uint8, 2)
		binary.BigEndian.PutUint16(binAt, uint16(at))
		buf = append(buf, binAt...)
	}
	if length%4 != 0 {
		pad := make([]uint8, 4-(length%4))
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
	length := uint16(len(tlv.AssocTypes)) * 2
	padding := uint16(0)
	if length%4 != 0 {
		padding = 2
	}
	return TL_LENGTH + length + padding
}

func (tlv *AssocTypeList) CapStrings() []string {
	return []string{}
}

type SRPolicyCandidatePathIdentifier struct {
	OriginatorAddr netip.Addr // After DecodeFromBytes, even ipv4 addresses are assigned in ipv6 format
}

func (tlv *SRPolicyCandidatePathIdentifier) DecodeFromBytes(data []uint8) error {
	tlv.OriginatorAddr, _ = netip.AddrFromSlice(data[12:28])
	return nil
}

func (tlv *SRPolicyCandidatePathIdentifier) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLV_SRPOLICY_CPATH_ID_LENGTH)
	buf = append(buf, length...)

	buf = append(buf, 0x0a)                   // protocol origin, PCEP = 10
	buf = append(buf, 0x00, 0x00, 0x00)       // mbz
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // Originator ASN
	// Originator Address
	if tlv.OriginatorAddr.Is4() {
		buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		buf = append(buf, tlv.OriginatorAddr.AsSlice()...)
	} else if tlv.OriginatorAddr.Is6() {
		buf = append(buf, tlv.OriginatorAddr.AsSlice()...)
	}
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // discriminator

	return buf
}

func (tlv *SRPolicyCandidatePathIdentifier) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SRPolicyCandidatePathIdentifier) Type() uint16 {
	return TLV_SRPOLICY_CPATH_ID
}

func (tlv *SRPolicyCandidatePathIdentifier) Len() uint16 {
	return TL_LENGTH + TLV_SRPOLICY_CPATH_ID_LENGTH
}

type SRPolicyCandidatePathPreference struct {
	Preference uint32
}

func (tlv *SRPolicyCandidatePathPreference) DecodeFromBytes(data []uint8) error {
	tlv.Preference = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (tlv *SRPolicyCandidatePathPreference) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH)
	buf = append(buf, length...)

	preference := make([]uint8, 4)
	binary.BigEndian.PutUint32(preference, tlv.Preference)
	buf = append(buf, preference...)

	return buf
}

func (tlv *SRPolicyCandidatePathPreference) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SRPolicyCandidatePathPreference) Type() uint16 {
	return TLV_SRPOLICY_CPATH_PREFERENCE
}

func (tlv *SRPolicyCandidatePathPreference) Len() uint16 {
	return TL_LENGTH + TLV_SRPOLICY_CPATH_PREFERENCE_LENGTH
}

type Color struct {
	Color uint32
}

func (tlv *Color) DecodeFromBytes(data []uint8) error {
	tlv.Color = binary.BigEndian.Uint32(data[4:8])
	return nil
}

func (tlv *Color) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, tlv.Type())
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLV_COLOR)
	buf = append(buf, length...)

	color := make([]uint8, 4)
	binary.BigEndian.PutUint32(color, tlv.Color)
	buf = append(buf, color...)

	return buf
}

func (tlv *Color) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *Color) Type() uint16 {
	return TLV_COLOR
}

func (tlv *Color) Len() uint16 {
	return TL_LENGTH + TLV_COLOR_LENGTH
}

type UndefinedTLV struct {
	Typ    uint16
	Length uint16
	Value  []uint8
}

func (tlv *UndefinedTLV) DecodeFromBytes(data []uint8) error {
	tlv.Typ = binary.BigEndian.Uint16(data[0:2])
	tlv.Length = binary.BigEndian.Uint16(data[2:4])

	tlv.Value = data[4 : 4+tlv.Length]
	return nil
}

func (tlv *UndefinedTLV) Serialize() []uint8 {
	bytePcepTLV := []uint8{}

	byteTLVType := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTLVType, tlv.Typ)
	bytePcepTLV = append(bytePcepTLV, byteTLVType...) // Type (2byte)

	byteTLVLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTLVLength, tlv.Length)
	bytePcepTLV = append(bytePcepTLV, byteTLVLength...) // Length (2byte)

	bytePcepTLV = append(bytePcepTLV, tlv.Value...) // Value (Length byte)
	if padding := tlv.Length % 4; padding != 0 {
		bytePadding := make([]uint8, 4-padding)
		bytePcepTLV = append(bytePcepTLV, bytePadding...)
	}
	return bytePcepTLV
}

func (tlv *UndefinedTLV) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *UndefinedTLV) Type() uint16 {
	return tlv.Typ
}

func (tlv *UndefinedTLV) Len() uint16 {
	padding := uint16(0)
	if tlv.Length%4 != 0 {
		padding = (4 - tlv.Length%4)
	}
	return TL_LENGTH + tlv.Length + padding
}

func (tlv *UndefinedTLV) CapStrings() []string {
	cap := "unknown_type_" + strconv.FormatInt(int64(tlv.Typ), 10)
	return []string{cap}
}

func (tlv *UndefinedTLV) SetLength() {
	tlv.Length = uint16(len(tlv.Value))
}

func DecodeTLV(data []uint8) (TLVInterface, error) {
	if len(data) < 2 {
		return nil, errors.New("insufficient data to read TLV type")
	}

	tlvType := binary.BigEndian.Uint16(data[0:2])

	if createTLV, found := tlvMap[tlvType]; found {
		tlv := createTLV()
		if err := tlv.DecodeFromBytes(data); err != nil {
			return nil, fmt.Errorf("error decoding TLV type %x: %w", tlvType, err)
		}
		return tlv, nil
	}

	tlv := &UndefinedTLV{}
	if err := tlv.DecodeFromBytes(data); err != nil {
		return nil, fmt.Errorf("error decoding undefined TLV type %x: %w", tlvType, err)
	}

	return tlv, nil
}

func DecodeTLVs(data []uint8) ([]TLVInterface, error) {
	var tlvs []TLVInterface

	for len(data) > 0 {
		tlv, err := DecodeTLV(data)
		if err != nil {
			return nil, err
		}

		tlvs = append(tlvs, tlv)

		tlvLen := int(tlv.Len())
		if len(data) < tlvLen {
			return nil, fmt.Errorf("expected TLV length %d but found %d bytes remaining", tlvLen, len(data))
		}

		data = data[tlvLen:]
	}

	return tlvs, nil
}
