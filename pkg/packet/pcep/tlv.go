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

type TLVType uint16

const ( // PCEP TLV
	TLVNoPathVector                       TLVType = 0x01
	TLVOverloadDuration                   TLVType = 0x02
	TLVReqMissing                         TLVType = 0x03
	TLVOFList                             TLVType = 0x04
	TLVOrder                              TLVType = 0x05
	TLVP2MPCapable                        TLVType = 0x06
	TLVVendorInformation                  TLVType = 0x07
	TLVWavelengthSelection                TLVType = 0x08
	TLVWavelengthRestriction              TLVType = 0x09
	TLVWavelengthAllocation               TLVType = 0x0a
	TLVOpticalInterfaceClassList          TLVType = 0x0b
	TLVClientSignalInformation            TLVType = 0x0c
	TLVHPCECapability                     TLVType = 0x0d
	TLVDomainID                           TLVType = 0x0e
	TLVHPCEFlag                           TLVType = 0x0f
	TLVStatefulPCECapability              TLVType = 0x10
	TLVSymbolicPathName                   TLVType = 0x11
	TLVIPv4LSPIdentifiers                 TLVType = 0x12
	TLVIPv6LSPIdentifiers                 TLVType = 0x13
	TLVLSPErrorCode                       TLVType = 0x14
	TLVRsvpErrorSpec                      TLVType = 0x15
	TLVLSPDBVersion                       TLVType = 0x17
	TLVSpeakerEntityID                    TLVType = 0x18
	TLVSRPCECapability                    TLVType = 0x1a
	TLVPathSetupType                      TLVType = 0x1c
	TLVOperatorConfiguredAssociationRange TLVType = 0x1d
	TLVGlobalAssociationSource            TLVType = 0x1e
	TLVExtendedAssociationID              TLVType = 0x1f
	TLVP2MPIPv4LSPIdentifiers             TLVType = 0x20
	TLVP2MPIPv6LSPIdentifiers             TLVType = 0x21
	TLVPathSetupTypeCapability            TLVType = 0x22
	TLVAssocTypeList                      TLVType = 0x23
	TLVAutoBandwidthCapability            TLVType = 0x24
	TLVAutoBandwidthAttributes            TLVType = 0x25
	TLVPathProtectionAssociationGroupTLV  TLVType = 0x26
	TLVIPv4Address                        TLVType = 0x27
	TLVIPv6Address                        TLVType = 0x28
	TLVUnnumberedEndpoint                 TLVType = 0x29
	TLVLabelRequest                       TLVType = 0x2a
	TLVLabelSet                           TLVType = 0x2b
	TLVProtectionAttribute                TLVType = 0x2c
	TLVGmplsCapability                    TLVType = 0x2d
	TLVDisjointnessConfiguration          TLVType = 0x2e
	TLVDisjointnessStatus                 TLVType = 0x2f
	TLVPolicyParameters                   TLVType = 0x30
	TLVSchedLSPAttribute                  TLVType = 0x31
	TLVSchedPdLSPAttribute                TLVType = 0x32
	TLVPCEFlowspecCapability              TLVType = 0x33
	TLVFlowFilter                         TLVType = 0x34
	TLVBidirectionalLSPAssociationGroup   TLVType = 0x36
	TLVTePathBinding                      TLVType = 0x37
	TLVSRPolicyPolName                    TLVType = 0x38
	TLVSRPolicyCPathID                    TLVType = 0x39
	TLVSRPolicyCPathName                  TLVType = 0x3a
	TLVSRPolicyCPathPreference            TLVType = 0x3b
	TLVMultipathCap                       TLVType = 0x3c
	TLVMultipathWeight                    TLVType = 0x3d
	TLVMultipathBackup                    TLVType = 0x3e
	TLVMultipathOppdirPath                TLVType = 0x3f
	TLVLSPExtendedFlag                    TLVType = 0x40
	TLVVirtualNetwork                     TLVType = 0x41
	TLVSrAlgorithm                        TLVType = 0x42
	TLVColor                              TLVType = 0x43
	TLVComputationPriority                TLVType = 0x44
	TLVExplicitNullLabelPolicy            TLVType = 0x45
	TLVInvalidation                       TLVType = 0x46
	TLVSRPolicyCapability                 TLVType = 0x47
	TLVPathRecomputation                  TLVType = 0x48
	TLVSRP2MPPolicyCapability             TLVType = 0x49
	TLVIPv4SrP2MPInstanceID               TLVType = 0x4a
	TLVIPv6SrP2MPInstanceID               TLVType = 0x4b
)

var tlvDescriptions = map[TLVType]struct {
	Description string
	Reference   string
}{
	TLVNoPathVector:                       {"NO-PATH-VECTOR", "RFC5440"},
	TLVOverloadDuration:                   {"OVERLOAD-DURATION", "RFC5440"},
	TLVReqMissing:                         {"REQ-MISSING", "RFC5440"},
	TLVOFList:                             {"OF-LIST", "RFC5541"},
	TLVOrder:                              {"ORDER", "RFC5557"},
	TLVP2MPCapable:                        {"P2MP-CAPABLE", "RFC8306"},
	TLVVendorInformation:                  {"VENDOR-INFORMATION", "RFC7470"},
	TLVWavelengthSelection:                {"WAVELENGTH-SELECTION", "RFC8780"},
	TLVWavelengthRestriction:              {"WAVELENGTH-RESTRICTION", "RFC8780"},
	TLVWavelengthAllocation:               {"WAVELENGTH-ALLOCATION", "RFC8780"},
	TLVOpticalInterfaceClassList:          {"OPTICAL-INTERFACE-CLASS-LIST", "RFC8780"},
	TLVClientSignalInformation:            {"CLIENT-SIGNAL-INFORMATION", "RFC8780"},
	TLVHPCECapability:                     {"H-PCE-CAPABILITY", "RFC8685"},
	TLVDomainID:                           {"DOMAIN-ID", "RFC8685"},
	TLVHPCEFlag:                           {"H-PCE-FLAG", "RFC8685"},
	TLVStatefulPCECapability:              {"STATEFUL-PCE-CAPABILITY", "RFC8231"},
	TLVSymbolicPathName:                   {"SYMBOLIC-PATH-NAME", "RFC8231"},
	TLVIPv4LSPIdentifiers:                 {"IPV4-LSP-IDENTIFIERS", "RFC8231"},
	TLVIPv6LSPIdentifiers:                 {"IPV6-LSP-IDENTIFIERS", "RFC8231"},
	TLVLSPErrorCode:                       {"LSP-ERROR-CODE", "RFC8231"},
	TLVRsvpErrorSpec:                      {"RSVP-ERROR-SPEC", "RFC8231"},
	TLVLSPDBVersion:                       {"LSP-DB-VERSION", "RFC8232"},
	TLVSpeakerEntityID:                    {"SPEAKER-ENTITY-ID", "RFC8232"},
	TLVSRPCECapability:                    {"SR-PCE-CAPABILITY", "RFC8664"},
	TLVPathSetupType:                      {"PATH-SETUP-TYPE", "RFC8408"},
	TLVOperatorConfiguredAssociationRange: {"OPERATOR-CONFIGURED-ASSOCIATION-RANGE", "RFC8697"},
	TLVGlobalAssociationSource:            {"GLOBAL-ASSOCIATION-SOURCE", "RFC8697"},
	TLVExtendedAssociationID:              {"EXTENDED-ASSOCIATION-ID", "RFC8697"},
	TLVP2MPIPv4LSPIdentifiers:             {"P2MP-IPV4-LSP-IDENTIFIERS", "RFC8623"},
	TLVP2MPIPv6LSPIdentifiers:             {"P2MP-IPV6-LSP-IDENTIFIERS", "RFC8623"},
	TLVPathSetupTypeCapability:            {"PATH-SETUP-TYPE-CAPABILITY", "RFC8408"},
	TLVAssocTypeList:                      {"ASSOC-TYPE-LIST", "RFC8697"},
	TLVAutoBandwidthCapability:            {"AUTO-BANDWIDTH-CAPABILITY", "RFC8733"},
	TLVAutoBandwidthAttributes:            {"AUTO-BANDWIDTH-ATTRIBUTES", "RFC8733"},
	TLVPathProtectionAssociationGroupTLV:  {"PATH-PROTECTION-ASSOCIATION-GROUP", "RFC8745"},
	TLVIPv4Address:                        {"IPV4-ADDRESS", "RFC8779"},
	TLVIPv6Address:                        {"IPV6-ADDRESS", "RFC8779"},
	TLVUnnumberedEndpoint:                 {"UNNUMBERED-ENDPOINT", "RFC8779"},
	TLVLabelRequest:                       {"LABEL-REQUEST", "RFC8779"},
	TLVLabelSet:                           {"LABEL-SET", "RFC8779"},
	TLVProtectionAttribute:                {"PROTECTION-ATTRIBUTE", "RFC8779"},
	TLVGmplsCapability:                    {"GMPLS-CAPABILITY", "RFC8779"},
	TLVDisjointnessConfiguration:          {"DISJOINTNESS-CONFIGURATION", "RFC8800"},
	TLVDisjointnessStatus:                 {"DISJOINTNESS-STATUS", "RFC8800"},
	TLVPolicyParameters:                   {"POLICY-PARAMETERS-TLV", "RFC9005"},
	TLVSchedLSPAttribute:                  {"SCHED-LSP-ATTRIBUTE", "RFC8934"},
	TLVSchedPdLSPAttribute:                {"SCHED-PD-LSP-ATTRIBUTE", "RFC8934"},
	TLVPCEFlowspecCapability:              {"PCE-FLOWSPEC-CAPABILITY TLV", "RFC9168"},
	TLVFlowFilter:                         {"FLOW-FILTER-TLV", "RFC9168"},
	TLVBidirectionalLSPAssociationGroup:   {"BIDIRECTIONAL-LSP Association Group TLV", "RFC9059"},
	TLVTePathBinding:                      {"TE-PATH-BINDING", "RFC9604"},
	TLVSRPolicyPolName:                    {"SRPOLICY-POL-NAME", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVSRPolicyCPathID:                    {"SRPOLICY-CPATH-ID", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVSRPolicyCPathName:                  {"SRPOLICY-CPATH-NAME", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVSRPolicyCPathPreference:            {"SRPOLICY-CPATH-PREFERENCE", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVMultipathCap:                       {"MULTIPATH-CAP", "draft-ietf-pce-multipath-07"},
	TLVMultipathWeight:                    {"MULTIPATH-WEIGHT", "draft-ietf-pce-multipath-07"},
	TLVMultipathBackup:                    {"MULTIPATH-BACKUP", "draft-ietf-pce-multipath-07"},
	TLVMultipathOppdirPath:                {"MULTIPATH-OPPDIR-PATH", "draft-ietf-pce-multipath-07"},
	TLVLSPExtendedFlag:                    {"LSP-EXTENDED-FLAG", "RFC9357"},
	TLVVirtualNetwork:                     {"VIRTUAL-NETWORK", "RFC9358"},
	TLVSrAlgorithm:                        {"SR-ALGORITHM", "draft-ietf-pce-sid-algo-12"},
	TLVColor:                              {"COLOR", "RFC-ietf-pce-pcep-color-12"},
	TLVComputationPriority:                {"COMPUTATION-PRIORITY", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVExplicitNullLabelPolicy:            {"EXPLICIT-NULL-LABEL-POLICY", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVInvalidation:                       {"INVALIDATION", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVSRPolicyCapability:                 {"SRPOLICY-CAPABILITY", "draft-ietf-pce-segment-routing-policy-cp-14"},
	TLVPathRecomputation:                  {"PATH-RECOMPUTATION", "draft-ietf-pce-circuit-style-pcep-extensions-03"},
	TLVSRP2MPPolicyCapability:             {"SRP2MP-POLICY-CAPABILITY", "draft-ietf-pce-sr-p2mp-policy-09"},
	TLVIPv4SrP2MPInstanceID:               {"IPV4-SR-P2MP-INSTANCE-ID", "draft-ietf-pce-sr-p2mp-policy-09"},
	TLVIPv6SrP2MPInstanceID:               {"IPV6-SR-P2MP-INSTANCE-ID", "draft-ietf-pce-sr-p2mp-policy-09"},
}

func (t TLVType) String() string {
	if desc, ok := tlvDescriptions[t]; ok {
		return fmt.Sprintf("%s (%s)", desc.Description, desc.Reference)
	}
	return fmt.Sprintf("Unknown TLV (0x%04x)", uint16(t))
}

var tlvMap = map[TLVType]func() TLVInterface{
	TLVStatefulPCECapability:   func() TLVInterface { return &StatefulPCECapability{} },
	TLVSymbolicPathName:        func() TLVInterface { return &SymbolicPathName{} },
	TLVIPv4LSPIdentifiers:      func() TLVInterface { return &IPv4LSPIdentifiers{} },
	TLVIPv6LSPIdentifiers:      func() TLVInterface { return &IPv6LSPIdentifiers{} },
	TLVLSPDBVersion:            func() TLVInterface { return &LSPDBVersion{} },
	TLVSRPCECapability:         func() TLVInterface { return &SRPCECapability{} },
	TLVPathSetupType:           func() TLVInterface { return &PathSetupType{} },
	TLVExtendedAssociationID:   func() TLVInterface { return &ExtendedAssociationID{} },
	TLVPathSetupTypeCapability: func() TLVInterface { return &PathSetupTypeCapability{} },
	TLVAssocTypeList:           func() TLVInterface { return &AssocTypeList{} },
	TLVColor:                   func() TLVInterface { return &Color{} },
}

const (
	TLVStatefulPCECapabilityValueLength     uint16 = 4
	TLVLSPDBVersionValueLength              uint16 = 8
	TLVSRPCECapabilityValueLength           uint16 = 4
	TLVPathSetupTypeValueLength             uint16 = 4
	TLVExtendedAssociationIDIPv4ValueLength uint16 = 8
	TLVExtendedAssociationIDIPv6ValueLength uint16 = 20
	TLVIPv4LSPIdentifiersValueLength        uint16 = 16
	TLVIPv6LSPIdentifiersValueLength        uint16 = 52
	TLVSRPolicyCPathIDValueLength           uint16 = 28
	TLVSRPolicyCPathPreferenceValueLength   uint16 = 4
	TLVColorValueLength                     uint16 = 4
)

// Juniper specific TLV (deprecated)
const (
	TLVExtendedAssociationIDIPv4Juniper TLVType = 0xffe3
	TLVSRPolicyCPathIDJuniper           TLVType = 0xffe4
	TLVSRPolicyCPathPreferenceJuniper   TLVType = 0xffe5
)

// Cisco specific SubTLV
const (
	SubTLVColorCisco      TLVType = 0x01
	SubTLVPreferenceCisco TLVType = 0x03
)

const (
	SubTLVColorCiscoValueLength      uint16 = 4
	SubTLVPreferenceCiscoValueLength uint16 = 4
)

const TLVHeaderLength = 4

type TLVInterface interface {
	DecodeFromBytes(data []uint8) error
	Serialize() []uint8
	MarshalLogObject(enc zapcore.ObjectEncoder) error
	Type() TLVType
	Len() uint16 // Total length of Type, Length, and Value
}

type StatefulPCECapability struct {
	LSPUpdateCapability            bool // 31
	IncludeDBVersion               bool // 30
	LSPInstantiationCapability     bool // 29
	TriggeredResync                bool // 28
	DeltaLSPSyncCapability         bool // 27
	TriggeredInitialSync           bool // 26
	P2mpCapability                 bool // 25
	P2mpLSPUpdateCapability        bool // 24
	P2mpLSPInstantiationCapability bool // 23
	LSPSchedulingCapability        bool // 22
	PdLSPCapability                bool // 21
	ColorCapability                bool // 20
	PathRecomputationCapability    bool // 19
	StrictPathCapability           bool // 18
	Relax                          bool // 17
}

func (tlv *StatefulPCECapability) DecodeFromBytes(flags []uint8) error {
	if len(flags) < 4 {
		return fmt.Errorf("flags array is too short, expected at least 4 bytes but got %d", len(flags))
	}

	flagMap := []struct {
		field *bool
		mask  uint8
		index int
	}{
		{&tlv.LSPUpdateCapability, 0x01, 3},
		{&tlv.IncludeDBVersion, 0x02, 3},
		{&tlv.LSPInstantiationCapability, 0x04, 3},
		{&tlv.TriggeredResync, 0x08, 3},
		{&tlv.DeltaLSPSyncCapability, 0x10, 3},
		{&tlv.TriggeredInitialSync, 0x20, 3},
		{&tlv.P2mpCapability, 0x40, 3},
		{&tlv.P2mpLSPUpdateCapability, 0x80, 3},
		{&tlv.P2mpLSPInstantiationCapability, 0x01, 2},
		{&tlv.LSPSchedulingCapability, 0x02, 2},
		{&tlv.PdLSPCapability, 0x04, 2},
		{&tlv.ColorCapability, 0x08, 2},
		{&tlv.PathRecomputationCapability, 0x10, 2},
		{&tlv.StrictPathCapability, 0x20, 2},
		{&tlv.Relax, 0x40, 2},
	}

	for _, f := range flagMap {
		*f.field = (flags[f.index] & f.mask) != 0
	}

	return nil
}

func setFlag(flags []uint8, index int, mask uint8, condition bool) {
	if condition {
		flags[index] = flags[index] | mask
	}
}

func (tlv *StatefulPCECapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLVStatefulPCECapabilityValueLength)
	buf = append(buf, length...)

	flags := make([]uint8, TLVStatefulPCECapabilityValueLength)

	setFlag(flags, 3, 0x01, tlv.LSPUpdateCapability)
	setFlag(flags, 3, 0x02, tlv.IncludeDBVersion)
	setFlag(flags, 3, 0x04, tlv.LSPInstantiationCapability)
	setFlag(flags, 3, 0x08, tlv.TriggeredResync)
	setFlag(flags, 3, 0x10, tlv.DeltaLSPSyncCapability)
	setFlag(flags, 3, 0x20, tlv.TriggeredInitialSync)
	setFlag(flags, 3, 0x40, tlv.P2mpCapability)
	setFlag(flags, 3, 0x80, tlv.P2mpLSPUpdateCapability)
	setFlag(flags, 2, 0x01, tlv.P2mpLSPInstantiationCapability)
	setFlag(flags, 2, 0x02, tlv.LSPSchedulingCapability)
	setFlag(flags, 2, 0x04, tlv.PdLSPCapability)
	setFlag(flags, 2, 0x08, tlv.ColorCapability)
	setFlag(flags, 2, 0x10, tlv.PathRecomputationCapability)
	setFlag(flags, 2, 0x20, tlv.StrictPathCapability)
	setFlag(flags, 2, 0x40, tlv.Relax)

	buf = append(buf, flags...)

	return buf
}

func (tlv *StatefulPCECapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *StatefulPCECapability) Type() TLVType {
	return TLVStatefulPCECapability
}

func (tlv *StatefulPCECapability) Len() uint16 {
	return TLVHeaderLength + TLVStatefulPCECapabilityValueLength
}

func (tlv *StatefulPCECapability) CapStrings() []string {
	ret := []string{}
	ret = append(ret, "Stateful")
	if tlv.LSPUpdateCapability {
		ret = append(ret, "Update")
	}
	if tlv.IncludeDBVersion {
		ret = append(ret, "Include-DB-Ver")
	}
	if tlv.LSPInstantiationCapability {
		ret = append(ret, "Initiate")
	}
	if tlv.TriggeredResync {
		ret = append(ret, "Triggerd-Resync")
	}
	if tlv.DeltaLSPSyncCapability {
		ret = append(ret, "Delta-LSP-Sync")
	}
	if tlv.TriggeredInitialSync {
		ret = append(ret, "Triggerd-init-sync")
	}
	if tlv.ColorCapability {
		ret = append(ret, "Color")
	}
	return ret
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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	l := uint16(len(tlv.Name))
	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, l)
	buf = append(buf, length...)

	buf = append(buf, []uint8(tlv.Name)...)

	if l%4 != 0 {
		pad := make([]uint8, 4-l%4)
		buf = append(buf, pad...)
	}
	return buf
}

func (tlv *SymbolicPathName) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SymbolicPathName) Type() TLVType {
	return TLVSymbolicPathName
}

func (tlv *SymbolicPathName) Len() uint16 {
	l := uint16(len(tlv.Name))
	padding := uint16(0)
	if l%4 != 0 {
		padding = (4 - l%4)
	}
	return TLVHeaderLength + l + padding
}

type IPv4LSPIdentifiers struct {
	IPv4TunnelSenderAddress   netip.Addr
	IPv4TunnelEndpointAddress netip.Addr
	LSPID                     uint16
	TunnelID                  uint16
}

func (tlv *IPv4LSPIdentifiers) DecodeFromBytes(data []uint8) error {
	var ok bool
	if tlv.IPv4TunnelSenderAddress, ok = netip.AddrFromSlice(data[12:16]); !ok {
		tlv.IPv4TunnelSenderAddress, _ = netip.AddrFromSlice(data[4:8])
	}
	tlv.LSPID = binary.BigEndian.Uint16(data[8:10])
	tlv.TunnelID = binary.BigEndian.Uint16(data[10:12])
	tlv.IPv4TunnelEndpointAddress, _ = netip.AddrFromSlice(data[16:20])
	return nil
}

func (tlv *IPv4LSPIdentifiers) Serialize() []uint8 {
	return nil
}

func (tlv *IPv4LSPIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *IPv4LSPIdentifiers) Type() TLVType {
	return TLVIPv4LSPIdentifiers
}

func (tlv *IPv4LSPIdentifiers) Len() uint16 {
	return TLVHeaderLength + TLVIPv4LSPIdentifiersValueLength
}

type IPv6LSPIdentifiers struct {
	IPv6TunnelSenderAddress   netip.Addr
	IPv6TunnelEndpointAddress netip.Addr
	LSPID                     uint16
	TunnelID                  uint16
}

func (tlv *IPv6LSPIdentifiers) DecodeFromBytes(data []uint8) error {
	tlv.IPv6TunnelSenderAddress, _ = netip.AddrFromSlice(data[4:20])
	tlv.LSPID = binary.BigEndian.Uint16(data[20:22])
	tlv.TunnelID = binary.BigEndian.Uint16(data[22:24])
	tlv.IPv6TunnelEndpointAddress, _ = netip.AddrFromSlice(data[40:56])
	return nil
}

func (tlv *IPv6LSPIdentifiers) Serialize() []uint8 {
	return nil
}

func (tlv *IPv6LSPIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *IPv6LSPIdentifiers) Type() TLVType {
	return TLVIPv6LSPIdentifiers
}

func (tlv *IPv6LSPIdentifiers) Len() uint16 {
	return TLVHeaderLength + TLVIPv6LSPIdentifiersValueLength
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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLVLSPDBVersionValueLength)
	buf = append(buf, length...)

	val := make([]uint8, TLVLSPDBVersionValueLength)
	binary.BigEndian.PutUint64(val, tlv.VersionNumber)

	buf = append(buf, val...)
	return buf
}

func (tlv *LSPDBVersion) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *LSPDBVersion) Type() TLVType {
	return TLVLSPDBVersion
}

func (tlv *LSPDBVersion) Len() uint16 {
	return TLVHeaderLength + TLVLSPDBVersionValueLength
}

func (tlv *LSPDBVersion) CapStrings() []string {
	return []string{"LSP-DB-VERSION"}
}

type SRPCECapability struct {
	UnlimitedMSD    bool
	SupportNAI      bool
	MaximumSidDepth uint8
}

func (tlv *SRPCECapability) DecodeFromBytes(data []uint8) error {
	tlv.UnlimitedMSD = (data[6] & 0x01) != 0
	tlv.SupportNAI = (data[6] & 0x02) != 0
	tlv.MaximumSidDepth = data[7]
	return nil
}

func (tlv *SRPCECapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLVSRPCECapabilityValueLength)
	buf = append(buf, length...)

	val := make([]uint8, TLVSRPCECapabilityValueLength)
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

func (tlv *SRPCECapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SRPCECapability) Type() TLVType {
	return TLVSRPCECapability
}

func (tlv *SRPCECapability) Len() uint16 {
	return TLVHeaderLength + TLVSRPCECapabilityValueLength
}

func (tlv *SRPCECapability) CapStrings() []string {
	return []string{"SR-TE"}
}

type Pst uint8

const (
	PathSetupTypeRSVPTE  Pst = 0x0
	PathSetupTypeSRTE    Pst = 0x1
	PathSetupTypePCECCTE Pst = 0x2
	PathSetupTypeSRv6TE  Pst = 0x3
	PathSetupTypeIPTE    Pst = 0x4
)

var pathSetupDescriptions = map[Pst]struct {
	Description string
	Reference   string
}{
	PathSetupTypeRSVPTE:  {"Path is set up using the RSVP-TE signaling protocol", "RFC8408"},
	PathSetupTypeSRTE:    {"Traffic engineering path is set up using Segment Routing", "RFC8664"},
	PathSetupTypePCECCTE: {"Traffic engineering path is set up using PCECC mode", "RFC9050"},
	PathSetupTypeSRv6TE:  {"Traffic engineering path is set up using SRv6", "RFC9603"},
	PathSetupTypeIPTE:    {"Native IP TE Path", "RFC9757"},
}

func (pst Pst) String() string {
	if desc, found := pathSetupDescriptions[pst]; found {
		return fmt.Sprintf("%s (%s)", desc.Description, desc.Reference)
	}
	return fmt.Sprintf("Unknown PathSetupType (0x%02x)", uint16(pst))
}

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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLVPathSetupTypeValueLength)
	buf = append(buf, length...)

	val := make([]uint8, TLVPathSetupTypeValueLength)
	val[3] = uint8(tlv.PathSetupType)

	buf = append(buf, val...)
	return buf
}

func (tlv *PathSetupType) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *PathSetupType) Type() TLVType {
	return TLVPathSetupType
}

func (tlv *PathSetupType) Len() uint16 {
	return TLVHeaderLength + TLVPathSetupTypeValueLength
}

type ExtendedAssociationID struct {
	Color    uint32
	Endpoint netip.Addr
}

func (tlv *ExtendedAssociationID) DecodeFromBytes(data []uint8) error {
	l := binary.BigEndian.Uint16(data[2:4])

	tlv.Color = binary.BigEndian.Uint32(data[4:8])

	switch l {
	case TLVExtendedAssociationIDIPv4ValueLength:
		tlv.Endpoint, _ = netip.AddrFromSlice(data[8:12])
	case TLVExtendedAssociationIDIPv6ValueLength:
		tlv.Endpoint, _ = netip.AddrFromSlice(data[8:24])
	}

	return nil
}

func (tlv *ExtendedAssociationID) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	if tlv.Endpoint.Is4() {
		binary.BigEndian.PutUint16(length, TLVExtendedAssociationIDIPv4ValueLength)
	} else if tlv.Endpoint.Is6() {
		binary.BigEndian.PutUint16(length, TLVExtendedAssociationIDIPv6ValueLength)
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

func (tlv *ExtendedAssociationID) Type() TLVType {
	return TLVExtendedAssociationID
}

func (tlv *ExtendedAssociationID) Len() uint16 {
	if tlv.Endpoint.Is4() {
		return TLVHeaderLength + TLVExtendedAssociationIDIPv4ValueLength
	} else if tlv.Endpoint.Is6() {
		return TLVHeaderLength + TLVExtendedAssociationIDIPv6ValueLength
	}
	return 0

}

type PathSetupTypeCapability struct {
	PathSetupTypes Psts
	SubTLVs        []TLVInterface
}

func (tlv *PathSetupTypeCapability) DecodeFromBytes(data []uint8) error {
	l := binary.BigEndian.Uint16(data[2:4])

	pstNum := int(data[7])
	for i := 0; i < pstNum; i++ {
		tlv.PathSetupTypes = append(tlv.PathSetupTypes, Pst(data[8+i]))
	}

	if pstNum%4 != 0 {
		pstNum += 4 - (pstNum % 4) // padding byte
	}
	var err error
	tlv.SubTLVs, err = DecodeTLVs(data[8+pstNum : TLVHeaderLength+l]) // 8 byte: Type&Length (4 byte) + Reserve&pstNum (4 byte)
	if err != nil {
		return err
	}
	return nil
}

func (tlv *PathSetupTypeCapability) Serialize() []uint8 {
	buf := []uint8{}

	typ := make([]uint8, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	numOfPst := uint16(len(tlv.PathSetupTypes))

	l := uint16(4) // 4 byte: reserve & num of PSTs field
	l += numOfPst
	if numOfPst%4 != 0 {
		l += 4 - (numOfPst % 4)
	}
	for _, subTLV := range tlv.SubTLVs {
		l += subTLV.Len()
	}
	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, l)
	buf = append(buf, length...)

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

func (tlv *PathSetupTypeCapability) Type() TLVType {
	return TLVPathSetupTypeCapability
}

func (tlv *PathSetupTypeCapability) Len() uint16 {
	l := uint16(4) // 4 byte: reserve & num of PSTs field
	numOfPst := uint16(len(tlv.PathSetupTypes))
	l += numOfPst
	if numOfPst%4 != 0 {
		l += 4 - (numOfPst % 4)
	}
	for _, subTLV := range tlv.SubTLVs {
		l += subTLV.Len()
	}
	return TLVHeaderLength + l
}

func (tlv *PathSetupTypeCapability) CapStrings() []string {
	ret := []string{}
	if slices.Contains(tlv.PathSetupTypes, PathSetupTypeSRTE) {
		ret = append(ret, "SR-TE")
	}
	if slices.Contains(tlv.PathSetupTypes, PathSetupTypeSRv6TE) {
		ret = append(ret, "SRv6-TE")
	}
	return ret
}

type AssocType uint16

const (
	AssocTypePathProtectionAssociation              AssocType = 0x01
	AssocTypeDisjointAssociation                    AssocType = 0x02
	AssocTypePolicyAssociation                      AssocType = 0x03
	AssocTypeSingleSidedBidirectionalLSPAssociation AssocType = 0x04
	AssocTypeDoubleSidedBidirectionalLSPAssociation AssocType = 0x05
	AssocTypeSrPolicyAssociation                    AssocType = 0x06
	AssocTypeVnAssociationType                      AssocType = 0x07
)

var assocTypeNames = map[AssocType]string{
	AssocTypePathProtectionAssociation:              "Path Protection Association",
	AssocTypeDisjointAssociation:                    "Disjoint Association",
	AssocTypePolicyAssociation:                      "Policy Association",
	AssocTypeSingleSidedBidirectionalLSPAssociation: "Single Sided Bidirectional LSP Association",
	AssocTypeDoubleSidedBidirectionalLSPAssociation: "Double Sided Bidirectional LSP Association",
	AssocTypeSrPolicyAssociation:                    "SR Policy Association",
	AssocTypeVnAssociationType:                      "VN Association Type",
}

func (at AssocType) String() string {
	if name, ok := assocTypeNames[at]; ok {
		return name
	}
	return fmt.Sprintf("Unknown AssocType (0x%04x)", uint16(at))
}

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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	l := uint16(len(tlv.AssocTypes)) * 2
	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, l)
	buf = append(buf, length...)

	for _, at := range tlv.AssocTypes {
		binAt := make([]uint8, 2)
		binary.BigEndian.PutUint16(binAt, uint16(at))
		buf = append(buf, binAt...)
	}
	if l%4 != 0 {
		pad := make([]uint8, 4-(l%4))
		buf = append(buf, pad...)
	}
	return buf
}

func (tlv *AssocTypeList) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *AssocTypeList) Type() TLVType {
	return TLVAssocTypeList
}

func (tlv *AssocTypeList) Len() uint16 {
	l := uint16(len(tlv.AssocTypes)) * 2
	padding := uint16(0)
	if l%4 != 0 {
		padding = 2
	}
	return TLVHeaderLength + l + padding
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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLVSRPolicyCPathIDValueLength)
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

func (tlv *SRPolicyCandidatePathIdentifier) Type() TLVType {
	return TLVSRPolicyCPathID
}

func (tlv *SRPolicyCandidatePathIdentifier) Len() uint16 {
	return TLVHeaderLength + TLVSRPolicyCPathIDValueLength
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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, TLVSRPolicyCPathPreferenceValueLength)
	buf = append(buf, length...)

	preference := make([]uint8, 4)
	binary.BigEndian.PutUint32(preference, tlv.Preference)
	buf = append(buf, preference...)

	return buf
}

func (tlv *SRPolicyCandidatePathPreference) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *SRPolicyCandidatePathPreference) Type() TLVType {
	return TLVSRPolicyCPathPreference
}

func (tlv *SRPolicyCandidatePathPreference) Len() uint16 {
	return TLVHeaderLength + TLVSRPolicyCPathPreferenceValueLength
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
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]uint8, 2)
	binary.BigEndian.PutUint16(length, uint16(TLVColor))
	buf = append(buf, length...)

	color := make([]uint8, 4)
	binary.BigEndian.PutUint32(color, tlv.Color)
	buf = append(buf, color...)

	return buf
}

func (tlv *Color) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *Color) Type() TLVType {
	return TLVColor
}

func (tlv *Color) Len() uint16 {
	return TLVHeaderLength + TLVColorValueLength
}

type UndefinedTLV struct {
	Typ    TLVType
	Length uint16
	Value  []uint8
}

func (tlv *UndefinedTLV) DecodeFromBytes(data []uint8) error {
	tlv.Typ = TLVType(binary.BigEndian.Uint16(data[0:2]))
	tlv.Length = binary.BigEndian.Uint16(data[2:4])

	tlv.Value = data[4 : 4+tlv.Length]
	return nil
}

func (tlv *UndefinedTLV) Serialize() []uint8 {
	bytePCEPTLV := []uint8{}

	byteTLVType := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTLVType, uint16(tlv.Typ))
	bytePCEPTLV = append(bytePCEPTLV, byteTLVType...) // Type (2byte)

	byteTLVLength := make([]uint8, 2)
	binary.BigEndian.PutUint16(byteTLVLength, tlv.Length)
	bytePCEPTLV = append(bytePCEPTLV, byteTLVLength...) // Length (2byte)

	bytePCEPTLV = append(bytePCEPTLV, tlv.Value...) // Value (Length byte)
	if padding := tlv.Length % 4; padding != 0 {
		bytePadding := make([]uint8, 4-padding)
		bytePCEPTLV = append(bytePCEPTLV, bytePadding...)
	}
	return bytePCEPTLV
}

func (tlv *UndefinedTLV) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return nil
}

func (tlv *UndefinedTLV) Type() TLVType {
	return tlv.Typ
}

func (tlv *UndefinedTLV) Len() uint16 {
	padding := uint16(0)
	if tlv.Length%4 != 0 {
		padding = (4 - tlv.Length%4)
	}
	return TLVHeaderLength + tlv.Length + padding
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

	if createTLV, found := tlvMap[TLVType(tlvType)]; found {
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
