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
	"unicode/utf8"

	"go.uber.org/zap/zapcore"
)

type TLVType uint16

// PCEP TLV types
const (
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

// IP Length
const (
	IPv4AddrLen = 4
	IPv6AddrLen = 16
)

const (
	TLVTypeOffset   = 0
	TLVLengthOffset = 2
	TLVValueOffset  = 4
)

// TLV Alignment (4 bytes)
const TLVAlignment = 4

// TLV value lengths, excluding the 4-byte TLV header (type + length)
const (
	TLVStatefulPCECapabilityValueLength     uint16 = 4
	TLVIPv4LSPIdentifiersValueLength        uint16 = 16
	TLVIPv6LSPIdentifiersValueLength        uint16 = 52
	TLVLSPDBVersionValueLength              uint16 = 8
	TLVSRPCECapabilityValueLength           uint16 = 4
	TLVPathSetupTypeValueLength             uint16 = 4
	TLVExtendedAssociationIDIPv4ValueLength uint16 = 8
	TLVExtendedAssociationIDIPv6ValueLength uint16 = 20
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

// Cisco specific SubTLV length
const (
	SubTLVColorCiscoValueLength      uint16 = 4
	SubTLVPreferenceCiscoValueLength uint16 = 4
)

type TLVInterface interface {
	DecodeFromBytes(data []byte) error
	Serialize() []byte
	MarshalLogObject(enc zapcore.ObjectEncoder) error
	Type() TLVType
	Len() uint16 // Total length of Type, Length, and Value
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
	TLVSRPolicyCPathID:         func() TLVInterface { return &SRPolicyCandidatePathIdentifier{} },
	TLVSRPolicyCPathPreference: func() TLVInterface { return &SRPolicyCandidatePathPreference{} },
	TLVColor:                   func() TLVInterface { return &Color{} },
}

type StatefulPCECapability struct {
	LSPUpdateCapability            bool
	IncludeDBVersion               bool
	LSPInstantiationCapability     bool
	TriggeredResync                bool
	DeltaLSPSyncCapability         bool
	TriggeredInitialSync           bool
	P2mpCapability                 bool
	P2mpLSPUpdateCapability        bool
	P2mpLSPInstantiationCapability bool
	LSPSchedulingCapability        bool
	PdLSPCapability                bool
	ColorCapability                bool
	PathRecomputationCapability    bool
	StrictPathCapability           bool
	Relax                          bool
}

const (
	LSPUpdateCapabilityBit         uint32 = 1 << 0  // bit 31 (RFC 8231)
	IncludeDBVersionCapabilityBit  uint32 = 1 << 1  // bit 30 (RFC 8232)
	LSPInstantiationCapabilityBit  uint32 = 1 << 2  // bit 29 (RFC 8281)
	TriggeredResyncCapabilityBit   uint32 = 1 << 3  // bit 28 (RFC 8232)
	DeltaLSPSyncCapabilityBit      uint32 = 1 << 4  // bit 27 (RFC 8232)
	TriggeredInitialSyncBit        uint32 = 1 << 5  // bit 26 (RFC 8232)
	P2mpCapabilityBit              uint32 = 1 << 6  // bit 25 (RFC 8623)
	P2mpLSPUpdateBit               uint32 = 1 << 7  // bit 24 (RFC 8623)
	P2mpLSPInstantiationBit        uint32 = 1 << 8  // bit 23 (RFC 8623)
	LSPSchedulingCapabilityBit     uint32 = 1 << 9  // bit 22 (RFC 8934)
	PdLSPCapabilityBit             uint32 = 1 << 10 // bit 21 (RFC 8934)
	ColorCapabilityBit             uint32 = 1 << 11 // bit 20 (RFC 9863)
	PathRecomputationCapabilityBit uint32 = 1 << 12 // bit 19 (draft-ietf-pce-circuit-style-pcep-extensions)
	StrictPathCapabilityBit        uint32 = 1 << 13 // bit 18 (draft-ietf-pce-circuit-style-pcep-extensions)
	RelaxBit                       uint32 = 1 << 14 // bit 17 (RFC 9753)
)

const definedStatefulPCEFlagsMask uint32 = LSPUpdateCapabilityBit |
	IncludeDBVersionCapabilityBit |
	LSPInstantiationCapabilityBit |
	TriggeredResyncCapabilityBit |
	DeltaLSPSyncCapabilityBit |
	TriggeredInitialSyncBit |
	ColorCapabilityBit

func (tlv *StatefulPCECapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("StatefulPCECapability: %w", err)
	}

	if valueLen != int(TLVStatefulPCECapabilityValueLength) {
		return fmt.Errorf("StatefulPCECapability: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	flags := binary.BigEndian.Uint32(value[:TLVStatefulPCECapabilityValueLength])
	tlv.ExtractCapabilities(flags)

	return nil
}

func (tlv *StatefulPCECapability) Serialize() []byte {
	flags := tlv.SetFlags() & definedStatefulPCEFlagsMask

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVStatefulPCECapabilityValueLength),
		Uint32ToByteSlice(flags),
	)
}

func (tlv *StatefulPCECapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddBool("lspUpdateCapability", tlv.LSPUpdateCapability)
	enc.AddBool("includeDBVersion", tlv.IncludeDBVersion)
	enc.AddBool("lspInstantiationCapability", tlv.LSPInstantiationCapability)
	enc.AddBool("triggeredResync", tlv.TriggeredResync)
	enc.AddBool("deltaLSPSyncCapability", tlv.DeltaLSPSyncCapability)
	enc.AddBool("triggeredInitialSync", tlv.TriggeredInitialSync)
	enc.AddBool("colorCapability", tlv.ColorCapability)

	return nil
}

func (tlv *StatefulPCECapability) Type() TLVType {
	return TLVStatefulPCECapability
}

func (tlv *StatefulPCECapability) Len() uint16 {
	return TLVValueOffset + TLVStatefulPCECapabilityValueLength
}

func (tlv *StatefulPCECapability) ExtractCapabilities(flags uint32) {
	tlv.LSPUpdateCapability = flags&LSPUpdateCapabilityBit != 0
	tlv.IncludeDBVersion = flags&IncludeDBVersionCapabilityBit != 0
	tlv.LSPInstantiationCapability = flags&LSPInstantiationCapabilityBit != 0
	tlv.TriggeredResync = flags&TriggeredResyncCapabilityBit != 0
	tlv.DeltaLSPSyncCapability = flags&DeltaLSPSyncCapabilityBit != 0
	tlv.TriggeredInitialSync = flags&TriggeredInitialSyncBit != 0
	tlv.ColorCapability = flags&ColorCapabilityBit != 0
}

func (tlv *StatefulPCECapability) SetFlags() uint32 {
	var flags uint32
	flags = SetBit(flags, LSPUpdateCapabilityBit, tlv.LSPUpdateCapability)
	flags = SetBit(flags, IncludeDBVersionCapabilityBit, tlv.IncludeDBVersion)
	flags = SetBit(flags, LSPInstantiationCapabilityBit, tlv.LSPInstantiationCapability)
	flags = SetBit(flags, TriggeredResyncCapabilityBit, tlv.TriggeredResync)
	flags = SetBit(flags, DeltaLSPSyncCapabilityBit, tlv.DeltaLSPSyncCapability)
	flags = SetBit(flags, TriggeredInitialSyncBit, tlv.TriggeredInitialSync)
	flags = SetBit(flags, ColorCapabilityBit, tlv.ColorCapability)

	return flags
}

func (tlv *StatefulPCECapability) CapStrings() []string {
	ret := []string{"Stateful"}

	if tlv.LSPUpdateCapability {
		ret = append(ret, "Update")
	}
	if tlv.IncludeDBVersion {
		ret = append(ret, "Include-DB-Ver")
	}
	if tlv.LSPInstantiationCapability {
		ret = append(ret, "Instantiation")
	}
	if tlv.TriggeredResync {
		ret = append(ret, "Triggered-Resync")
	}
	if tlv.DeltaLSPSyncCapability {
		ret = append(ret, "Delta-LSP-Sync")
	}
	if tlv.TriggeredInitialSync {
		ret = append(ret, "Triggered-Initial-Sync")
	}
	if tlv.ColorCapability {
		ret = append(ret, "Color")
	}

	return ret
}

func NewStatefulPCECapability(flags uint32) *StatefulPCECapability {
	tlv := &StatefulPCECapability{}
	tlv.ExtractCapabilities(flags)
	return tlv
}

type SymbolicPathName struct {
	Name string
}

func (tlv *SymbolicPathName) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("SymbolicPathName: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if !utf8.Valid(value) {
		return fmt.Errorf("SymbolicPathName: invalid UTF-8")
	}

	tlv.Name = string(value)
	return nil
}

func (tlv *SymbolicPathName) Serialize() []byte {
	value := []byte(tlv.Name)
	padding := (TLVAlignment - (len(value) % TLVAlignment)) % TLVAlignment
	value = append(value, make([]byte, padding)...)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(uint16(len(tlv.Name))),
		value,
	)
}

func (tlv *SymbolicPathName) Type() TLVType {
	return TLVSymbolicPathName
}

func (tlv *SymbolicPathName) Len() uint16 {
	length := uint16(len(tlv.Name))
	padding := (TLVAlignment - (length % TLVAlignment)) % TLVAlignment

	return TLVValueOffset + length + padding
}

func (tlv *SymbolicPathName) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("symbolicPathName", tlv.Name)
	return nil
}

func NewSymbolicPathName(name string) *SymbolicPathName {
	return &SymbolicPathName{Name: name}
}

type IPv4LSPIdentifiers struct {
	IPv4TunnelSenderAddress   netip.Addr
	IPv4TunnelEndpointAddress netip.Addr
	LSPID                     uint16
	TunnelID                  uint16
	ExtendedTunnelID          uint32
}

const (
	IPv4SenderOffset      = 0
	IPv4LSPIDOffset       = 4
	IPv4TunnelIDOffset    = 6
	IPv4ExtTunnelIDOffset = 8
	IPv4TunnelEPOffset    = 12
)

func (tlv *IPv4LSPIdentifiers) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("IPv4LSPIdentifiers: %w", err)
	}

	if valueLen != int(TLVIPv4LSPIdentifiersValueLength) {
		return fmt.Errorf("IPv4LSPIdentifiers: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	// ok (second return value) is ignored because slice length is guaranteed by decodeTLVLength
	addr, _ := netip.AddrFromSlice(value[IPv4SenderOffset:IPv4LSPIDOffset])
	tlv.IPv4TunnelSenderAddress = addr

	tlv.LSPID = binary.BigEndian.Uint16(value[IPv4LSPIDOffset:IPv4TunnelIDOffset])
	tlv.TunnelID = binary.BigEndian.Uint16(value[IPv4TunnelIDOffset:IPv4ExtTunnelIDOffset])
	tlv.ExtendedTunnelID = binary.BigEndian.Uint32(value[IPv4ExtTunnelIDOffset:IPv4TunnelEPOffset])

	// ok (second return value) is ignored because slice length is guaranteed by decodeTLVLength
	addr, _ = netip.AddrFromSlice(value[IPv4TunnelEPOffset : IPv4TunnelEPOffset+IPv4AddrLen])
	tlv.IPv4TunnelEndpointAddress = addr

	return nil
}

func (tlv *IPv4LSPIdentifiers) Serialize() []byte {
	value := make([]byte, TLVIPv4LSPIdentifiersValueLength)

	copy(value[IPv4SenderOffset:IPv4LSPIDOffset], tlv.IPv4TunnelSenderAddress.AsSlice())
	binary.BigEndian.PutUint16(value[IPv4LSPIDOffset:IPv4TunnelIDOffset], tlv.LSPID)
	binary.BigEndian.PutUint16(value[IPv4TunnelIDOffset:IPv4ExtTunnelIDOffset], tlv.TunnelID)
	binary.BigEndian.PutUint32(value[IPv4ExtTunnelIDOffset:IPv4TunnelEPOffset], tlv.ExtendedTunnelID)
	copy(value[IPv4TunnelEPOffset:IPv4TunnelEPOffset+IPv4AddrLen], tlv.IPv4TunnelEndpointAddress.AsSlice())

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVIPv4LSPIdentifiersValueLength),
		value,
	)
}

func (tlv *IPv4LSPIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	if tlv.IPv4TunnelSenderAddress.IsValid() {
		enc.AddString("ipv4TunnelSenderAddress", tlv.IPv4TunnelSenderAddress.String())
	}
	if tlv.IPv4TunnelEndpointAddress.IsValid() {
		enc.AddString("ipv4TunnelEndpointAddress", tlv.IPv4TunnelEndpointAddress.String())
	}

	enc.AddUint16("lspID", tlv.LSPID)
	enc.AddUint16("tunnelID", tlv.TunnelID)
	enc.AddUint32("extendedTunnelID", tlv.ExtendedTunnelID)

	return nil
}

func (tlv *IPv4LSPIdentifiers) Type() TLVType {
	return TLVIPv4LSPIdentifiers
}

func (tlv *IPv4LSPIdentifiers) Len() uint16 {
	return TLVValueOffset + TLVIPv4LSPIdentifiersValueLength
}

func NewIPv4LSPIdentifiers(senderAddr, endpointAddr netip.Addr, lspID, tunnelID uint16, extendedTunnelID uint32) *IPv4LSPIdentifiers {
	return &IPv4LSPIdentifiers{
		IPv4TunnelSenderAddress:   senderAddr,
		IPv4TunnelEndpointAddress: endpointAddr,
		LSPID:                     lspID,
		TunnelID:                  tunnelID,
		ExtendedTunnelID:          extendedTunnelID,
	}
}

type IPv6LSPIdentifiers struct {
	IPv6TunnelSenderAddress   netip.Addr
	IPv6TunnelEndpointAddress netip.Addr
	LSPID                     uint16
	TunnelID                  uint16
	ExtendedTunnelID          [16]byte
}

const (
	// IPv6 LSP Identifiers
	IPv6SenderOffset           = 0
	IPv6LSPIDOffset            = 16
	IPv6TunnelIDOffset         = 18
	IPv6ExtendedTunnelIDOffset = 20
	IPv6TunnelEPOffset         = 36
)

func (tlv *IPv6LSPIdentifiers) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("IPv6LSPIdentifiers: %w", err)
	}

	if valueLen != int(TLVIPv6LSPIdentifiersValueLength) {
		return fmt.Errorf("IPv6LSPIdentifiers: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	// ok (second return value) is ignored because slice length is guaranteed by decodeTLVLength
	addr, _ := netip.AddrFromSlice(value[IPv6SenderOffset : IPv6SenderOffset+IPv6AddrLen])
	tlv.IPv6TunnelSenderAddress = addr

	tlv.LSPID = binary.BigEndian.Uint16(value[IPv6LSPIDOffset:IPv6TunnelIDOffset])
	tlv.TunnelID = binary.BigEndian.Uint16(value[IPv6TunnelIDOffset:IPv6ExtendedTunnelIDOffset])
	copy(tlv.ExtendedTunnelID[:], value[IPv6ExtendedTunnelIDOffset:IPv6TunnelEPOffset])

	// ok (second return value) is ignored because slice length is guaranteed by decodeTLVLength
	addr, _ = netip.AddrFromSlice(value[IPv6TunnelEPOffset : IPv6TunnelEPOffset+IPv6AddrLen])
	tlv.IPv6TunnelEndpointAddress = addr

	return nil
}

func (tlv *IPv6LSPIdentifiers) Serialize() []byte {
	value := make([]byte, TLVIPv6LSPIdentifiersValueLength)

	copy(value[IPv6SenderOffset:IPv6SenderOffset+IPv6AddrLen], tlv.IPv6TunnelSenderAddress.AsSlice())
	binary.BigEndian.PutUint16(value[IPv6LSPIDOffset:IPv6TunnelIDOffset], tlv.LSPID)
	binary.BigEndian.PutUint16(value[IPv6TunnelIDOffset:IPv6ExtendedTunnelIDOffset], tlv.TunnelID)
	copy(value[IPv6ExtendedTunnelIDOffset:IPv6TunnelEPOffset], tlv.ExtendedTunnelID[:])
	copy(value[IPv6TunnelEPOffset:IPv6TunnelEPOffset+IPv6AddrLen], tlv.IPv6TunnelEndpointAddress.AsSlice())

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVIPv6LSPIdentifiersValueLength),
		value,
	)
}

func (tlv *IPv6LSPIdentifiers) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	if tlv.IPv6TunnelSenderAddress.IsValid() {
		enc.AddString("ipv6TunnelSenderAddress", tlv.IPv6TunnelSenderAddress.String())
	}
	if tlv.IPv6TunnelEndpointAddress.IsValid() {
		enc.AddString("ipv6TunnelEndpointAddress", tlv.IPv6TunnelEndpointAddress.String())
	}

	enc.AddUint16("lspID", tlv.LSPID)
	enc.AddUint16("tunnelID", tlv.TunnelID)
	enc.AddString("extendedTunnelID", fmt.Sprintf("%x", tlv.ExtendedTunnelID[:]))

	return nil
}

func (tlv *IPv6LSPIdentifiers) Type() TLVType {
	return TLVIPv6LSPIdentifiers
}

func (tlv *IPv6LSPIdentifiers) Len() uint16 {
	return TLVValueOffset + TLVIPv6LSPIdentifiersValueLength
}

func NewIPv6LSPIdentifiers(senderAddr, endpointAddr netip.Addr, lspID, tunnelID uint16, extendedTunnelID [16]byte) *IPv6LSPIdentifiers {
	return &IPv6LSPIdentifiers{
		IPv6TunnelSenderAddress:   senderAddr,
		IPv6TunnelEndpointAddress: endpointAddr,
		LSPID:                     lspID,
		TunnelID:                  tunnelID,
		ExtendedTunnelID:          extendedTunnelID,
	}
}

type LSPDBVersion struct {
	VersionNumber uint64
}

func (tlv *LSPDBVersion) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("LSPDBVersion: %w", err)
	}

	if valueLen != int(TLVLSPDBVersionValueLength) {
		return fmt.Errorf("LSPDBVersion: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset:]
	tlv.VersionNumber = binary.BigEndian.Uint64(value)

	return nil
}

func (tlv *LSPDBVersion) Serialize() []byte {
	buf := []byte{}

	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, TLVLSPDBVersionValueLength)
	buf = append(buf, length...)

	val := make([]byte, TLVLSPDBVersionValueLength)
	binary.BigEndian.PutUint64(val, tlv.VersionNumber)

	buf = append(buf, val...)
	return buf
}

func (tlv *LSPDBVersion) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint64("versionNumber", tlv.VersionNumber)
	return nil
}

func (tlv *LSPDBVersion) Type() TLVType {
	return TLVLSPDBVersion
}

func (tlv *LSPDBVersion) Len() uint16 {
	return TLVValueOffset + TLVLSPDBVersionValueLength
}

func (tlv *LSPDBVersion) CapStrings() []string {
	return []string{"LSP-DB-VERSION"}
}

func NewLSPDBVersion(version uint64) *LSPDBVersion {
	return &LSPDBVersion{
		VersionNumber: version,
	}
}

type SRPCECapability struct {
	HasUnlimitedMaxSIDDepth bool
	IsNAISupported          bool
	MaximumSidDepth         uint8
}

const (
	UnlimitedMaximumSIDDepthFlag byte = 0x01
	NAISupportedFlag             byte = 0x02
)

const (
	SRPCECapabilityFlagsOffset = 0
	SRPCECapabilityMSDOffset   = 1
)

func (tlv *SRPCECapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("SRPCECapability: %w", err)
	}

	if valueLen != int(TLVSRPCECapabilityValueLength) {
		return fmt.Errorf("SRPCECapability: invalid value length %d", valueLen)
	}

	val := data[TLVValueOffset:]

	flags := val[SRPCECapabilityFlagsOffset]
	tlv.HasUnlimitedMaxSIDDepth = IsBitSet(flags, UnlimitedMaximumSIDDepthFlag)
	tlv.IsNAISupported = IsBitSet(flags, NAISupportedFlag)
	tlv.MaximumSidDepth = val[SRPCECapabilityMSDOffset]

	return nil
}

func (tlv *SRPCECapability) Serialize() []byte {
	value := make([]byte, TLVSRPCECapabilityValueLength)

	value[SRPCECapabilityFlagsOffset] = SetBit(value[SRPCECapabilityFlagsOffset], UnlimitedMaximumSIDDepthFlag, tlv.HasUnlimitedMaxSIDDepth)
	value[SRPCECapabilityFlagsOffset] = SetBit(value[SRPCECapabilityFlagsOffset], NAISupportedFlag, tlv.IsNAISupported)
	value[SRPCECapabilityMSDOffset] = tlv.MaximumSidDepth

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVSRPCECapabilityValueLength),
		value,
	)
}

func (tlv *SRPCECapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddBool("unlimited_max_sid_depth", tlv.HasUnlimitedMaxSIDDepth)
	enc.AddBool("nai_is_supported", tlv.IsNAISupported)
	enc.AddUint8("maximum_sid_depth", tlv.MaximumSidDepth)
	return nil
}

func (tlv *SRPCECapability) Type() TLVType {
	return TLVSRPCECapability
}

func (tlv *SRPCECapability) Len() uint16 {
	return TLVValueOffset + TLVSRPCECapabilityValueLength
}

func (tlv *SRPCECapability) CapStrings() []string {
	var ret []string
	if tlv.HasUnlimitedMaxSIDDepth {
		ret = append(ret, "Unlimited-SID-Depth")
	}
	if tlv.IsNAISupported {
		ret = append(ret, "NAI-Supported")
	}
	return ret
}

func NewSRPCECapability(hasUnlimitedMaxSIDDepth bool, isNAISupported bool, maximumSidDepth uint8) *SRPCECapability {
	return &SRPCECapability{
		HasUnlimitedMaxSIDDepth: hasUnlimitedMaxSIDDepth,
		IsNAISupported:          isNAISupported,
		MaximumSidDepth:         maximumSidDepth,
	}
}

type Pst uint8

const (
	PathSetupTypeRSVPTE  Pst = 0x00
	PathSetupTypeSRTE    Pst = 0x01
	PathSetupTypePCECCTE Pst = 0x02
	PathSetupTypeSRv6TE  Pst = 0x03
	PathSetupTypeIPTE    Pst = 0x04
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
		var values []string
		for _, pst := range ts {
			values = append(values, fmt.Sprintf("%d", pst))
		}
		result = strings.Join(values, ",")
	}
	return []byte(result), nil
}

type PathSetupType struct {
	PathSetupType Pst
}

const PathSetupTypeValueOffset = 3

func (tlv *PathSetupType) DecodeFromBytes(data []byte) error {
	_, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("PathSetupType: %w", err)
	}

	value := data[TLVValueOffset:]
	tlv.PathSetupType = Pst(value[PathSetupTypeValueOffset])

	return nil
}

func (tlv *PathSetupType) Serialize() []byte {
	value := make([]byte, TLVPathSetupTypeValueLength)
	value[PathSetupTypeValueOffset] = byte(tlv.PathSetupType)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVPathSetupTypeValueLength),
		value,
	)
}

func (tlv *PathSetupType) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("pathSetupType", tlv.PathSetupType.String())
	return nil
}

func (tlv *PathSetupType) Type() TLVType {
	return TLVPathSetupType
}

func (tlv *PathSetupType) Len() uint16 {
	return TLVValueOffset + TLVPathSetupTypeValueLength
}

func NewPathSetupType(pst Pst) *PathSetupType {
	return &PathSetupType{
		PathSetupType: pst,
	}
}

type ExtendedAssociationID struct {
	Color    uint32
	Endpoint netip.Addr
}

const (
	ExtendedAssociationIDColorOffset    = 0
	ExtendedAssociationIDEndpointOffset = 4
)

func (tlv *ExtendedAssociationID) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("ExtendedAssociationID: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.Color = binary.BigEndian.Uint32(value[ExtendedAssociationIDColorOffset : ExtendedAssociationIDColorOffset+TLVColorValueLength])

	var addrBytes []byte
	switch valueLen {
	case int(TLVExtendedAssociationIDIPv4ValueLength):
		addrBytes = value[ExtendedAssociationIDEndpointOffset : ExtendedAssociationIDEndpointOffset+IPv4AddrLen]

	case int(TLVExtendedAssociationIDIPv6ValueLength):
		addrBytes = value[ExtendedAssociationIDEndpointOffset : ExtendedAssociationIDEndpointOffset+IPv6AddrLen]

	default:
		return fmt.Errorf("ExtendedAssociationID: unsupported value length %d", valueLen)
	}

	addr, _ := netip.AddrFromSlice(addrBytes)

	tlv.Endpoint = addr
	return nil
}

func (tlv *ExtendedAssociationID) Serialize() []byte {
	if !tlv.Endpoint.IsValid() {
		return nil
	}

	var length uint16
	switch {
	case tlv.Endpoint.Is4():
		length = TLVExtendedAssociationIDIPv4ValueLength
	case tlv.Endpoint.Is6():
		length = TLVExtendedAssociationIDIPv6ValueLength
	}

	value := make([]byte, length)
	binary.BigEndian.PutUint32(value[ExtendedAssociationIDColorOffset:ExtendedAssociationIDColorOffset+TLVColorValueLength], tlv.Color)
	copy(value[ExtendedAssociationIDEndpointOffset:], tlv.Endpoint.AsSlice())

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(length),
		value,
	)
}

func (tlv *ExtendedAssociationID) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint32("color", tlv.Color)

	if tlv.Endpoint.IsValid() {
		if tlv.Endpoint.Is4() {
			enc.AddString("ipv4Addr", tlv.Endpoint.String())
		} else if tlv.Endpoint.Is6() {
			enc.AddString("ipv6Addr", tlv.Endpoint.String())
		}
	}

	return nil
}

func (tlv *ExtendedAssociationID) Type() TLVType {
	return TLVExtendedAssociationID
}

func (tlv *ExtendedAssociationID) Len() uint16 {
	if tlv.Endpoint.Is4() {
		return TLVValueOffset + TLVExtendedAssociationIDIPv4ValueLength
	} else if tlv.Endpoint.Is6() {
		return TLVValueOffset + TLVExtendedAssociationIDIPv6ValueLength
	}
	return 0

}

func NewExtendedAssociationID(color uint32, endpoint netip.Addr) *ExtendedAssociationID {
	return &ExtendedAssociationID{
		Color:    color,
		Endpoint: endpoint,
	}
}

type PathSetupTypeCapability struct {
	PathSetupTypes Psts
	SubTLVs        []TLVInterface
}

const (
	PathSetupTypeCapabilityFixedPartLength = 4
	PathSetupTypeCapabilityPSTCountOffset  = 3
)

func (tlv *PathSetupTypeCapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("PathSetupTypeCapability: %w", err)
	}

	if tlv.SubTLVs == nil {
		tlv.SubTLVs = []TLVInterface{}
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if len(value) < PathSetupTypeCapabilityFixedPartLength {
		return fmt.Errorf("PathSetupTypeCapability: value too short for fixed part")
	}

	pstNum := int(value[PathSetupTypeCapabilityPSTCountOffset])

	tlv.PathSetupTypes = make([]Pst, 0, pstNum)
	for i := 0; i < pstNum; i++ {
		offset := PathSetupTypeCapabilityFixedPartLength + i
		if offset >= len(value) {
			return fmt.Errorf("PathSetupTypeCapability: value too short for PathSetupTypes entries")
		}
		tlv.PathSetupTypes = append(tlv.PathSetupTypes, Pst(value[offset]))
	}

	padded := paddedLength(uint16(pstNum), TLVAlignment)
	subTLVOffset := PathSetupTypeCapabilityFixedPartLength + padded

	subTLVData := value[subTLVOffset:]
	tlv.SubTLVs, err = DecodeTLVs(subTLVData)
	if err != nil {
		return fmt.Errorf("PathSetupTypeCapability: %w", err)
	}
	if tlv.SubTLVs == nil {
		tlv.SubTLVs = []TLVInterface{}
	}

	return nil
}

func (tlv *PathSetupTypeCapability) Serialize() []byte {
	buf := []byte{}

	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	numOfPst := uint16(len(tlv.PathSetupTypes))
	paddedPSTLen := tlv.paddedPSTLength()

	length := uint16(PathSetupTypeCapabilityFixedPartLength) + paddedPSTLen
	for _, subTLV := range tlv.SubTLVs {
		length += subTLV.Len()
	}

	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)
	buf = append(buf, lengthBytes...)

	val := make([]byte, PathSetupTypeCapabilityFixedPartLength+paddedPSTLen)
	val[PathSetupTypeCapabilityPSTCountOffset] = byte(numOfPst)
	for i, pst := range tlv.PathSetupTypes {
		val[PathSetupTypeCapabilityFixedPartLength+i] = byte(pst)
	}

	buf = append(buf, val...)
	for _, subTLV := range tlv.SubTLVs {
		buf = append(buf, subTLV.Serialize()...)
	}

	return buf
}

func (tlv *PathSetupTypeCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	pstStrings := make([]string, len(tlv.PathSetupTypes))
	for i, pst := range tlv.PathSetupTypes {
		pstStrings[i] = pst.String()
	}
	_ = enc.AddArray("pathSetupTypes", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		for _, s := range pstStrings {
			ae.AppendString(s)
		}
		return nil
	}))

	subTLVTypes := make([]string, len(tlv.SubTLVs))
	for i, stlv := range tlv.SubTLVs {
		subTLVTypes[i] = fmt.Sprintf("0x%04x", stlv.Type())
	}
	_ = enc.AddArray("subTLVs", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		for _, s := range subTLVTypes {
			ae.AppendString(s)
		}
		return nil
	}))

	return nil
}

func (tlv *PathSetupTypeCapability) Type() TLVType {
	return TLVPathSetupTypeCapability
}

func (tlv *PathSetupTypeCapability) Len() uint16 {
	length := uint16(PathSetupTypeCapabilityFixedPartLength)
	length += tlv.paddedPSTLength()

	for _, subTLV := range tlv.SubTLVs {
		length += subTLV.Len()
	}

	return TLVValueOffset + length
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

func (tlv *PathSetupTypeCapability) paddedPSTLength() uint16 {
	numOfPst := uint16(len(tlv.PathSetupTypes))
	return paddedLength(numOfPst, TLVAlignment)
}

type AssocType uint16

const (
	AssocTypePathProtectionAssociation              AssocType = 0x01
	AssocTypeDisjointAssociation                    AssocType = 0x02
	AssocTypePolicyAssociation                      AssocType = 0x03
	AssocTypeSingleSidedBidirectionalLSPAssociation AssocType = 0x04
	AssocTypeDoubleSidedBidirectionalLSPAssociation AssocType = 0x05
	AssocTypeSRPolicyAssociation                    AssocType = 0x06
	AssocTypeVnAssociationType                      AssocType = 0x07
)

var assocTypeNames = map[AssocType]string{
	AssocTypePathProtectionAssociation:              "Path Protection Association",
	AssocTypeDisjointAssociation:                    "Disjoint Association",
	AssocTypePolicyAssociation:                      "Policy Association",
	AssocTypeSingleSidedBidirectionalLSPAssociation: "Single Sided Bidirectional LSP Association",
	AssocTypeDoubleSidedBidirectionalLSPAssociation: "Double Sided Bidirectional LSP Association",
	AssocTypeSRPolicyAssociation:                    "SR Policy Association",
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

func (tlv *AssocTypeList) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("AssocTypeList: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if len(value)%2 != 0 {
		return fmt.Errorf("AssocTypeList: value length not even, cannot contain 16-bit AssocType entries")
	}

	assocNum := len(value) / 2
	tlv.AssocTypes = make([]AssocType, assocNum)
	for i := 0; i < assocNum; i++ {
		tlv.AssocTypes[i] = AssocType(binary.BigEndian.Uint16(value[2*i : 2*i+2]))
	}

	return nil
}

func (tlv *AssocTypeList) Serialize() []byte {
	buf := []byte{}

	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := uint16(len(tlv.AssocTypes)) * 2
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, length)
	buf = append(buf, lengthBytes...)

	for _, at := range tlv.AssocTypes {
		binAt := make([]byte, 2)
		binary.BigEndian.PutUint16(binAt, uint16(at))
		buf = append(buf, binAt...)
	}
	if length%4 != 0 {
		pad := make([]byte, 4-(length%4))
		buf = append(buf, pad...)
	}
	return buf
}

func (tlv *AssocTypeList) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	_ = enc.AddArray("assocTypes", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		for _, at := range tlv.AssocTypes {
			ae.AppendString(at.String())
		}
		return nil
	}))

	return nil
}

func (tlv *AssocTypeList) Type() TLVType {
	return TLVAssocTypeList
}

func (tlv *AssocTypeList) Len() uint16 {
	length := uint16(len(tlv.AssocTypes)) * 2
	padding := uint16(0)
	if length%4 != 0 {
		padding = 2
	}
	return TLVValueOffset + length + padding
}

func (tlv *AssocTypeList) CapStrings() []string {
	return []string{}
}

type SRPolicyCandidatePathIdentifier struct {
	OriginatorAddr netip.Addr // After DecodeFromBytes, IPv4 addresses are stored as native IPv4 (upper 12 bytes zero), not IPv4-mapped IPv6
}

func (tlv *SRPolicyCandidatePathIdentifier) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("SRPolicyCandidatePathIdentifier: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if len(value) < 8+16 {
		return fmt.Errorf("SRPolicyCandidatePathIdentifier: value too short for OriginatorAddr")
	}

	addrBytes := value[8 : 8+16]

	if isIPv4Bytes(addrBytes) {
		var v4 [4]byte
		copy(v4[:], addrBytes[12:])
		tlv.OriginatorAddr = netip.AddrFrom4(v4)
	} else {
		tlv.OriginatorAddr = netip.AddrFrom16(*(*[16]byte)(addrBytes))
	}

	return nil
}

func (tlv *SRPolicyCandidatePathIdentifier) Serialize() []byte {
	buf := make([]byte, 0, TLVValueOffset+TLVSRPolicyCPathIDValueLength)

	buf = append(buf, Uint16ToByteSlice(tlv.Type())...)
	buf = append(buf, Uint16ToByteSlice(TLVSRPolicyCPathIDValueLength)...)
	buf = append(buf, 0x0a, 0x00, 0x00, 0x00) // protocol origin (1 byte) + reserved (3 bytes)
	buf = append(buf, 0x00, 0x00, 0x00, 0x00) // originator AS (4 bytes)

	addr := tlv.OriginatorAddr

	if addr.Is4() {
		// IPv4 → IPv4-mapped IPv6
		ipv4 := addr.As4()
		var addr16 [16]byte
		copy(addr16[12:], ipv4[:])
		buf = append(buf, addr16[:]...)
	} else {
		addr16 := addr.As16()
		buf = append(buf, addr16[:]...)
	}

	buf = append(buf, Uint32ToByteSlice(1)...) // discriminator (4 bytes)

	return buf
}

func (tlv *SRPolicyCandidatePathIdentifier) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("originatorAddr", tlv.OriginatorAddr.String())
	return nil
}

func (tlv *SRPolicyCandidatePathIdentifier) Type() TLVType {
	return TLVSRPolicyCPathID
}

func (tlv *SRPolicyCandidatePathIdentifier) Len() uint16 {
	return TLVValueOffset + TLVSRPolicyCPathIDValueLength
}

type SRPolicyCandidatePathPreference struct {
	Preference uint32
}

func (tlv *SRPolicyCandidatePathPreference) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("SRPolicyCandidatePathPreference: %w", err)
	}

	if valueLen != 4 {
		return fmt.Errorf("SRPolicyCandidatePathPreference: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.Preference = binary.BigEndian.Uint32(value)
	return nil
}

func (tlv *SRPolicyCandidatePathPreference) Serialize() []byte {
	buf := []byte{}

	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, TLVSRPolicyCPathPreferenceValueLength)
	buf = append(buf, length...)

	preference := make([]byte, 4)
	binary.BigEndian.PutUint32(preference, tlv.Preference)
	buf = append(buf, preference...)

	return buf
}

func (tlv *SRPolicyCandidatePathPreference) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint32("preference", tlv.Preference)
	return nil
}

func (tlv *SRPolicyCandidatePathPreference) Type() TLVType {
	return TLVSRPolicyCPathPreference
}

func (tlv *SRPolicyCandidatePathPreference) Len() uint16 {
	return TLVValueOffset + TLVSRPolicyCPathPreferenceValueLength
}

type Color struct {
	Color uint32
}

func (tlv *Color) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("Color: %w", err)
	}

	if valueLen != 4 {
		return fmt.Errorf("Color: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.Color = binary.BigEndian.Uint32(value)
	return nil
}

func (tlv *Color) Serialize() []byte {
	buf := []byte{}

	typ := make([]byte, 2)
	binary.BigEndian.PutUint16(typ, uint16(tlv.Type()))
	buf = append(buf, typ...)

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, TLVColorValueLength)
	buf = append(buf, length...)

	color := make([]byte, 4)
	binary.BigEndian.PutUint32(color, tlv.Color)
	buf = append(buf, color...)

	return buf
}

func (tlv *Color) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint32("color", tlv.Color)
	return nil
}

func (tlv *Color) Type() TLVType {
	return TLVColor
}

func (tlv *Color) Len() uint16 {
	return TLVValueOffset + TLVColorValueLength
}

type UndefinedTLV struct {
	Typ    TLVType
	Length uint16
	Value  []byte
}

func (tlv *UndefinedTLV) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data)
	if err != nil {
		return fmt.Errorf("UndefinedTLV: %w", err)
	}

	tlv.Typ = TLVType(binary.BigEndian.Uint16(data[TLVTypeOffset:TLVLengthOffset]))
	tlv.Length = uint16(valueLen)
	tlv.Value = data[TLVValueOffset : TLVValueOffset+valueLen]

	return nil
}

func (tlv *UndefinedTLV) Serialize() []byte {
	padding := (TLVAlignment - (tlv.Length % TLVAlignment)) % TLVAlignment

	return AppendByteSlices(
		Uint16ToByteSlice(uint16(tlv.Typ)),
		Uint16ToByteSlice(tlv.Length),
		tlv.Value,
		make([]byte, padding),
	)
}

func (tlv *UndefinedTLV) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("type", fmt.Sprintf("0x%04x", tlv.Typ))
	enc.AddUint16("length", tlv.Length)
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
	return TLVValueOffset + tlv.Length + padding
}

func (tlv *UndefinedTLV) CapStrings() []string {
	capStr := "unknown_type_" + strconv.FormatInt(int64(tlv.Typ), 10)
	return []string{capStr}
}

func (tlv *UndefinedTLV) SetLength() {
	tlv.Length = uint16(len(tlv.Value))
}

func DecodeTLV(data []byte) (TLVInterface, error) {
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

func DecodeTLVs(data []byte) ([]TLVInterface, error) {
	var tlvs []TLVInterface

	for len(data) > 0 {
		if len(data) < int(TLVValueOffset) {
			return nil, fmt.Errorf("truncated TLV header")
		}

		valueLen := int(binary.BigEndian.Uint16(data[TLVLengthOffset:TLVValueOffset]))
		totalLen := int(TLVValueOffset) + valueLen

		tlvType := binary.BigEndian.Uint16(data[TLVTypeOffset:TLVLengthOffset])
		if len(data) < totalLen {
			return nil, fmt.Errorf("truncated TLV value (type=0x%x)", tlvType)
		}

		tlv, err := DecodeTLV(data[:totalLen])
		if err != nil {
			return nil, err
		}

		tlvs = append(tlvs, tlv)

		paddedLen := (totalLen + TLVAlignment - 1) & ^(TLVAlignment - 1)
		if len(data) < paddedLen {
			return nil, fmt.Errorf("truncated TLV padding (type=0x%x)", tlvType)
		}

		data = data[paddedLen:]
	}

	return tlvs, nil
}
