// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.uber.org/zap/zapcore"
)

// TLVType is a PCEP TLV type code.
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
	TLVSRv6PCECapability                  TLVType = 0x1b
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
	TLVPathModification                   TLVType = 0x48
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
	TLVSRv6PCECapability:                  {"SRv6-PCE-CAPABILITY", "RFC9603"},
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
	TLVVirtualNetwork:                     {"VIRTUAL-NETWORK-TLV", "RFC9358"},
	TLVSrAlgorithm:                        {"SR-Algorithm", "RFC9933"},
	TLVColor:                              {"Color", "RFC9863"},
	TLVComputationPriority:                {"COMPUTATION-PRIORITY", "RFC9862"},
	TLVExplicitNullLabelPolicy:            {"EXPLICIT-NULL-LABEL-POLICY", "RFC9862"},
	TLVInvalidation:                       {"INVALIDATION", "RFC9862"},
	TLVSRPolicyCapability:                 {"SRPOLICY-CAPABILITY", "RFC9862"},
	TLVPathModification:                   {"PATH-MODIFICATION", "draft-ietf-pce-circuit-style-pcep-extensions-16"},
	TLVSRP2MPPolicyCapability:             {"SR-P2MP-POLICY-CAPABILITY", "draft-ietf-pce-sr-p2mp-policy-11"},
	TLVIPv4SrP2MPInstanceID:               {"IPV4-SR-P2MP-INSTANCE-ID", "draft-ietf-pce-sr-p2mp-policy-11"},
	TLVIPv6SrP2MPInstanceID:               {"IPV6-SR-P2MP-INSTANCE-ID", "draft-ietf-pce-sr-p2mp-policy-11"},

	TLVExtendedAssociationIDIPv4Juniper: {"EXTENDED-ASSOCIATION-ID (Juniper)", "vendor-specific"},
	TLVSRPolicyCPathIDJuniper:           {"SRPOLICY-CPATH-ID (Juniper)", "vendor-specific"},
	TLVSRPolicyCPathPreferenceJuniper:   {"SRPOLICY-CPATH-PREFERENCE (Juniper)", "vendor-specific"},
}

// String returns a human-readable representation of the TLV type.
func (t TLVType) String() string {
	if desc, ok := tlvDescriptions[t]; ok {
		return fmt.Sprintf("%s (%s)", desc.Description, desc.Reference)
	}
	return fmt.Sprintf("Unknown TLV (0x%04x)", uint16(t))
}

// Name returns the registered name of the TLV type, or "" if unregistered.
func (t TLVType) Name() string {
	if desc, ok := tlvDescriptions[t]; ok {
		return desc.Description
	}
	return ""
}

// Reference returns the defining document of the TLV type, or "" if unregistered.
func (t TLVType) Reference() string {
	if desc, ok := tlvDescriptions[t]; ok {
		return desc.Reference
	}
	return ""
}

// IPv4AddrLen is the byte length of an IPv4 address.
const IPv4AddrLen = 4

// IPv6AddrLen is the byte length of an IPv6 address.
const IPv6AddrLen = 16

// Byte offsets of the fields of a PCEP TLV. TLVValueOffset doubles as the
// length of the TLV header, since the value starts right after it.
const (
	TLVTypeOffset   = 0
	TLVLengthOffset = 2
	TLVValueOffset  = 4
)

// TLVAlignment is the alignment boundary for PCEP TLVs (4 bytes).
const TLVAlignment = 4

// TLV value lengths, excluding the 4-byte TLV header (type + length)
const (
	TLVVendorInformationMinValueLength      uint16 = 4 // Enterprise Number only, without Enterprise-Specific Information
	TLVStatefulPCECapabilityValueLength     uint16 = 4
	TLVIPv4LSPIdentifiersValueLength        uint16 = 16
	TLVIPv6LSPIdentifiersValueLength        uint16 = 52
	TLVLSPDBVersionValueLength              uint16 = 8
	TLVSRPCECapabilityValueLength           uint16 = 4
	TLVSRv6PCECapabilityValueLength         uint16 = 4
	TLVMultipathCapValueLength              uint16 = 4
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

// TLVInterface is implemented by every decodable PCEP TLV.
type TLVInterface interface {
	DecodeFromBytes(data []byte) error
	Serialize() ([]byte, error)
	MarshalLogObject(enc zapcore.ObjectEncoder) error
	Type() TLVType
	Len() int // Total serialized length of Type, Length, and Value.
}

var tlvMap = map[TLVType]func() TLVInterface{
	TLVVendorInformation:       func() TLVInterface { return &VendorInformation{} },
	TLVStatefulPCECapability:   func() TLVInterface { return &StatefulPCECapability{} },
	TLVSymbolicPathName:        func() TLVInterface { return &SymbolicPathName{} },
	TLVIPv4LSPIdentifiers:      func() TLVInterface { return &IPv4LSPIdentifiers{} },
	TLVIPv6LSPIdentifiers:      func() TLVInterface { return &IPv6LSPIdentifiers{} },
	TLVLSPDBVersion:            func() TLVInterface { return &LSPDBVersion{} },
	TLVSRPCECapability:         func() TLVInterface { return &SRPCECapability{} },
	TLVSRv6PCECapability:       func() TLVInterface { return &SRv6PCECapability{} },
	TLVMultipathCap:            func() TLVInterface { return &MultipathCapability{} },
	TLVPathSetupType:           func() TLVInterface { return &PathSetupType{} },
	TLVExtendedAssociationID:   func() TLVInterface { return &ExtendedAssociationID{} },
	TLVPathSetupTypeCapability: func() TLVInterface { return &PathSetupTypeCapability{} },
	TLVAssocTypeList:           func() TLVInterface { return &AssocTypeList{} },
	TLVSRPolicyCPathID:         func() TLVInterface { return &SRPolicyCandidatePathIdentifier{} },
	TLVSRPolicyCPathPreference: func() TLVInterface { return &SRPolicyCandidatePathPreference{} },
	TLVColor:                   func() TLVInterface { return &Color{} },

	// Juniper vendor-specific Association TLVs.
	TLVExtendedAssociationIDIPv4Juniper: func() TLVInterface { return &ExtendedAssociationIDIPv4Juniper{} },
	TLVSRPolicyCPathIDJuniper:           func() TLVInterface { return &SRPolicyCandidatePathIdentifierJuniper{} },
	TLVSRPolicyCPathPreferenceJuniper:   func() TLVInterface { return &SRPolicyCandidatePathPreferenceJuniper{} },
}

// VendorInformation represents the VENDOR-INFORMATION TLV (RFC 7470 §4).
// Enterprise-Specific Information is opaque and kept as raw bytes.
type VendorInformation struct {
	EnterpriseNumber              EnterpriseNumber
	EnterpriseSpecificInformation []byte
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *VendorInformation) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, true)
	if err != nil {
		return fmt.Errorf("VendorInformation: %w", err)
	}

	if valueLen < int(TLVVendorInformationMinValueLength) {
		return fmt.Errorf("VendorInformation: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.EnterpriseNumber = EnterpriseNumber(binary.BigEndian.Uint32(value[:TLVVendorInformationMinValueLength]))

	if info := value[TLVVendorInformationMinValueLength:]; len(info) > 0 {
		tlv.EnterpriseSpecificInformation = slices.Clone(info)
	} else {
		tlv.EnterpriseSpecificInformation = nil
	}

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *VendorInformation) Serialize() ([]byte, error) {
	length, err := tlvValueLength(tlv.valueLength())
	if err != nil {
		return nil, fmt.Errorf("VendorInformation: %w", err)
	}

	value := make([]byte, tlv.paddedValueLength())
	binary.BigEndian.PutUint32(value[:TLVVendorInformationMinValueLength], uint32(tlv.EnterpriseNumber))
	copy(value[TLVVendorInformationMinValueLength:], tlv.EnterpriseSpecificInformation)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(length),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *VendorInformation) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint32("enterpriseNumber", uint32(tlv.EnterpriseNumber))
	enc.AddString("enterprise", tlv.EnterpriseNumber.String())

	if len(tlv.EnterpriseSpecificInformation) > 0 {
		enc.AddString("enterpriseSpecificInformation", hex.EncodeToString(tlv.EnterpriseSpecificInformation))
	}

	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *VendorInformation) Type() TLVType {
	return TLVVendorInformation
}

// Len returns the wire length of the receiver.
func (tlv *VendorInformation) Len() int {
	return TLVValueOffset + tlv.paddedValueLength()
}

// CapStrings returns capability strings for the receiver.
func (tlv *VendorInformation) CapStrings() []string {
	return []string{"Vendor-Info(" + tlv.EnterpriseNumber.capLabel() + ")"}
}

func (tlv *VendorInformation) valueLength() int {
	return int(TLVVendorInformationMinValueLength) + len(tlv.EnterpriseSpecificInformation)
}

func (tlv *VendorInformation) paddedValueLength() int {
	return paddedLength(tlv.valueLength(), TLVAlignment)
}

// NewVendorInformation creates and returns a new VendorInformation.
func NewVendorInformation(enterpriseNumber EnterpriseNumber, enterpriseSpecificInformation []byte) *VendorInformation {
	return &VendorInformation{
		EnterpriseNumber:              enterpriseNumber,
		EnterpriseSpecificInformation: enterpriseSpecificInformation,
	}
}

// StatefulPCECapability represents the STATEFUL-PCE-CAPABILITY TLV and its
// supported stateful PCE operations (RFC 8231 §7.1.1 and its extensions).
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

// Flag bits of the STATEFUL-PCE-CAPABILITY TLV, as masks against the 32-bit
// Flags field. Trailing comments give the bit position and defining document;
// RFC bit positions are numbered from the most significant bit.
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

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *StatefulPCECapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
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

// Serialize encodes the receiver into bytes.
func (tlv *StatefulPCECapability) Serialize() ([]byte, error) {
	flags := tlv.SetFlags() & definedStatefulPCEFlagsMask

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVStatefulPCECapabilityValueLength),
		Uint32ToByteSlice(flags),
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
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

// Type returns the TLV type of the receiver.
func (tlv *StatefulPCECapability) Type() TLVType {
	return TLVStatefulPCECapability
}

// Len returns the wire length of the receiver.
func (tlv *StatefulPCECapability) Len() int {
	return int(TLVValueOffset + TLVStatefulPCECapabilityValueLength)
}

// ExtractCapabilities extracts capabilities from the given flags.
func (tlv *StatefulPCECapability) ExtractCapabilities(flags uint32) {
	tlv.LSPUpdateCapability = flags&LSPUpdateCapabilityBit != 0
	tlv.IncludeDBVersion = flags&IncludeDBVersionCapabilityBit != 0
	tlv.LSPInstantiationCapability = flags&LSPInstantiationCapabilityBit != 0
	tlv.TriggeredResync = flags&TriggeredResyncCapabilityBit != 0
	tlv.DeltaLSPSyncCapability = flags&DeltaLSPSyncCapabilityBit != 0
	tlv.TriggeredInitialSync = flags&TriggeredInitialSyncBit != 0
	tlv.ColorCapability = flags&ColorCapabilityBit != 0
}

// SetFlags sets and returns flags from the receiver's fields.
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

// CapStrings returns capability strings for the receiver.
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

// NewStatefulPCECapability creates and returns a new StatefulPCECapability.
func NewStatefulPCECapability(flags uint32) *StatefulPCECapability {
	tlv := &StatefulPCECapability{}
	tlv.ExtractCapabilities(flags)
	return tlv
}

// SymbolicPathName represents the SYMBOLIC-PATH-NAME TLV carrying the operator-visible name of an LSP (RFC 8231 §7.3.2).
type SymbolicPathName struct {
	Name string
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *SymbolicPathName) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, true)
	if err != nil {
		return fmt.Errorf("SymbolicPathName: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if !utf8.Valid(value) {
		return errors.New("SymbolicPathName: invalid UTF-8")
	}

	tlv.Name = string(value)
	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *SymbolicPathName) Serialize() ([]byte, error) {
	length, err := tlvValueLength(len(tlv.Name))
	if err != nil {
		return nil, fmt.Errorf("SymbolicPathName: %w", err)
	}

	value := []byte(tlv.Name)

	padding := (TLVAlignment - (len(value) % TLVAlignment)) % TLVAlignment
	value = append(value, make([]byte, padding)...)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(length),
		value,
	), nil
}

// Type returns the TLV type of the receiver.
func (tlv *SymbolicPathName) Type() TLVType {
	return TLVSymbolicPathName
}

// Len returns the wire length of the receiver.
func (tlv *SymbolicPathName) Len() int {
	length := len(tlv.Name)
	padding := (TLVAlignment - (length % TLVAlignment)) % TLVAlignment

	return TLVValueOffset + length + padding
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *SymbolicPathName) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("symbolicPathName", tlv.Name)
	return nil
}

// NewSymbolicPathName creates and returns a new SymbolicPathName.
func NewSymbolicPathName(name string) *SymbolicPathName {
	return &SymbolicPathName{Name: name}
}

// IPv4LSPIdentifiers represents the IPV4-LSP-IDENTIFIERS TLV, identifying
// an LSP by its IPv4 tunnel endpoints and IDs (RFC 8231 §7.3.1).
type IPv4LSPIdentifiers struct {
	IPv4TunnelSenderAddress   netip.Addr
	IPv4TunnelEndpointAddress netip.Addr
	LSPID                     uint16
	TunnelID                  uint16
	ExtendedTunnelID          uint32
}

// Byte offsets of the fields within the IPV4-LSP-IDENTIFIERS TLV value.
const (
	IPv4SenderOffset      = 0
	IPv4LSPIDOffset       = 4
	IPv4TunnelIDOffset    = 6
	IPv4ExtTunnelIDOffset = 8
	IPv4TunnelEPOffset    = 12
)

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *IPv4LSPIdentifiers) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
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

// Serialize encodes the receiver into bytes.
func (tlv *IPv4LSPIdentifiers) Serialize() ([]byte, error) {
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
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
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

// Type returns the TLV type of the receiver.
func (tlv *IPv4LSPIdentifiers) Type() TLVType {
	return TLVIPv4LSPIdentifiers
}

// Len returns the wire length of the receiver.
func (tlv *IPv4LSPIdentifiers) Len() int {
	return int(TLVValueOffset + TLVIPv4LSPIdentifiersValueLength)
}

// NewIPv4LSPIdentifiers creates and returns a new IPv4LSPIdentifiers.
func NewIPv4LSPIdentifiers(senderAddr, endpointAddr netip.Addr, lspID, tunnelID uint16, extendedTunnelID uint32) *IPv4LSPIdentifiers {
	return &IPv4LSPIdentifiers{
		IPv4TunnelSenderAddress:   senderAddr,
		IPv4TunnelEndpointAddress: endpointAddr,
		LSPID:                     lspID,
		TunnelID:                  tunnelID,
		ExtendedTunnelID:          extendedTunnelID,
	}
}

// IPv6LSPIdentifiers represents the IPV6-LSP-IDENTIFIERS TLV, identifying
// an LSP by its IPv6 tunnel endpoints and IDs (RFC 8231 §7.3.1).
type IPv6LSPIdentifiers struct {
	IPv6TunnelSenderAddress   netip.Addr
	IPv6TunnelEndpointAddress netip.Addr
	LSPID                     uint16
	TunnelID                  uint16
	ExtendedTunnelID          [16]byte
}

// Byte offsets of the fields within the IPV6-LSP-IDENTIFIERS TLV value.
const (
	IPv6SenderOffset           = 0
	IPv6LSPIDOffset            = 16
	IPv6TunnelIDOffset         = 18
	IPv6ExtendedTunnelIDOffset = 20
	IPv6TunnelEPOffset         = 36
)

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *IPv6LSPIdentifiers) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("IPv6LSPIdentifiers: %w", err)
	}

	if valueLen != int(TLVIPv6LSPIdentifiersValueLength) {
		return fmt.Errorf("IPv6LSPIdentifiers: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	// ok (second return value) is ignored because slice length is guaranteed by decodeTLVLength
	addr, _ := netip.AddrFromSlice(value[IPv6SenderOffset:IPv6LSPIDOffset])
	tlv.IPv6TunnelSenderAddress = addr

	tlv.LSPID = binary.BigEndian.Uint16(value[IPv6LSPIDOffset:IPv6TunnelIDOffset])
	tlv.TunnelID = binary.BigEndian.Uint16(value[IPv6TunnelIDOffset:IPv6ExtendedTunnelIDOffset])
	copy(tlv.ExtendedTunnelID[:], value[IPv6ExtendedTunnelIDOffset:IPv6TunnelEPOffset])

	// ok (second return value) is ignored because slice length is guaranteed by decodeTLVLength
	addr, _ = netip.AddrFromSlice(value[IPv6TunnelEPOffset : IPv6TunnelEPOffset+IPv6AddrLen])
	tlv.IPv6TunnelEndpointAddress = addr

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *IPv6LSPIdentifiers) Serialize() ([]byte, error) {
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
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
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
	enc.AddString("extendedTunnelID", hex.EncodeToString(tlv.ExtendedTunnelID[:]))

	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *IPv6LSPIdentifiers) Type() TLVType {
	return TLVIPv6LSPIdentifiers
}

// Len returns the wire length of the receiver.
func (tlv *IPv6LSPIdentifiers) Len() int {
	return int(TLVValueOffset + TLVIPv6LSPIdentifiersValueLength)
}

// NewIPv6LSPIdentifiers creates and returns a new IPv6LSPIdentifiers.
func NewIPv6LSPIdentifiers(senderAddr, endpointAddr netip.Addr, lspID, tunnelID uint16, extendedTunnelID [16]byte) *IPv6LSPIdentifiers {
	return &IPv6LSPIdentifiers{
		IPv6TunnelSenderAddress:   senderAddr,
		IPv6TunnelEndpointAddress: endpointAddr,
		LSPID:                     lspID,
		TunnelID:                  tunnelID,
		ExtendedTunnelID:          extendedTunnelID,
	}
}

// LSPDBVersion represents the LSP-DB-VERSION TLV, carrying the LSP state
// database version number used for state synchronization (RFC 8232).
type LSPDBVersion struct {
	VersionNumber uint64
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *LSPDBVersion) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("LSPDBVersion: %w", err)
	}

	if valueLen != int(TLVLSPDBVersionValueLength) {
		return fmt.Errorf("LSPDBVersion: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]
	tlv.VersionNumber = binary.BigEndian.Uint64(value)

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *LSPDBVersion) Serialize() ([]byte, error) {
	value := make([]byte, TLVLSPDBVersionValueLength)

	binary.BigEndian.PutUint64(value, tlv.VersionNumber)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVLSPDBVersionValueLength),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *LSPDBVersion) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint64("versionNumber", tlv.VersionNumber)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *LSPDBVersion) Type() TLVType {
	return TLVLSPDBVersion
}

// Len returns the wire length of the receiver.
func (tlv *LSPDBVersion) Len() int {
	return int(TLVValueOffset + TLVLSPDBVersionValueLength)
}

// CapStrings returns capability strings for the receiver.
func (tlv *LSPDBVersion) CapStrings() []string {
	return []string{"LSP-DB-VERSION"}
}

// NewLSPDBVersion creates and returns a new LSPDBVersion.
func NewLSPDBVersion(version uint64) *LSPDBVersion {
	return &LSPDBVersion{
		VersionNumber: version,
	}
}

// SRPCECapability represents the SR-PCE-CAPABILITY TLV, advertising the
// maximum SID depth (MSD) for SR-MPLS paths and NAI support (RFC 8664).
// The MSD octet is always present on the wire and is 0 when unlimited.
type SRPCECapability struct {
	HasUnlimitedMaxSIDDepth bool
	IsNAISupported          bool
	MaximumSidDepth         uint8
}

// Flag bits of the SR-PCE-CAPABILITY TLV.
const (
	UnlimitedMaximumSIDDepthFlag byte = 0x01
	NAISupportedFlag             byte = 0x02
)

// Byte offsets of the fields within the SR-PCE-CAPABILITY TLV value.
const (
	SRPCECapabilityFlagsOffset = 0
	SRPCECapabilityMSDOffset   = 1
)

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *SRPCECapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("SRPCECapability: %w", err)
	}

	if valueLen != int(TLVSRPCECapabilityValueLength) {
		return fmt.Errorf("SRPCECapability: invalid value length %d", valueLen)
	}

	val := data[TLVValueOffset : TLVValueOffset+valueLen]

	flags := val[SRPCECapabilityFlagsOffset]
	tlv.HasUnlimitedMaxSIDDepth = IsBitSet(flags, UnlimitedMaximumSIDDepthFlag)
	tlv.IsNAISupported = IsBitSet(flags, NAISupportedFlag)
	tlv.MaximumSidDepth = val[SRPCECapabilityMSDOffset]

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *SRPCECapability) Serialize() ([]byte, error) {
	value := make([]byte, TLVSRPCECapabilityValueLength)

	value[SRPCECapabilityFlagsOffset] = SetBit(value[SRPCECapabilityFlagsOffset], UnlimitedMaximumSIDDepthFlag, tlv.HasUnlimitedMaxSIDDepth)
	value[SRPCECapabilityFlagsOffset] = SetBit(value[SRPCECapabilityFlagsOffset], NAISupportedFlag, tlv.IsNAISupported)
	value[SRPCECapabilityMSDOffset] = tlv.MaximumSidDepth

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVSRPCECapabilityValueLength),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *SRPCECapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddBool("unlimited_max_sid_depth", tlv.HasUnlimitedMaxSIDDepth)
	enc.AddBool("nai_is_supported", tlv.IsNAISupported)
	enc.AddUint8("maximum_sid_depth", tlv.MaximumSidDepth)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *SRPCECapability) Type() TLVType {
	return TLVSRPCECapability
}

// Len returns the wire length of the receiver.
func (tlv *SRPCECapability) Len() int {
	return int(TLVValueOffset + TLVSRPCECapabilityValueLength)
}

// CapStrings returns capability strings for the receiver.
func (tlv *SRPCECapability) CapStrings() []string {
	ret := []string{"SR"}
	if tlv.HasUnlimitedMaxSIDDepth {
		ret = append(ret, "Unlimited-SID-Depth")
	} else {
		ret = append(ret, fmt.Sprintf("MSD=%d", tlv.MaximumSidDepth))
	}
	if tlv.IsNAISupported {
		ret = append(ret, "SR-NAI-Supported")
	}
	return ret
}

// HasInvalidZeroMSD reports the invalid RFC 8664 §5.1 combination of
// X=0 and MSD=0.
func (tlv *SRPCECapability) HasInvalidZeroMSD() bool {
	return !tlv.HasUnlimitedMaxSIDDepth && tlv.MaximumSidDepth == 0
}

// NewSRPCECapability creates and returns a new SRPCECapability.
func NewSRPCECapability(hasUnlimitedMaxSIDDepth bool, isNAISupported bool, maximumSidDepth uint8) *SRPCECapability {
	return &SRPCECapability{
		HasUnlimitedMaxSIDDepth: hasUnlimitedMaxSIDDepth,
		IsNAISupported:          isNAISupported,
		MaximumSidDepth:         maximumSidDepth,
	}
}

// SRv6PCECapability represents the SRv6-PCE-CAPABILITY TLV, advertising SRv6
// path setup support (RFC 9603).
type SRv6PCECapability struct {
	IsNAISupported bool
}

// SRv6NAISupportedFlag is the SRv6-PCE-CAPABILITY Flags bit indicating NAI
// support in SRv6-ERO subobjects.
const SRv6NAISupportedFlag uint16 = 0x0002

// Byte offsets of the fields within the SRv6-PCE-CAPABILITY TLV value.
const (
	SRv6PCECapabilityReservedOffset = 0
	SRv6PCECapabilityFlagsOffset    = 2
)

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *SRv6PCECapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("SRv6PCECapability: %w", err)
	}

	if valueLen < int(TLVSRv6PCECapabilityValueLength) {
		return fmt.Errorf("SRv6PCECapability: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	flags := binary.BigEndian.Uint16(value[SRv6PCECapabilityFlagsOffset : SRv6PCECapabilityFlagsOffset+2])
	tlv.IsNAISupported = (flags & SRv6NAISupportedFlag) != 0

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *SRv6PCECapability) Serialize() ([]byte, error) {
	value := make([]byte, TLVSRv6PCECapabilityValueLength)
	// value[0:2] reserved, must be zero.
	var flags uint16
	if tlv.IsNAISupported {
		flags |= SRv6NAISupportedFlag
	}
	binary.BigEndian.PutUint16(value[SRv6PCECapabilityFlagsOffset:SRv6PCECapabilityFlagsOffset+2], flags)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVSRv6PCECapabilityValueLength),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *SRv6PCECapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddBool("nai_is_supported", tlv.IsNAISupported)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *SRv6PCECapability) Type() TLVType {
	return TLVSRv6PCECapability
}

// Len returns the wire length of the receiver.
func (tlv *SRv6PCECapability) Len() int {
	return int(TLVValueOffset + TLVSRv6PCECapabilityValueLength)
}

// CapStrings returns capability strings for the receiver.
func (tlv *SRv6PCECapability) CapStrings() []string {
	ret := []string{"SRv6"}
	if tlv.IsNAISupported {
		ret = append(ret, "SRv6-NAI-Supported")
	}
	return ret
}

// NewSRv6PCECapability creates and returns a new SRv6PCECapability.
func NewSRv6PCECapability(isNAISupported bool) *SRv6PCECapability {
	return &SRv6PCECapability{
		IsNAISupported: isNAISupported,
	}
}

// MultipathCapability represents the MULTIPATH-CAP TLV, advertising the
// maximum number of paths the speaker can return and its supported multipath
// attributes (draft-ietf-pce-multipath).
type MultipathCapability struct {
	MaxMultipaths            uint16
	IsWeightedSupported      bool
	IsOppositeDirSupported   bool
	IsForwardClassSupported  bool
	IsCompositePathSupported bool
}

// Flag bits of the MULTIPATH-CAP TLV, as masks against its 16-bit Flags field.
// 0x0002 is unassigned.
const (
	MultipathFlagW uint16 = 0x0001 // weighted paths
	MultipathFlagO uint16 = 0x0004 // opposite-direction paths
	MultipathFlagF uint16 = 0x0008 // forward class
	MultipathFlagC uint16 = 0x0010 // composite paths
)

// Byte offsets of the fields within the MULTIPATH-CAP TLV value.
const (
	MultipathCapMaxMultipathsOffset = 0
	MultipathCapFlagsOffset         = 2
)

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *MultipathCapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("MultipathCapability: %w", err)
	}

	if valueLen != int(TLVMultipathCapValueLength) {
		return fmt.Errorf("MultipathCapability: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.MaxMultipaths = binary.BigEndian.Uint16(value[MultipathCapMaxMultipathsOffset : MultipathCapMaxMultipathsOffset+2])
	flags := binary.BigEndian.Uint16(value[MultipathCapFlagsOffset : MultipathCapFlagsOffset+2])
	tlv.IsWeightedSupported = (flags & MultipathFlagW) != 0
	tlv.IsOppositeDirSupported = (flags & MultipathFlagO) != 0
	tlv.IsForwardClassSupported = (flags & MultipathFlagF) != 0
	tlv.IsCompositePathSupported = (flags & MultipathFlagC) != 0

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *MultipathCapability) Serialize() ([]byte, error) {
	value := make([]byte, TLVMultipathCapValueLength)

	binary.BigEndian.PutUint16(value[MultipathCapMaxMultipathsOffset:MultipathCapMaxMultipathsOffset+2], tlv.MaxMultipaths)

	var flags uint16
	if tlv.IsWeightedSupported {
		flags |= MultipathFlagW
	}
	if tlv.IsOppositeDirSupported {
		flags |= MultipathFlagO
	}
	if tlv.IsForwardClassSupported {
		flags |= MultipathFlagF
	}
	if tlv.IsCompositePathSupported {
		flags |= MultipathFlagC
	}
	binary.BigEndian.PutUint16(value[MultipathCapFlagsOffset:MultipathCapFlagsOffset+2], flags)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVMultipathCapValueLength),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *MultipathCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint16("max_multipaths", tlv.MaxMultipaths)
	enc.AddBool("weighted_is_supported", tlv.IsWeightedSupported)
	enc.AddBool("opposite_dir_is_supported", tlv.IsOppositeDirSupported)
	enc.AddBool("forward_class_is_supported", tlv.IsForwardClassSupported)
	enc.AddBool("composite_path_is_supported", tlv.IsCompositePathSupported)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *MultipathCapability) Type() TLVType {
	return TLVMultipathCap
}

// Len returns the wire length of the receiver.
func (tlv *MultipathCapability) Len() int {
	return int(TLVValueOffset + TLVMultipathCapValueLength)
}

// CapStrings returns capability strings for the receiver.
func (tlv *MultipathCapability) CapStrings() []string {
	ret := []string{"Multipath", fmt.Sprintf("MaxMultipaths=%d", tlv.MaxMultipaths)}
	if tlv.IsWeightedSupported {
		ret = append(ret, "Weighted")
	}
	if tlv.IsOppositeDirSupported {
		ret = append(ret, "OppositeDir")
	}
	if tlv.IsForwardClassSupported {
		ret = append(ret, "ForwardClass")
	}
	if tlv.IsCompositePathSupported {
		ret = append(ret, "CompositePath")
	}
	return ret
}

// NewMultipathCapability creates and returns a new MultipathCapability.
func NewMultipathCapability(maxMultipaths uint16, isWeightedSupported, isOppositeDirSupported, isForwardClassSupported, isCompositePathSupported bool) *MultipathCapability {
	return &MultipathCapability{
		MaxMultipaths:            maxMultipaths,
		IsWeightedSupported:      isWeightedSupported,
		IsOppositeDirSupported:   isOppositeDirSupported,
		IsForwardClassSupported:  isForwardClassSupported,
		IsCompositePathSupported: isCompositePathSupported,
	}
}

// Pst is a Path Setup Type identifying the signaling method used to set up a
// path (RFC 8408).
type Pst uint8

// Path Setup Types. pathSetupDescriptions holds their descriptions and
// defining documents.
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

// Psts is a list of Path Setup Types advertised in the
// PATH-SETUP-TYPE-CAPABILITY TLV.
type Psts []Pst

// MarshalJSON encodes the list as a JSON array of numeric Path Setup Type
// values, or as null when the list itself is nil.
func (ts Psts) MarshalJSON() ([]byte, error) {
	if ts == nil {
		return []byte("null"), nil
	}

	if len(ts) == 0 {
		return []byte("[]"), nil
	}

	values := make([]int, len(ts))
	for i, pst := range ts {
		values[i] = int(pst)
	}
	return json.Marshal(values)
}

// PathSetupType represents the PATH-SETUP-TYPE TLV, stating the setup type
// of a single path (RFC 8408).
type PathSetupType struct {
	PathSetupType Pst
}

// PathSetupTypeValueOffset is the byte offset of the PST field within the
// PATH-SETUP-TYPE TLV value; the preceding 3 bytes are reserved.
const PathSetupTypeValueOffset = 3

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *PathSetupType) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("PathSetupType: %w", err)
	}

	if valueLen != int(TLVPathSetupTypeValueLength) {
		return fmt.Errorf("PathSetupType: unexpected value length: expected %d, got %d", TLVPathSetupTypeValueLength, valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]
	tlv.PathSetupType = Pst(value[PathSetupTypeValueOffset])

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *PathSetupType) Serialize() ([]byte, error) {
	value := make([]byte, TLVPathSetupTypeValueLength)

	value[PathSetupTypeValueOffset] = byte(tlv.PathSetupType)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVPathSetupTypeValueLength),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *PathSetupType) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("pathSetupType", tlv.PathSetupType.String())
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *PathSetupType) Type() TLVType {
	return TLVPathSetupType
}

// Len returns the wire length of the receiver.
func (tlv *PathSetupType) Len() int {
	return int(TLVValueOffset + TLVPathSetupTypeValueLength)
}

// NewPathSetupType creates and returns a new PathSetupType.
func NewPathSetupType(pst Pst) *PathSetupType {
	return &PathSetupType{
		PathSetupType: pst,
	}
}

// ExtendedAssociationID represents the EXTENDED-ASSOCIATION-ID TLV (RFC 8697),
// carrying the SR Policy color and endpoint.
type ExtendedAssociationID struct {
	Color    uint32
	Endpoint netip.Addr
}

// Byte offsets of the fields within the EXTENDED-ASSOCIATION-ID TLV value.
const (
	ExtendedAssociationIDColorOffset    = 0
	ExtendedAssociationIDEndpointOffset = 4
)

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *ExtendedAssociationID) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("ExtendedAssociationID: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]
	if len(value) < int(TLVColorValueLength) {
		return fmt.Errorf("ExtendedAssociationID: value too short: got %d, want at least %d", valueLen, TLVColorValueLength)
	}

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

// Serialize encodes the receiver into bytes.
func (tlv *ExtendedAssociationID) Serialize() ([]byte, error) {
	return tlv.serialize(tlv.Type()), nil
}

func (tlv *ExtendedAssociationID) serialize(typ TLVType) []byte {
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
		Uint16ToByteSlice(typ),
		Uint16ToByteSlice(length),
		value,
	)
}

// MarshalLogObject marshals the receiver into a log object.
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

// Type returns the TLV type of the receiver.
func (tlv *ExtendedAssociationID) Type() TLVType {
	return TLVExtendedAssociationID
}

// Len returns the wire length of the receiver.
func (tlv *ExtendedAssociationID) Len() int {
	if tlv.Endpoint.Is4() {
		return int(TLVValueOffset + TLVExtendedAssociationIDIPv4ValueLength)
	} else if tlv.Endpoint.Is6() {
		return int(TLVValueOffset + TLVExtendedAssociationIDIPv6ValueLength)
	}
	return 0

}

// NewExtendedAssociationID creates and returns a new ExtendedAssociationID.
func NewExtendedAssociationID(color uint32, endpoint netip.Addr) *ExtendedAssociationID {
	return &ExtendedAssociationID{
		Color:    color,
		Endpoint: endpoint,
	}
}

// ExtendedAssociationIDIPv4Juniper is the Juniper vendor-specific
// Extended Association ID TLV (0xffe3). Juniper devices always use the
// IPv4 zero-padded wire format for this TLV, even on IPv6 PCEP sessions,
// so the IPv6 wire format (value length 20) is rejected here.
type ExtendedAssociationIDIPv4Juniper struct {
	ExtendedAssociationID
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *ExtendedAssociationIDIPv4Juniper) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("ExtendedAssociationIDIPv4Juniper: %w", err)
	}

	if valueLen != int(TLVExtendedAssociationIDIPv4ValueLength) {
		return fmt.Errorf("ExtendedAssociationIDIPv4Juniper: invalid value length %d", valueLen)
	}

	return tlv.ExtendedAssociationID.DecodeFromBytes(data)
}

// Serialize encodes the receiver into bytes.
func (tlv *ExtendedAssociationIDIPv4Juniper) Serialize() ([]byte, error) {
	if !tlv.Endpoint.Is4() {
		return nil, nil
	}

	return tlv.serialize(tlv.Type()), nil
}

// Type returns the TLV type of the receiver.
func (tlv *ExtendedAssociationIDIPv4Juniper) Type() TLVType {
	return TLVExtendedAssociationIDIPv4Juniper
}

// Len returns the wire length of the receiver.
func (tlv *ExtendedAssociationIDIPv4Juniper) Len() int {
	if !tlv.Endpoint.Is4() {
		return 0
	}

	return int(TLVValueOffset + TLVExtendedAssociationIDIPv4ValueLength)
}

// PathSetupTypeCapability represents the PATH-SETUP-TYPE-CAPABILITY TLV, which
// lists the path setup types the speaker supports together with any
// per-setup-type sub-TLVs (RFC 8408).
type PathSetupTypeCapability struct {
	PathSetupTypes Psts
	SubTLVs        []TLVInterface
}

const (
	// PathSetupTypeCapabilityFixedPartLength is the length of the reserved and
	// number of PSTs fields, after which the PST list starts.
	PathSetupTypeCapabilityFixedPartLength = 4
	// PathSetupTypeCapabilityPSTCountOffset is the byte offset of the number of
	// PSTs field within the TLV value.
	PathSetupTypeCapabilityPSTCountOffset = 3
	// MaxPathSetupTypes is the largest PST count the 1-byte field can express.
	MaxPathSetupTypes = 255
)

func (tlv *PathSetupTypeCapability) pstCount() int {
	if len(tlv.PathSetupTypes) > MaxPathSetupTypes {
		return MaxPathSetupTypes
	}
	return len(tlv.PathSetupTypes)
}

func (tlv *PathSetupTypeCapability) paddedPSTLength() int {
	return paddedLength(tlv.pstCount(), TLVAlignment)
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *PathSetupTypeCapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("PathSetupTypeCapability: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if len(value) < PathSetupTypeCapabilityFixedPartLength {
		return errors.New("PathSetupTypeCapability: value too short for fixed part")
	}

	pstNum := int(value[PathSetupTypeCapabilityPSTCountOffset])

	tlv.PathSetupTypes = make([]Pst, 0, pstNum)
	for i := range pstNum {
		offset := PathSetupTypeCapabilityFixedPartLength + i
		if offset >= len(value) {
			return errors.New("PathSetupTypeCapability: value too short for PathSetupTypes entries")
		}
		tlv.PathSetupTypes = append(tlv.PathSetupTypes, Pst(value[offset]))
	}

	padded := paddedLength(pstNum, TLVAlignment)
	subTLVOffset := PathSetupTypeCapabilityFixedPartLength + padded

	if subTLVOffset > len(value) {
		return errors.New("PathSetupTypeCapability: value too short for subTLVs")
	}
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

// Serialize encodes the receiver into bytes.
func (tlv *PathSetupTypeCapability) Serialize() ([]byte, error) {
	pstCount := tlv.pstCount()

	fixedPartLen := PathSetupTypeCapabilityFixedPartLength + tlv.paddedPSTLength()

	value := make([]byte, fixedPartLen)
	value[PathSetupTypeCapabilityPSTCountOffset] = byte(pstCount)

	for i := range pstCount {
		value[PathSetupTypeCapabilityFixedPartLength+i] =
			byte(tlv.PathSetupTypes[i])
	}

	subTLVsBytes := []byte{}
	for _, subTLV := range tlv.SubTLVs {
		b, err := subTLV.Serialize()
		if err != nil {
			return nil, fmt.Errorf("PathSetupTypeCapability: %w", err)
		}
		subTLVsBytes = append(subTLVsBytes, b...)
	}

	totalLen, err := tlvValueLength(fixedPartLen + len(subTLVsBytes))
	if err != nil {
		return nil, fmt.Errorf("PathSetupTypeCapability: %w", err)
	}

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(totalLen),
		value,
		subTLVsBytes,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
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
		// TLVType implements Stringer; use uint16 for numeric formatting.
		subTLVTypes[i] = fmt.Sprintf("0x%04x (%s)", uint16(stlv.Type()), stlv.Type())
	}
	_ = enc.AddArray("subTLVs", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
		for _, s := range subTLVTypes {
			ae.AppendString(s)
		}
		return nil
	}))

	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *PathSetupTypeCapability) Type() TLVType {
	return TLVPathSetupTypeCapability
}

// Len returns the wire length of the receiver.
func (tlv *PathSetupTypeCapability) Len() int {
	length := PathSetupTypeCapabilityFixedPartLength
	length += tlv.paddedPSTLength()

	for _, subTLV := range tlv.SubTLVs {
		length += subTLV.Len()
	}

	return TLVValueOffset + length
}

// CapStrings returns capability strings for the receiver.
func (tlv *PathSetupTypeCapability) CapStrings() []string {
	ret := []string{}

	psts := tlv.PathSetupTypes[:tlv.pstCount()]

	if slices.Contains(psts, PathSetupTypeSRTE) {
		ret = append(ret, "SR-TE")
	}
	if slices.Contains(psts, PathSetupTypeSRv6TE) {
		ret = append(ret, "SRv6-TE")
	}

	return ret
}

// AssocType is the association type of an ASSOCIATION object, identifying
// what the associated LSPs have in common (RFC 8697).
type AssocType uint16

// IANA-assigned association types (see the IANA PCEP "Association Type Field" registry).
const (
	AssocTypePathProtectionAssociation              AssocType = 0x01
	AssocTypeDisjointAssociation                    AssocType = 0x02
	AssocTypePolicyAssociation                      AssocType = 0x03
	AssocTypeSingleSidedBidirectionalLSPAssociation AssocType = 0x04
	AssocTypeDoubleSidedBidirectionalLSPAssociation AssocType = 0x05
	AssocTypeSRPolicyAssociation                    AssocType = 0x06
	AssocTypeVnAssociationType                      AssocType = 0x07
	AssocTypeBidirectionalSRLSPAssociation          AssocType = 0x08
	AssocTypeP2MPSRPolicyAssociation                AssocType = 0x09
)

// Vendor-specific Association Type values used for legacy PCC interoperability.
const (
	AssocTypeSRPolicyAssociationCisco   AssocType = 0x14   // Cisco-specific
	AssocTypeSRPolicyAssociationJuniper AssocType = 0xffe1 // Juniper-specific (deprecated)
)

var assocTypeDescriptions = map[AssocType]struct {
	Description string
	Reference   string
}{
	AssocTypePathProtectionAssociation:              {"Path Protection Association", "RFC8745"},
	AssocTypeDisjointAssociation:                    {"Disjoint Association", "RFC8800"},
	AssocTypePolicyAssociation:                      {"Policy Association", "RFC9005"},
	AssocTypeSingleSidedBidirectionalLSPAssociation: {"Single Sided Bidirectional LSP Association", "RFC9059"},
	AssocTypeDoubleSidedBidirectionalLSPAssociation: {"Double Sided Bidirectional LSP Association", "RFC9059"},
	AssocTypeSRPolicyAssociation:                    {"SR Policy Association", "RFC9862"},
	AssocTypeVnAssociationType:                      {"VN Association Type", "RFC9358"},
	AssocTypeBidirectionalSRLSPAssociation:          {"Bidirectional SR LSP Association", "draft-ietf-pce-sr-bidir-path-25"},
	AssocTypeP2MPSRPolicyAssociation:                {"P2MP SR Policy Association", "draft-ietf-pce-sr-p2mp-policy-11"},
	AssocTypeSRPolicyAssociationCisco:               {"SR Policy Association (Cisco-specific)", "not IANA-assigned"},
	AssocTypeSRPolicyAssociationJuniper:             {"SR Policy Association (Juniper-specific, deprecated)", "not IANA-assigned"},
}

// String returns the display name of the association type, suffixing
// draft-defined types with " (draft)".
func (at AssocType) String() string {
	desc, ok := assocTypeDescriptions[at]
	if !ok {
		return fmt.Sprintf("Unknown AssocType (0x%04x)", uint16(at))
	}
	if strings.HasPrefix(desc.Reference, "draft-") {
		return desc.Description + " (draft)"
	}
	return desc.Description
}

// AssocTypeList represents the ASSOC-TYPE-LIST TLV, advertising the
// association types supported by the speaker (RFC 8697).
type AssocTypeList struct {
	AssocTypes []AssocType
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *AssocTypeList) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, true)
	if err != nil {
		return fmt.Errorf("AssocTypeList: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	if len(value)%2 != 0 {
		return errors.New("AssocTypeList: value length not even, cannot contain 16-bit AssocType entries")
	}

	assocNum := len(value) / 2
	tlv.AssocTypes = make([]AssocType, assocNum)
	for i := range assocNum {
		tlv.AssocTypes[i] = AssocType(binary.BigEndian.Uint16(value[2*i : 2*i+2]))
	}

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *AssocTypeList) Serialize() ([]byte, error) {
	valueLenInt := len(tlv.AssocTypes) * 2

	valueLen, err := tlvValueLength(valueLenInt)
	if err != nil {
		return nil, fmt.Errorf("AssocTypeList: %w", err)
	}

	padding := (TLVAlignment - (valueLenInt % TLVAlignment)) % TLVAlignment

	value := make([]byte, valueLenInt+padding)

	offset := 0
	for _, at := range tlv.AssocTypes {
		binary.BigEndian.PutUint16(value[offset:offset+2], uint16(at))
		offset += 2
	}

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(valueLen),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
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

// Type returns the TLV type of the receiver.
func (tlv *AssocTypeList) Type() TLVType {
	return TLVAssocTypeList
}

// Len returns the wire length of the receiver.
func (tlv *AssocTypeList) Len() int {
	length := len(tlv.AssocTypes) * 2
	padding := 0
	if length%4 != 0 {
		padding = 2
	}
	return TLVValueOffset + length + padding
}

// CapStrings returns capability strings for the receiver.
func (tlv *AssocTypeList) CapStrings() []string {
	ret := make([]string, 0, len(tlv.AssocTypes))
	for _, at := range tlv.AssocTypes {
		ret = append(ret, "AssocType:"+at.String())
	}
	return ret
}

// SRPolicyCandidatePathIdentifier represents the SRPOLICY-CPATH-ID TLV,
// identifying an SR Policy candidate path by its originator and discriminator
// (draft-ietf-pce-segment-routing-policy-cp).
type SRPolicyCandidatePathIdentifier struct {
	ProtocolOrigin uint8 // Protocol that originated the candidate path.
	OriginatorASN  uint32
	OriginatorAddr netip.Addr // Decoded IPv4 addresses are stored as native IPv4.
	Discriminator  uint32
}

// Byte offsets and field lengths within the SRPOLICY-CPATH-ID TLV value. The
// Originator Address field is always 16 bytes; an IPv4 address is carried in
// its last 4 bytes.
const (
	SRPolicyCPathIDProtocolOriginOffset = 0
	SRPolicyCPathIDASNOffset            = 4
	SRPolicyCPathIDAddrOffset           = 8
	SRPolicyCPathIDIPv4Offset           = 12 // offset within Originator Address field
	SRPolicyCPathIDDiscriminatorOffset  = 24
	SRPolicyCPathIDASNLen               = 4
	SRPolicyCPathIDDiscriminatorLen     = 4
)

// ProtocolOriginPCEP is the Protocol-Origin value meaning the candidate path
// was signaled by PCEP.
const ProtocolOriginPCEP = 0x0a

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *SRPolicyCandidatePathIdentifier) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("SRPolicyCandidatePathIdentifier: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]
	if len(value) != int(TLVSRPolicyCPathIDValueLength) {
		return fmt.Errorf("SRPolicyCandidatePathIdentifier: invalid value length, expected %d, got %d", TLVSRPolicyCPathIDValueLength, len(value))
	}

	tlv.ProtocolOrigin = value[SRPolicyCPathIDProtocolOriginOffset]

	tlv.OriginatorASN = binary.BigEndian.Uint32(
		value[SRPolicyCPathIDASNOffset : SRPolicyCPathIDASNOffset+SRPolicyCPathIDASNLen],
	)

	addrBytes := value[SRPolicyCPathIDAddrOffset : SRPolicyCPathIDAddrOffset+IPv6AddrLen]

	if isIPv4Bytes(addrBytes) {
		var v4 [IPv4AddrLen]byte
		copy(v4[:], addrBytes[SRPolicyCPathIDIPv4Offset:])
		tlv.OriginatorAddr = netip.AddrFrom4(v4)
	} else {
		var addr16 [IPv6AddrLen]byte
		copy(addr16[:], addrBytes)
		tlv.OriginatorAddr = netip.AddrFrom16(addr16)
	}

	tlv.Discriminator = binary.BigEndian.Uint32(
		value[SRPolicyCPathIDDiscriminatorOffset : SRPolicyCPathIDDiscriminatorOffset+SRPolicyCPathIDDiscriminatorLen],
	)

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *SRPolicyCandidatePathIdentifier) Serialize() ([]byte, error) {
	return tlv.serialize(tlv.Type()), nil
}

func (tlv *SRPolicyCandidatePathIdentifier) serialize(typ TLVType) []byte {

	value := make([]byte, TLVSRPolicyCPathIDValueLength)

	value[SRPolicyCPathIDProtocolOriginOffset] = tlv.ProtocolOrigin

	binary.BigEndian.PutUint32(
		value[SRPolicyCPathIDASNOffset:SRPolicyCPathIDASNOffset+SRPolicyCPathIDASNLen],
		tlv.OriginatorASN,
	)

	addr := tlv.OriginatorAddr

	switch {
	case !addr.IsValid():
		// keep zero

	case addr.Is4():
		ipv4 := addr.As4()

		copy(
			value[SRPolicyCPathIDAddrOffset+SRPolicyCPathIDIPv4Offset:SRPolicyCPathIDAddrOffset+SRPolicyCPathIDIPv4Offset+IPv4AddrLen],
			ipv4[:],
		)

	case addr.Is6():
		ipv6 := addr.As16()

		copy(
			value[SRPolicyCPathIDAddrOffset:SRPolicyCPathIDAddrOffset+IPv6AddrLen],
			ipv6[:],
		)
	}

	binary.BigEndian.PutUint32(
		value[SRPolicyCPathIDDiscriminatorOffset:SRPolicyCPathIDDiscriminatorOffset+SRPolicyCPathIDDiscriminatorLen],
		tlv.Discriminator,
	)

	return AppendByteSlices(
		Uint16ToByteSlice(typ),
		Uint16ToByteSlice(TLVSRPolicyCPathIDValueLength),
		value,
	)
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *SRPolicyCandidatePathIdentifier) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint8("protocolOrigin", tlv.ProtocolOrigin)
	enc.AddUint32("originatorAsn", tlv.OriginatorASN)
	enc.AddString("originatorAddr", tlv.OriginatorAddr.String())
	enc.AddUint32("discriminator", tlv.Discriminator)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *SRPolicyCandidatePathIdentifier) Type() TLVType {
	return TLVSRPolicyCPathID
}

// Len returns the wire length of the receiver.
func (tlv *SRPolicyCandidatePathIdentifier) Len() int {
	return int(TLVValueOffset + TLVSRPolicyCPathIDValueLength)
}

// SRPolicyCandidatePathIdentifierJuniper is the Juniper vendor-specific
// SR Policy candidate path identifier TLV (0xffe4).
type SRPolicyCandidatePathIdentifierJuniper struct {
	SRPolicyCandidatePathIdentifier
}

// Serialize encodes the receiver into bytes.
func (tlv *SRPolicyCandidatePathIdentifierJuniper) Serialize() ([]byte, error) {
	return tlv.serialize(tlv.Type()), nil
}

// Type returns the TLV type of the receiver.
func (tlv *SRPolicyCandidatePathIdentifierJuniper) Type() TLVType {
	return TLVSRPolicyCPathIDJuniper
}

// SRPolicyCandidatePathPreference represents the SRPOLICY-CPATH-PREFERENCE TLV,
// carrying the preference used to select among an SR Policy's candidate paths
// (draft-ietf-pce-segment-routing-policy-cp).
type SRPolicyCandidatePathPreference struct {
	Preference uint32
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *SRPolicyCandidatePathPreference) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("SRPolicyCandidatePathPreference: %w", err)
	}

	if valueLen != int(TLVSRPolicyCPathPreferenceValueLength) {
		return fmt.Errorf("SRPolicyCandidatePathPreference: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.Preference = binary.BigEndian.Uint32(value)
	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *SRPolicyCandidatePathPreference) Serialize() ([]byte, error) {
	return tlv.serialize(tlv.Type()), nil
}

func (tlv *SRPolicyCandidatePathPreference) serialize(typ TLVType) []byte {
	value := make([]byte, TLVSRPolicyCPathPreferenceValueLength)

	binary.BigEndian.PutUint32(
		value,
		tlv.Preference,
	)

	return AppendByteSlices(
		Uint16ToByteSlice(typ),
		Uint16ToByteSlice(TLVSRPolicyCPathPreferenceValueLength),
		value,
	)
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *SRPolicyCandidatePathPreference) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint32("preference", tlv.Preference)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *SRPolicyCandidatePathPreference) Type() TLVType {
	return TLVSRPolicyCPathPreference
}

// Len returns the wire length of the receiver.
func (tlv *SRPolicyCandidatePathPreference) Len() int {
	return int(TLVValueOffset + TLVSRPolicyCPathPreferenceValueLength)
}

// SRPolicyCandidatePathPreferenceJuniper is the Juniper vendor-specific
// SR Policy candidate path preference TLV (0xffe5).
type SRPolicyCandidatePathPreferenceJuniper struct {
	SRPolicyCandidatePathPreference
}

// Serialize encodes the receiver into bytes.
func (tlv *SRPolicyCandidatePathPreferenceJuniper) Serialize() ([]byte, error) {
	return tlv.serialize(tlv.Type()), nil
}

// Type returns the TLV type of the receiver.
func (tlv *SRPolicyCandidatePathPreferenceJuniper) Type() TLVType {
	return TLVSRPolicyCPathPreferenceJuniper
}

// Color represents the Color TLV, carrying the color of the SR Policy to which
// an LSP belongs (RFC 9863).
type Color struct {
	Color uint32
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *Color) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("Color: %w", err)
	}

	if valueLen != int(TLVColorValueLength) {
		return fmt.Errorf("Color: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	tlv.Color = binary.BigEndian.Uint32(value)
	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *Color) Serialize() ([]byte, error) {
	value := make([]byte, TLVColorValueLength)

	binary.BigEndian.PutUint32(
		value,
		tlv.Color,
	)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVColorValueLength),
		value,
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *Color) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddUint32("color", tlv.Color)
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *Color) Type() TLVType {
	return TLVColor
}

// Len returns the wire length of the receiver.
func (tlv *Color) Len() int {
	return int(TLVValueOffset + TLVColorValueLength)
}

// UnknownTLV holds a TLV without a typed implementation, preserving its type
// and raw value for logging and unchanged re-serialization.
type UnknownTLV struct {
	Typ   TLVType
	Value []byte
}

// DecodeFromBytes decodes the given bytes into the receiver.
func (tlv *UnknownTLV) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, true)
	if err != nil {
		return fmt.Errorf("UnknownTLV: %w", err)
	}

	tlv.Typ = TLVType(binary.BigEndian.Uint16(data[TLVTypeOffset:TLVLengthOffset]))
	tlv.Value = data[TLVValueOffset : TLVValueOffset+valueLen]

	return nil
}

// Serialize encodes the receiver into bytes.
func (tlv *UnknownTLV) Serialize() ([]byte, error) {
	length, err := tlvValueLength(len(tlv.Value))
	if err != nil {
		return nil, fmt.Errorf("UnknownTLV: %w", err)
	}
	padding := paddedLength(len(tlv.Value), TLVAlignment) - len(tlv.Value)

	return AppendByteSlices(
		Uint16ToByteSlice(uint16(tlv.Typ)),
		Uint16ToByteSlice(length),
		tlv.Value,
		make([]byte, padding),
	), nil
}

// MarshalLogObject marshals the receiver into a log object.
func (tlv *UnknownTLV) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if tlv == nil {
		return nil
	}

	enc.AddString("type", fmt.Sprintf("0x%04x", uint16(tlv.Typ)))
	enc.AddInt("length", len(tlv.Value))
	return nil
}

// Type returns the TLV type of the receiver.
func (tlv *UnknownTLV) Type() TLVType {
	return tlv.Typ
}

// Len returns the wire length of the receiver.
func (tlv *UnknownTLV) Len() int {
	return TLVValueOffset + paddedLength(len(tlv.Value), TLVAlignment)
}

// CapStrings returns the capability strings for the UnknownTLV.
func (tlv *UnknownTLV) CapStrings() []string {
	if _, ok := tlvDescriptions[tlv.Typ]; ok {
		return []string{fmt.Sprintf("0x%04x (%s)", uint16(tlv.Typ), tlv.Typ)}
	}
	capStr := "unknown_type_" + strconv.FormatInt(int64(tlv.Typ), 10)
	return []string{capStr}
}

// DecodeTLV decodes a single TLV from data, selecting the implementation from
// its type field and falling back to UnknownTLV for unhandled types.
func DecodeTLV(data []byte) (TLVInterface, error) {
	if len(data) < 2 {
		return nil, errors.New("insufficient data to read TLV type")
	}

	return decodeTLV(data, TLVType(binary.BigEndian.Uint16(data[0:2])))
}

// decodeTLV decodes a single TLV of an already known type from the standard PCEP TLV type space.
func decodeTLV(data []byte, tlvType TLVType) (TLVInterface, error) {
	createTLV, found := tlvMap[tlvType]
	if !found {
		return decodeUnknownTLV(data, tlvType)
	}

	tlv := createTLV()
	if err := tlv.DecodeFromBytes(data); err != nil {
		return nil, fmt.Errorf("error decoding TLV type %x: %w", uint16(tlvType), err)
	}

	return tlv, nil
}

// decodeUnknownTLV decodes a single TLV without consulting tlvMap, keeping its value as raw bytes.
func decodeUnknownTLV(data []byte, tlvType TLVType) (TLVInterface, error) {
	tlv := &UnknownTLV{}
	if err := tlv.DecodeFromBytes(data); err != nil {
		return nil, fmt.Errorf("error decoding unknown TLV type %x: %w", uint16(tlvType), err)
	}

	return tlv, nil
}

// DecodeTLVs decodes a sequence of TLVs using the standard PCEP TLV type space.
func DecodeTLVs(data []byte) ([]TLVInterface, error) {
	return decodeTLVSequence(data, decodeTLV)
}

// DecodeVendorTLVs decodes vendor-specific TLVs as UnknownTLV.
func DecodeVendorTLVs(data []byte) ([]TLVInterface, error) {
	return decodeTLVSequence(data, decodeUnknownTLV)
}

func decodeTLVSequence(data []byte, decode func([]byte, TLVType) (TLVInterface, error)) ([]TLVInterface, error) {
	var tlvs []TLVInterface

	for len(data) > 0 {
		if len(data) < int(TLVValueOffset) {
			return nil, errors.New("truncated TLV header")
		}

		valueLen := int(binary.BigEndian.Uint16(data[TLVLengthOffset:TLVValueOffset]))
		totalLen := int(TLVValueOffset) + valueLen

		tlvType := binary.BigEndian.Uint16(data[TLVTypeOffset:TLVLengthOffset])
		if len(data) < totalLen {
			return nil, fmt.Errorf("truncated TLV value (type=0x%x)", tlvType)
		}

		tlv, err := decode(data[:totalLen], TLVType(tlvType))
		if err != nil {
			return nil, err
		}

		tlvs = append(tlvs, tlv)

		paddedLen := (totalLen + TLVAlignment - 1) & ^(TLVAlignment - 1)
		if len(data) < paddedLen {
			return nil, fmt.Errorf("truncated TLV padding (type=0x%x)", tlvType)
		}

		for i := totalLen; i < paddedLen; i++ {
			if data[i] != 0 {
				return nil, fmt.Errorf("invalid TLV padding (expected zero bytes) (type=0x%x)", tlvType)
			}
		}
		data = data[paddedLen:]
	}

	return tlvs, nil
}
