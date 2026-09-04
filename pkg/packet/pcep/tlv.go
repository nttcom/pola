// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"unicode/utf8"
)

// TLVType is a PCEP TLV type code.
type TLVType uint16

// PCEP TLV type codes.
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

const (
	nameAssocPathProtection = "Path Protection Association"
	nameAssocDisjoint       = "Disjoint Association"
	nameAssocPolicy         = "Policy Association"
	nameAssocSRPolicy       = "SR Policy Association"
)

var tlvDescriptions = map[TLVType]codePointInfo{
	TLVNoPathVector:                       {"NO-PATH-VECTOR", rfc(5440)},
	TLVOverloadDuration:                   {"OVERLOAD-DURATION", rfc(5440)},
	TLVReqMissing:                         {"REQ-MISSING", rfc(5440)},
	TLVOFList:                             {"OF-LIST", rfc(5541)},
	TLVOrder:                              {"ORDER", rfc(5557)},
	TLVP2MPCapable:                        {"P2MP-CAPABLE", rfc(8306)},
	TLVVendorInformation:                  {"VENDOR-INFORMATION", rfc(7470)},
	TLVWavelengthSelection:                {"WAVELENGTH-SELECTION", rfc(8780)},
	TLVWavelengthRestriction:              {"WAVELENGTH-RESTRICTION", rfc(8780)},
	TLVWavelengthAllocation:               {"WAVELENGTH-ALLOCATION", rfc(8780)},
	TLVOpticalInterfaceClassList:          {"OPTICAL-INTERFACE-CLASS-LIST", rfc(8780)},
	TLVClientSignalInformation:            {"CLIENT-SIGNAL-INFORMATION", rfc(8780)},
	TLVHPCECapability:                     {"H-PCE-CAPABILITY", rfc(8685)},
	TLVDomainID:                           {"DOMAIN-ID", rfc(8685)},
	TLVHPCEFlag:                           {"H-PCE-FLAG", rfc(8685)},
	TLVStatefulPCECapability:              {"STATEFUL-PCE-CAPABILITY", rfc(8231)},
	TLVSymbolicPathName:                   {"SYMBOLIC-PATH-NAME", rfc(8231)},
	TLVIPv4LSPIdentifiers:                 {"IPV4-LSP-IDENTIFIERS", rfc(8231)},
	TLVIPv6LSPIdentifiers:                 {"IPV6-LSP-IDENTIFIERS", rfc(8231)},
	TLVLSPErrorCode:                       {"LSP-ERROR-CODE", rfc(8231)},
	TLVRsvpErrorSpec:                      {"RSVP-ERROR-SPEC", rfc(8231)},
	TLVLSPDBVersion:                       {"LSP-DB-VERSION", rfc(8232)},
	TLVSpeakerEntityID:                    {"SPEAKER-ENTITY-ID", rfc(8232)},
	TLVSRPCECapability:                    {"SR-PCE-CAPABILITY", rfc(8664)},
	TLVSRv6PCECapability:                  {"SRv6-PCE-CAPABILITY", rfc(9603)},
	TLVPathSetupType:                      {"PATH-SETUP-TYPE", rfc(8408)},
	TLVOperatorConfiguredAssociationRange: {"OPERATOR-CONFIGURED-ASSOCIATION-RANGE", rfc(8697)},
	TLVGlobalAssociationSource:            {"GLOBAL-ASSOCIATION-SOURCE", rfc(8697)},
	TLVExtendedAssociationID:              {"EXTENDED-ASSOCIATION-ID", rfc(8697)},
	TLVP2MPIPv4LSPIdentifiers:             {"P2MP-IPV4-LSP-IDENTIFIERS", rfc(8623)},
	TLVP2MPIPv6LSPIdentifiers:             {"P2MP-IPV6-LSP-IDENTIFIERS", rfc(8623)},
	TLVPathSetupTypeCapability:            {"PATH-SETUP-TYPE-CAPABILITY", rfc(8408)},
	TLVAssocTypeList:                      {"ASSOC-TYPE-LIST", rfc(8697)},
	TLVAutoBandwidthCapability:            {"AUTO-BANDWIDTH-CAPABILITY", rfc(8733)},
	TLVAutoBandwidthAttributes:            {"AUTO-BANDWIDTH-ATTRIBUTES", rfc(8733)},
	TLVPathProtectionAssociationGroupTLV:  {"PATH-PROTECTION-ASSOCIATION-GROUP", rfc(8745)},
	TLVIPv4Address:                        {"IPV4-ADDRESS", rfc(8779)},
	TLVIPv6Address:                        {"IPV6-ADDRESS", rfc(8779)},
	TLVUnnumberedEndpoint:                 {"UNNUMBERED-ENDPOINT", rfc(8779)},
	TLVLabelRequest:                       {"LABEL-REQUEST", rfc(8779)},
	TLVLabelSet:                           {"LABEL-SET", rfc(8779)},
	TLVProtectionAttribute:                {"PROTECTION-ATTRIBUTE", rfc(8779)},
	TLVGmplsCapability:                    {"GMPLS-CAPABILITY", rfc(8779)},
	TLVDisjointnessConfiguration:          {"DISJOINTNESS-CONFIGURATION", rfc(8800)},
	TLVDisjointnessStatus:                 {"DISJOINTNESS-STATUS", rfc(8800)},
	TLVPolicyParameters:                   {"POLICY-PARAMETERS-TLV", rfc(9005)},
	TLVSchedLSPAttribute:                  {"SCHED-LSP-ATTRIBUTE", rfc(8934)},
	TLVSchedPdLSPAttribute:                {"SCHED-PD-LSP-ATTRIBUTE", rfc(8934)},
	TLVPCEFlowspecCapability:              {"PCE-FLOWSPEC-CAPABILITY TLV", rfc(9168)},
	TLVFlowFilter:                         {"FLOW-FILTER-TLV", rfc(9168)},
	TLVBidirectionalLSPAssociationGroup:   {"BIDIRECTIONAL-LSP Association Group TLV", rfc(9059)},
	TLVTePathBinding:                      {"TE-PATH-BINDING", rfc(9604)},
	TLVSRPolicyPolName:                    {"SRPOLICY-POL-NAME", refDraftPCESegmentRoutingPolicyCP},
	TLVSRPolicyCPathID:                    {"SRPOLICY-CPATH-ID", refDraftPCESegmentRoutingPolicyCP},
	TLVSRPolicyCPathName:                  {"SRPOLICY-CPATH-NAME", refDraftPCESegmentRoutingPolicyCP},
	TLVSRPolicyCPathPreference:            {"SRPOLICY-CPATH-PREFERENCE", refDraftPCESegmentRoutingPolicyCP},
	TLVMultipathCap:                       {"MULTIPATH-CAP", refDraftPCEMultipath},
	TLVMultipathWeight:                    {"MULTIPATH-WEIGHT", refDraftPCEMultipath},
	TLVMultipathBackup:                    {"MULTIPATH-BACKUP", refDraftPCEMultipath},
	TLVMultipathOppdirPath:                {"MULTIPATH-OPPDIR-PATH", refDraftPCEMultipath},
	TLVLSPExtendedFlag:                    {"LSP-EXTENDED-FLAG", rfc(9357)},
	TLVVirtualNetwork:                     {"VIRTUAL-NETWORK-TLV", rfc(9358)},
	TLVSrAlgorithm:                        {"SR-Algorithm", rfc(9933)},
	TLVColor:                              {"Color", rfc(9863)},
	TLVComputationPriority:                {"COMPUTATION-PRIORITY", rfc(9862)},
	TLVExplicitNullLabelPolicy:            {"EXPLICIT-NULL-LABEL-POLICY", rfc(9862)},
	TLVInvalidation:                       {"INVALIDATION", rfc(9862)},
	TLVSRPolicyCapability:                 {"SRPOLICY-CAPABILITY", rfc(9862)},
	TLVPathModification:                   {"PATH-MODIFICATION", refDraftPCECircuitStyle},
	TLVSRP2MPPolicyCapability:             {"SR-P2MP-POLICY-CAPABILITY", refDraftPCESRP2MPPolicy},
	TLVIPv4SrP2MPInstanceID:               {"IPV4-SR-P2MP-INSTANCE-ID", refDraftPCESRP2MPPolicy},
	TLVIPv6SrP2MPInstanceID:               {"IPV6-SR-P2MP-INSTANCE-ID", refDraftPCESRP2MPPolicy},

	// These Juniper code points are IANA-unassigned and have no published specification.
	TLVExtendedAssociationIDIPv4Juniper: {"EXTENDED-ASSOCIATION-ID (Juniper)", refNotIANAAssigned},
	TLVSRPolicyCPathIDJuniper:           {"SRPOLICY-CPATH-ID (Juniper)", refNotIANAAssigned},
	TLVSRPolicyCPathPreferenceJuniper:   {"SRPOLICY-CPATH-PREFERENCE (Juniper)", refNotIANAAssigned},
}

// Name returns the registered name of the TLV type.
func (t TLVType) Name() string { return tlvDescriptions[t].Description }

// Reference returns the defining document of the TLV type.
func (t TLVType) Reference() Reference { return tlvDescriptions[t].Reference }

// String returns a human-readable representation of the TLV type.
func (t TLVType) String() string {
	if name := t.Name(); name != "" {
		return fmt.Sprintf("%s (0x%04x)", name, uint16(t))
	}

	return fmt.Sprintf("Unknown TLV (0x%04x)", uint16(t))
}

// StringWithReference returns the TLV type with its reference.
func (t TLVType) StringWithReference() string {
	return withReference(t.String(), t.Reference())
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

// TLVAlignment is the byte boundary PCEP TLVs are padded to.
const TLVAlignment = 4

// Fixed value lengths of PCEP TLVs.
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

// Juniper vendor-specific TLV type codes.
const (
	TLVExtendedAssociationIDIPv4Juniper TLVType = 0xffe3
	TLVSRPolicyCPathIDJuniper           TLVType = 0xffe4
	TLVSRPolicyCPathPreferenceJuniper   TLVType = 0xffe5
)

// Cisco specific SubTLV.
const (
	SubTLVColorCisco      TLVType = 0x01
	SubTLVPreferenceCisco TLVType = 0x03
)

// TLVInterface is implemented by every decodable PCEP TLV.
type TLVInterface interface {
	// DecodeFromBytes decodes exactly one TLV (Type, Length, Value, padding).
	DecodeFromBytes(data []byte) error
	// Serialize encodes the TLV (Type, Length, Value, padding).
	Serialize() ([]byte, error)
	Type() TLVType
	Len() int
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

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *VendorInformation) Type() TLVType {
	return TLVVendorInformation
}

// Len implements TLVInterface.
func (tlv *VendorInformation) Len() int {
	return TLVValueOffset + tlv.paddedValueLength()
}

func (tlv *VendorInformation) isCapability() {}

func (tlv *VendorInformation) valueLength() int {
	return int(TLVVendorInformationMinValueLength) + len(tlv.EnterpriseSpecificInformation)
}

func (tlv *VendorInformation) paddedValueLength() int {
	return paddedLength(tlv.valueLength(), TLVAlignment)
}

// NewVendorInformation creates a VENDOR-INFORMATION TLV.
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

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
func (tlv *StatefulPCECapability) Serialize() ([]byte, error) {
	flags := tlv.SetFlags() & definedStatefulPCEFlagsMask

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVStatefulPCECapabilityValueLength),
		Uint32ToByteSlice(flags),
	), nil
}

// Type implements TLVInterface.
func (tlv *StatefulPCECapability) Type() TLVType {
	return TLVStatefulPCECapability
}

// Len implements TLVInterface.
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

func (tlv *StatefulPCECapability) isCapability() {}

// NewStatefulPCECapability creates a STATEFUL-PCE-CAPABILITY TLV from its flag bits.
func NewStatefulPCECapability(flags uint32) *StatefulPCECapability {
	tlv := &StatefulPCECapability{}
	tlv.ExtractCapabilities(flags)

	return tlv
}

// SymbolicPathName represents the SYMBOLIC-PATH-NAME TLV carrying the operator-visible name of an LSP (RFC 8231 §7.3.2).
type SymbolicPathName struct {
	Name string
}

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *SymbolicPathName) Type() TLVType {
	return TLVSymbolicPathName
}

// Len implements TLVInterface.
func (tlv *SymbolicPathName) Len() int {
	length := len(tlv.Name)
	padding := (TLVAlignment - (length % TLVAlignment)) % TLVAlignment

	return TLVValueOffset + length + padding
}

// NewSymbolicPathName creates a SYMBOLIC-PATH-NAME TLV.
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

// DecodeFromBytes implements TLVInterface.
func (tlv *IPv4LSPIdentifiers) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("IPv4LSPIdentifiers: %w", err)
	}

	if valueLen != int(TLVIPv4LSPIdentifiersValueLength) {
		return fmt.Errorf("IPv4LSPIdentifiers: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	addr, _ := netip.AddrFromSlice(value[IPv4SenderOffset:IPv4LSPIDOffset])
	tlv.IPv4TunnelSenderAddress = addr

	tlv.LSPID = binary.BigEndian.Uint16(value[IPv4LSPIDOffset:IPv4TunnelIDOffset])
	tlv.TunnelID = binary.BigEndian.Uint16(value[IPv4TunnelIDOffset:IPv4ExtTunnelIDOffset])
	tlv.ExtendedTunnelID = binary.BigEndian.Uint32(value[IPv4ExtTunnelIDOffset:IPv4TunnelEPOffset])

	addr, _ = netip.AddrFromSlice(value[IPv4TunnelEPOffset : IPv4TunnelEPOffset+IPv4AddrLen])
	tlv.IPv4TunnelEndpointAddress = addr

	return nil
}

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *IPv4LSPIdentifiers) Type() TLVType {
	return TLVIPv4LSPIdentifiers
}

// Len implements TLVInterface.
func (tlv *IPv4LSPIdentifiers) Len() int {
	return int(TLVValueOffset + TLVIPv4LSPIdentifiersValueLength)
}

// NewIPv4LSPIdentifiers creates an IPV4-LSP-IDENTIFIERS TLV.
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

// DecodeFromBytes implements TLVInterface.
func (tlv *IPv6LSPIdentifiers) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("IPv6LSPIdentifiers: %w", err)
	}

	if valueLen != int(TLVIPv6LSPIdentifiersValueLength) {
		return fmt.Errorf("IPv6LSPIdentifiers: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	addr, _ := netip.AddrFromSlice(value[IPv6SenderOffset:IPv6LSPIDOffset])
	tlv.IPv6TunnelSenderAddress = addr

	tlv.LSPID = binary.BigEndian.Uint16(value[IPv6LSPIDOffset:IPv6TunnelIDOffset])
	tlv.TunnelID = binary.BigEndian.Uint16(value[IPv6TunnelIDOffset:IPv6ExtendedTunnelIDOffset])
	copy(tlv.ExtendedTunnelID[:], value[IPv6ExtendedTunnelIDOffset:IPv6TunnelEPOffset])

	addr, _ = netip.AddrFromSlice(value[IPv6TunnelEPOffset : IPv6TunnelEPOffset+IPv6AddrLen])
	tlv.IPv6TunnelEndpointAddress = addr

	return nil
}

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *IPv6LSPIdentifiers) Type() TLVType {
	return TLVIPv6LSPIdentifiers
}

// Len implements TLVInterface.
func (tlv *IPv6LSPIdentifiers) Len() int {
	return int(TLVValueOffset + TLVIPv6LSPIdentifiersValueLength)
}

// NewIPv6LSPIdentifiers creates an IPV6-LSP-IDENTIFIERS TLV.
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

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
func (tlv *LSPDBVersion) Serialize() ([]byte, error) {
	value := make([]byte, TLVLSPDBVersionValueLength)

	binary.BigEndian.PutUint64(value, tlv.VersionNumber)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVLSPDBVersionValueLength),
		value,
	), nil
}

// Type implements TLVInterface.
func (tlv *LSPDBVersion) Type() TLVType {
	return TLVLSPDBVersion
}

// Len implements TLVInterface.
func (tlv *LSPDBVersion) Len() int {
	return int(TLVValueOffset + TLVLSPDBVersionValueLength)
}

func (tlv *LSPDBVersion) isCapability() {}

// NewLSPDBVersion creates an LSP-DB-VERSION TLV.
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

// Field offsets in the SR-PCE-CAPABILITY TLV value (RFC 8664 §5.1.1):
// Reserved (2 octets), Flags (1 octet), MSD (1 octet).
// Reserved octets MUST be zero when sent and MUST be ignored when received.
const (
	SRPCECapabilityFlagsOffset = 2
	SRPCECapabilityMSDOffset   = 3
)

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *SRPCECapability) Type() TLVType {
	return TLVSRPCECapability
}

// Len implements TLVInterface.
func (tlv *SRPCECapability) Len() int {
	return int(TLVValueOffset + TLVSRPCECapabilityValueLength)
}

func (tlv *SRPCECapability) isCapability() {}

// HasInvalidZeroMSD reports RFC 8664 §5.1 violation: X=0 and MSD=0.
func (tlv *SRPCECapability) HasInvalidZeroMSD() bool {
	return !tlv.HasUnlimitedMaxSIDDepth && tlv.MaximumSidDepth == 0
}

// MaxSIDs returns the sender's session-wide SID depth limit.
// ok is false when no limit is enforced.
func (tlv *SRPCECapability) MaxSIDs() (maxSIDs uint8, ok bool) {
	if tlv.HasUnlimitedMaxSIDDepth || tlv.MaximumSidDepth == 0 {
		return 0, false
	}

	return tlv.MaximumSidDepth, true
}

// NewSRPCECapability creates an SR-PCE-CAPABILITY TLV.
func NewSRPCECapability(hasUnlimitedMaxSIDDepth, isNAISupported bool, maximumSidDepth uint8) *SRPCECapability {
	return &SRPCECapability{
		HasUnlimitedMaxSIDDepth: hasUnlimitedMaxSIDDepth,
		IsNAISupported:          isNAISupported,
		MaximumSidDepth:         maximumSidDepth,
	}
}

// MSD is an (MSD-Type, MSD-Value) pair.
type MSD struct {
	Type  uint8
	Value uint8
}

// MSDPairLength is the size of an MSD pair on the wire.
const MSDPairLength = 2

// SRv6 MSD types defined in RFC 9352 (Type 43 is unassigned by IANA).
const (
	MSDTypeSRHMaxSL      uint8 = 41
	MSDTypeSRHMaxEndPop  uint8 = 42
	MSDTypeSRHMaxHEncaps uint8 = 44
	MSDTypeSRHMaxEndD    uint8 = 45
)

// SRv6PCECapability represents the SRv6-PCE-CAPABILITY TLV (RFC 9603).
type SRv6PCECapability struct {
	IsNAISupported bool
	MSDs           []MSD
}

// SRv6NAISupportedFlag indicates NAI resolution support.
const SRv6NAISupportedFlag uint16 = 0x0002

// Byte offsets of fields within the SRv6-PCE-CAPABILITY TLV value.
const (
	SRv6PCECapabilityReservedOffset = 0
	SRv6PCECapabilityFlagsOffset    = 2
	SRv6PCECapabilityMSDsOffset     = 4
)

// DecodeFromBytes implements TLVInterface.
func (tlv *SRv6PCECapability) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, true)
	if err != nil {
		return fmt.Errorf("SRv6PCECapability: %w", err)
	}

	if valueLen < int(TLVSRv6PCECapabilityValueLength) {
		return fmt.Errorf("SRv6PCECapability: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	flags := binary.BigEndian.Uint16(value[SRv6PCECapabilityFlagsOffset : SRv6PCECapabilityFlagsOffset+2])
	tlv.IsNAISupported = (flags & SRv6NAISupportedFlag) != 0

	msdBytes := value[SRv6PCECapabilityMSDsOffset:]
	if len(msdBytes)%MSDPairLength != 0 {
		return fmt.Errorf("SRv6PCECapability: value length %d leaves a truncated (MSD-Type, MSD-Value) pair", valueLen)
	}

	tlv.MSDs = nil
	for i := 0; i < len(msdBytes); i += MSDPairLength {
		tlv.MSDs = append(tlv.MSDs, MSD{Type: msdBytes[i], Value: msdBytes[i+1]})
	}

	return nil
}

func (tlv *SRv6PCECapability) valueLength() int {
	return int(TLVSRv6PCECapabilityValueLength) + MSDPairLength*len(tlv.MSDs)
}

// Serialize implements TLVInterface.
func (tlv *SRv6PCECapability) Serialize() ([]byte, error) {
	valueLenInt := tlv.valueLength()

	valueLen, err := tlvValueLength(valueLenInt)
	if err != nil {
		return nil, fmt.Errorf("SRv6PCECapability: %w", err)
	}

	value := make([]byte, paddedLength(valueLenInt, TLVAlignment))

	var flags uint16
	if tlv.IsNAISupported {
		flags |= SRv6NAISupportedFlag
	}

	binary.BigEndian.PutUint16(value[SRv6PCECapabilityFlagsOffset:SRv6PCECapabilityFlagsOffset+2], flags)

	offset := SRv6PCECapabilityMSDsOffset
	for _, msd := range tlv.MSDs {
		value[offset] = msd.Type
		value[offset+1] = msd.Value
		offset += MSDPairLength
	}

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(valueLen),
		value,
	), nil
}

// Type implements TLVInterface.
func (tlv *SRv6PCECapability) Type() TLVType {
	return TLVSRv6PCECapability
}

// Len implements TLVInterface.
func (tlv *SRv6PCECapability) Len() int {
	return TLVValueOffset + paddedLength(tlv.valueLength(), TLVAlignment)
}

func (tlv *SRv6PCECapability) isCapability() {}

// MaxSIDs returns the SID limit from the SRH Max H.Encaps MSD.
// A zero MSD-Value maps to one SID (RFC 9352 §4.3).
// ok is false when the MSD is absent.
func (tlv *SRv6PCECapability) MaxSIDs() (maxSIDs uint8, ok bool) {
	for _, msd := range tlv.MSDs {
		if msd.Type != MSDTypeSRHMaxHEncaps {
			continue
		}

		if msd.Value == 0 {
			return 1, true
		}

		return msd.Value, true
	}

	return 0, false
}

// NewSRv6PCECapability creates an SRv6-PCE-CAPABILITY TLV.
func NewSRv6PCECapability(isNAISupported bool, msds ...MSD) *SRv6PCECapability {
	return &SRv6PCECapability{
		IsNAISupported: isNAISupported,
		MSDs:           msds,
	}
}

// MultipathCapability represents the MULTIPATH-CAP TLV (draft-ietf-pce-multipath).
type MultipathCapability struct {
	MaxMultipaths            uint16
	IsWeightedSupported      bool
	IsOppositeDirSupported   bool
	IsForwardClassSupported  bool
	IsCompositePathSupported bool
}

// Flag bits of the MULTIPATH-CAP TLV.
const (
	MultipathFlagW uint16 = 0x0001
	MultipathFlagO uint16 = 0x0004
	MultipathFlagF uint16 = 0x0008
	MultipathFlagC uint16 = 0x0010
)

// Byte offsets of the fields within the MULTIPATH-CAP TLV value.
const (
	MultipathCapMaxMultipathsOffset = 0
	MultipathCapFlagsOffset         = 2
)

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *MultipathCapability) Type() TLVType {
	return TLVMultipathCap
}

// Len implements TLVInterface.
func (tlv *MultipathCapability) Len() int {
	return int(TLVValueOffset + TLVMultipathCapValueLength)
}

func (tlv *MultipathCapability) isCapability() {}

// NewMultipathCapability creates a MULTIPATH-CAPABILITY TLV.
func NewMultipathCapability(maxMultipaths uint16, isWeightedSupported, isOppositeDirSupported, isForwardClassSupported, isCompositePathSupported bool) *MultipathCapability {
	return &MultipathCapability{
		MaxMultipaths:            maxMultipaths,
		IsWeightedSupported:      isWeightedSupported,
		IsOppositeDirSupported:   isOppositeDirSupported,
		IsForwardClassSupported:  isForwardClassSupported,
		IsCompositePathSupported: isCompositePathSupported,
	}
}

// Pst is a Path Setup Type identifying the signaling method used to set up a path (RFC 8408).
type Pst uint8

// Path setup type codes.
const (
	PathSetupTypeRSVPTE  Pst = 0x00
	PathSetupTypeSRTE    Pst = 0x01
	PathSetupTypePCECCTE Pst = 0x02
	PathSetupTypeSRv6TE  Pst = 0x03
	PathSetupTypeIPTE    Pst = 0x04
)

var pathSetupDescriptions = map[Pst]codePointInfo{
	PathSetupTypeRSVPTE:  {"Path is set up using the RSVP-TE signaling protocol", rfc(8408)},
	PathSetupTypeSRTE:    {"Traffic engineering path is set up using Segment Routing", rfc(8664)},
	PathSetupTypePCECCTE: {"Traffic engineering path is set up using PCECC mode", rfc(9050)},
	PathSetupTypeSRv6TE:  {"Traffic engineering path is set up using SRv6", rfc(9603)},
	PathSetupTypeIPTE:    {"Native IP TE Path", rfc(9757)},
}

// Name returns the registered name of the path setup type.
func (pst Pst) Name() string { return pathSetupDescriptions[pst].Description }

// Reference returns the defining document of the path setup type.
func (pst Pst) Reference() Reference { return pathSetupDescriptions[pst].Reference }

// String returns a human-readable representation of the path setup type.
func (pst Pst) String() string {
	if name := pst.Name(); name != "" {
		return fmt.Sprintf("%s (0x%02x)", name, uint8(pst))
	}

	return fmt.Sprintf("Unknown PathSetupType (0x%02x)", uint8(pst))
}

// StringWithReference returns the path setup type with its reference.
func (pst Pst) StringWithReference() string {
	return withReference(pst.String(), pst.Reference())
}

// Psts is a list of path setup types.
type Psts []Pst

// MarshalJSON encodes Psts as a numeric JSON array, distinguishing nil from empty.
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

// PathSetupType represents the PATH-SETUP-TYPE TLV for a single path (RFC 8408).
type PathSetupType struct {
	PathSetupType Pst
}

// PathSetupTypeValueOffset is the PST field offset; the preceding 3 bytes are reserved (RFC 8408).
const PathSetupTypeValueOffset = 3

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
func (tlv *PathSetupType) Serialize() ([]byte, error) {
	value := make([]byte, TLVPathSetupTypeValueLength)

	value[PathSetupTypeValueOffset] = byte(tlv.PathSetupType)

	return AppendByteSlices(
		Uint16ToByteSlice(tlv.Type()),
		Uint16ToByteSlice(TLVPathSetupTypeValueLength),
		value,
	), nil
}

// Type implements TLVInterface.
func (tlv *PathSetupType) Type() TLVType {
	return TLVPathSetupType
}

// Len implements TLVInterface.
func (tlv *PathSetupType) Len() int {
	return int(TLVValueOffset + TLVPathSetupTypeValueLength)
}

// NewPathSetupType creates a PATH-SETUP-TYPE TLV.
func NewPathSetupType(pst Pst) *PathSetupType {
	return &PathSetupType{
		PathSetupType: pst,
	}
}

// ExtendedAssociationID represents the EXTENDED-ASSOCIATION-ID TLV (RFC 8697).
type ExtendedAssociationID struct {
	Color    uint32
	Endpoint netip.Addr
}

// Byte offsets of the fields of an EXTENDED-ASSOCIATION-ID TLV value.
const (
	ExtendedAssociationIDColorOffset    = 0
	ExtendedAssociationIDEndpointOffset = 4
)

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
func (tlv *ExtendedAssociationID) Serialize() ([]byte, error) {
	return tlv.serializeAs(tlv.Type()), nil
}

func (tlv *ExtendedAssociationID) serializeAs(typ TLVType) []byte {
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

// Type implements TLVInterface.
func (tlv *ExtendedAssociationID) Type() TLVType {
	return TLVExtendedAssociationID
}

// Len implements TLVInterface.
func (tlv *ExtendedAssociationID) Len() int {
	if tlv.Endpoint.Is4() {
		return int(TLVValueOffset + TLVExtendedAssociationIDIPv4ValueLength)
	} else if tlv.Endpoint.Is6() {
		return int(TLVValueOffset + TLVExtendedAssociationIDIPv6ValueLength)
	}

	return 0
}

// NewExtendedAssociationID creates an EXTENDED-ASSOCIATION-ID TLV.
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

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
func (tlv *ExtendedAssociationIDIPv4Juniper) Serialize() ([]byte, error) {
	if !tlv.Endpoint.Is4() {
		return nil, nil
	}

	return tlv.serializeAs(tlv.Type()), nil
}

// Type implements TLVInterface.
func (tlv *ExtendedAssociationIDIPv4Juniper) Type() TLVType {
	return TLVExtendedAssociationIDIPv4Juniper
}

// Len implements TLVInterface.
func (tlv *ExtendedAssociationIDIPv4Juniper) Len() int {
	if !tlv.Endpoint.Is4() {
		return 0
	}

	return int(TLVValueOffset + TLVExtendedAssociationIDIPv4ValueLength)
}

// PathSetupTypeCapability represents the PATH-SETUP-TYPE-CAPABILITY TLV (RFC 8408).
type PathSetupTypeCapability struct {
	PathSetupTypes Psts
	SubTLVs        []TLVInterface
}

// Layout of the PATH-SETUP-TYPE-CAPABILITY TLV value.
const (
	PathSetupTypeCapabilityFixedPartLength = 4
	PathSetupTypeCapabilityPSTCountOffset  = 3
	MaxPathSetupTypes                      = 255
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

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
func (tlv *PathSetupTypeCapability) Serialize() ([]byte, error) {
	pstCount := tlv.pstCount()
	if pstCount < 0 || pstCount > MaxPathSetupTypes {
		return nil, fmt.Errorf("PathSetupTypeCapability: PST count %d exceeds %d", pstCount, MaxPathSetupTypes)
	}

	fixedPartLen := PathSetupTypeCapabilityFixedPartLength + tlv.paddedPSTLength()

	value := make([]byte, fixedPartLen)
	value[PathSetupTypeCapabilityPSTCountOffset] = byte(pstCount)

	for i := range pstCount {
		value[PathSetupTypeCapabilityFixedPartLength+i] = byte(tlv.PathSetupTypes[i])
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

// Type implements TLVInterface.
func (tlv *PathSetupTypeCapability) Type() TLVType {
	return TLVPathSetupTypeCapability
}

// Len implements TLVInterface.
func (tlv *PathSetupTypeCapability) Len() int {
	length := PathSetupTypeCapabilityFixedPartLength
	length += tlv.paddedPSTLength()

	for _, subTLV := range tlv.SubTLVs {
		length += subTLV.Len()
	}

	return TLVValueOffset + length
}

func (tlv *PathSetupTypeCapability) isCapability() {}

// SubCapabilities returns sub-TLVs that implement CapabilityInterface.
func (tlv *PathSetupTypeCapability) SubCapabilities() []CapabilityInterface {
	ret := make([]CapabilityInterface, 0, len(tlv.SubTLVs))
	for _, subTLV := range tlv.SubTLVs {
		if c, ok := subTLV.(CapabilityInterface); ok {
			ret = append(ret, c)
		}
	}

	return ret
}

// PathSetupTypeList returns the advertised PSTs, limited by the PST count.
func (tlv *PathSetupTypeCapability) PathSetupTypeList() Psts {
	return tlv.PathSetupTypes[:tlv.pstCount()]
}

// HasPathSetupType reports whether the receiver advertises the given PST.
func (tlv *PathSetupTypeCapability) HasPathSetupType(pst Pst) bool {
	return slices.Contains(tlv.PathSetupTypeList(), pst)
}

// AssocType is an ASSOCIATION object type (RFC 8697).
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

var assocTypeDescriptions = map[AssocType]codePointInfo{
	AssocTypePathProtectionAssociation:              {nameAssocPathProtection, rfc(8745)},
	AssocTypeDisjointAssociation:                    {nameAssocDisjoint, rfc(8800)},
	AssocTypePolicyAssociation:                      {nameAssocPolicy, rfc(9005)},
	AssocTypeSingleSidedBidirectionalLSPAssociation: {"Single Sided Bidirectional LSP Association", rfc(9059)},
	AssocTypeDoubleSidedBidirectionalLSPAssociation: {"Double Sided Bidirectional LSP Association", rfc(9059)},
	AssocTypeSRPolicyAssociation:                    {nameAssocSRPolicy, rfc(9862)},
	AssocTypeVnAssociationType:                      {"VN Association Type", rfc(9358)},
	AssocTypeBidirectionalSRLSPAssociation:          {"Bidirectional SR LSP Association", refDraftPCESRBidirPath},
	AssocTypeP2MPSRPolicyAssociation:                {"P2MP SR Policy Association", refDraftPCESRP2MPPolicy},
	AssocTypeSRPolicyAssociationCisco:               {"SR Policy Association (Cisco-specific)", refNotIANAAssigned},
	AssocTypeSRPolicyAssociationJuniper:             {"SR Policy Association (Juniper-specific, deprecated)", refNotIANAAssigned},
}

// Name returns the registered name of the association Type.
func (at AssocType) Name() string { return assocTypeDescriptions[at].Description }

// Reference returns the defining document of the association Type.
func (at AssocType) Reference() Reference { return assocTypeDescriptions[at].Reference }

// String returns a human-readable representation of the association Type.
func (at AssocType) String() string {
	if name := at.Name(); name != "" {
		return fmt.Sprintf("%s (0x%04x)", name, uint16(at))
	}

	return fmt.Sprintf("Unknown AssocType (0x%04x)", uint16(at))
}

// StringWithReference returns the association Type with its reference.
func (at AssocType) StringWithReference() string {
	return withReference(at.String(), at.Reference())
}

// AssocTypeList represents the ASSOC-TYPE-LIST TLV (RFC 8697).
type AssocTypeList struct {
	AssocTypes []AssocType
}

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *AssocTypeList) Type() TLVType {
	return TLVAssocTypeList
}

// Len implements TLVInterface.
func (tlv *AssocTypeList) Len() int {
	length := len(tlv.AssocTypes) * 2

	padding := 0
	if length%4 != 0 {
		padding = 2
	}

	return TLVValueOffset + length + padding
}

func (tlv *AssocTypeList) isCapability() {}

// SRPolicyCandidatePathIdentifier represents the SRPOLICY-CPATH-ID TLV (draft-ietf-pce-segment-routing-policy-cp).
type SRPolicyCandidatePathIdentifier struct {
	ProtocolOrigin uint8
	OriginatorASN  uint32
	// OriginatorAddr stores IPv4 as native IPv4 and IPv6 in full 16-byte format.
	OriginatorAddr netip.Addr
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

// ProtocolOriginPCEP is the Protocol-Origin value for PCEP-initiated candidate paths (RFC 9256).
const ProtocolOriginPCEP = 0x0a

// DecodeFromBytes implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifier) DecodeFromBytes(data []byte) error {
	return decodeSRPolicyCPathID(data, &tlv.ProtocolOrigin, &tlv.OriginatorASN, &tlv.OriginatorAddr, &tlv.Discriminator)
}

// Serialize implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifier) Serialize() ([]byte, error) {
	return serializeSRPolicyCPathID(tlv.Type(), tlv.ProtocolOrigin, tlv.OriginatorASN, tlv.OriginatorAddr, tlv.Discriminator), nil
}

// Type implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifier) Type() TLVType {
	return TLVSRPolicyCPathID
}

// Len implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifier) Len() int {
	return int(TLVValueOffset + TLVSRPolicyCPathIDValueLength)
}

// SRPolicyCandidatePathIdentifierJuniper is the Juniper vendor-specific
// SR Policy candidate path identifier TLV (0xffe4). Same wire format as
// SRPolicyCandidatePathIdentifier, distinguished only by TLV type.
type SRPolicyCandidatePathIdentifierJuniper struct {
	ProtocolOrigin uint8
	OriginatorASN  uint32
	// OriginatorAddr stores IPv4 as native IPv4 and IPv6 in full 16-byte format.
	OriginatorAddr netip.Addr
	Discriminator  uint32
}

// DecodeFromBytes implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifierJuniper) DecodeFromBytes(data []byte) error {
	return decodeSRPolicyCPathID(data, &tlv.ProtocolOrigin, &tlv.OriginatorASN, &tlv.OriginatorAddr, &tlv.Discriminator)
}

// Serialize implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifierJuniper) Serialize() ([]byte, error) {
	return serializeSRPolicyCPathID(tlv.Type(), tlv.ProtocolOrigin, tlv.OriginatorASN, tlv.OriginatorAddr, tlv.Discriminator), nil
}

// Type implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifierJuniper) Type() TLVType {
	return TLVSRPolicyCPathIDJuniper
}

// Len implements TLVInterface.
func (tlv *SRPolicyCandidatePathIdentifierJuniper) Len() int {
	return int(TLVValueOffset + TLVSRPolicyCPathIDValueLength)
}

// decodeSRPolicyCPathID decodes the shared SRPOLICY-CPATH-ID wire format,
// used by both the standard and Juniper vendor-specific TLV variants.
func decodeSRPolicyCPathID(data []byte, protocolOrigin *uint8, originatorASN *uint32, originatorAddr *netip.Addr, discriminator *uint32) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("SRPolicyCandidatePathIdentifier: %w", err)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]
	if len(value) != int(TLVSRPolicyCPathIDValueLength) {
		return fmt.Errorf("SRPolicyCandidatePathIdentifier: invalid value length, expected %d, got %d", TLVSRPolicyCPathIDValueLength, len(value))
	}

	*protocolOrigin = value[SRPolicyCPathIDProtocolOriginOffset]

	*originatorASN = binary.BigEndian.Uint32(
		value[SRPolicyCPathIDASNOffset : SRPolicyCPathIDASNOffset+SRPolicyCPathIDASNLen],
	)

	addrBytes := value[SRPolicyCPathIDAddrOffset : SRPolicyCPathIDAddrOffset+IPv6AddrLen]

	if isIPv4Bytes(addrBytes) {
		var v4 [IPv4AddrLen]byte
		copy(v4[:], addrBytes[SRPolicyCPathIDIPv4Offset:])
		*originatorAddr = netip.AddrFrom4(v4)
	} else {
		var addr16 [IPv6AddrLen]byte
		copy(addr16[:], addrBytes)
		*originatorAddr = netip.AddrFrom16(addr16)
	}

	*discriminator = binary.BigEndian.Uint32(
		value[SRPolicyCPathIDDiscriminatorOffset : SRPolicyCPathIDDiscriminatorOffset+SRPolicyCPathIDDiscriminatorLen],
	)

	return nil
}

// serializeSRPolicyCPathID encodes the shared SRPOLICY-CPATH-ID wire format,
// used by both the standard and Juniper vendor-specific TLV variants.
func serializeSRPolicyCPathID(typ TLVType, protocolOrigin uint8, originatorASN uint32, originatorAddr netip.Addr, discriminator uint32) []byte {
	value := make([]byte, TLVSRPolicyCPathIDValueLength)

	value[SRPolicyCPathIDProtocolOriginOffset] = protocolOrigin

	binary.BigEndian.PutUint32(
		value[SRPolicyCPathIDASNOffset:SRPolicyCPathIDASNOffset+SRPolicyCPathIDASNLen],
		originatorASN,
	)

	switch {
	case !originatorAddr.IsValid():
		// keep zero

	case originatorAddr.Is4():
		ipv4 := originatorAddr.As4()

		copy(
			value[SRPolicyCPathIDAddrOffset+SRPolicyCPathIDIPv4Offset:SRPolicyCPathIDAddrOffset+SRPolicyCPathIDIPv4Offset+IPv4AddrLen],
			ipv4[:],
		)

	case originatorAddr.Is6():
		ipv6 := originatorAddr.As16()

		copy(
			value[SRPolicyCPathIDAddrOffset:SRPolicyCPathIDAddrOffset+IPv6AddrLen],
			ipv6[:],
		)
	}

	binary.BigEndian.PutUint32(
		value[SRPolicyCPathIDDiscriminatorOffset:SRPolicyCPathIDDiscriminatorOffset+SRPolicyCPathIDDiscriminatorLen],
		discriminator,
	)

	return AppendByteSlices(
		Uint16ToByteSlice(typ),
		Uint16ToByteSlice(TLVSRPolicyCPathIDValueLength),
		value,
	)
}

// SRPolicyCandidatePathPreference represents the SRPOLICY-CPATH-PREFERENCE TLV (draft-ietf-pce-segment-routing-policy-cp).
type SRPolicyCandidatePathPreference struct {
	Preference uint32
}

// DecodeFromBytes implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreference) DecodeFromBytes(data []byte) error {
	return decodeSRPolicyCPathPreference(data, &tlv.Preference)
}

// Serialize implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreference) Serialize() ([]byte, error) {
	return serializeSRPolicyCPathPreference(tlv.Type(), tlv.Preference), nil
}

// Type implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreference) Type() TLVType {
	return TLVSRPolicyCPathPreference
}

// Len implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreference) Len() int {
	return int(TLVValueOffset + TLVSRPolicyCPathPreferenceValueLength)
}

// SRPolicyCandidatePathPreferenceJuniper is the Juniper vendor-specific
// SR Policy candidate path preference TLV (0xffe5). Same wire format as
// SRPolicyCandidatePathPreference, distinguished only by TLV type.
type SRPolicyCandidatePathPreferenceJuniper struct {
	Preference uint32
}

// DecodeFromBytes implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreferenceJuniper) DecodeFromBytes(data []byte) error {
	return decodeSRPolicyCPathPreference(data, &tlv.Preference)
}

// Serialize implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreferenceJuniper) Serialize() ([]byte, error) {
	return serializeSRPolicyCPathPreference(tlv.Type(), tlv.Preference), nil
}

// Type implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreferenceJuniper) Type() TLVType {
	return TLVSRPolicyCPathPreferenceJuniper
}

// Len implements TLVInterface.
func (tlv *SRPolicyCandidatePathPreferenceJuniper) Len() int {
	return int(TLVValueOffset + TLVSRPolicyCPathPreferenceValueLength)
}

func decodeSRPolicyCPathPreference(data []byte, preference *uint32) error {
	valueLen, err := decodeTLVLength(data, false)
	if err != nil {
		return fmt.Errorf("SRPolicyCandidatePathPreference: %w", err)
	}

	if valueLen != int(TLVSRPolicyCPathPreferenceValueLength) {
		return fmt.Errorf("SRPolicyCandidatePathPreference: invalid value length %d", valueLen)
	}

	value := data[TLVValueOffset : TLVValueOffset+valueLen]

	*preference = binary.BigEndian.Uint32(value)

	return nil
}

func serializeSRPolicyCPathPreference(typ TLVType, preference uint32) []byte {
	value := make([]byte, TLVSRPolicyCPathPreferenceValueLength)

	binary.BigEndian.PutUint32(value, preference)

	return AppendByteSlices(
		Uint16ToByteSlice(typ),
		Uint16ToByteSlice(TLVSRPolicyCPathPreferenceValueLength),
		value,
	)
}

// Color represents the Color TLV (RFC 9863).
type Color struct {
	Color uint32
}

// DecodeFromBytes implements TLVInterface.
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

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *Color) Type() TLVType {
	return TLVColor
}

// Len implements TLVInterface.
func (tlv *Color) Len() int {
	return int(TLVValueOffset + TLVColorValueLength)
}

// UnknownTLV holds a TLV without a typed implementation, preserving its type
// and raw value for logging and unchanged re-serialization.
type UnknownTLV struct {
	Typ   TLVType
	Value []byte
}

// DecodeFromBytes implements TLVInterface.
func (tlv *UnknownTLV) DecodeFromBytes(data []byte) error {
	valueLen, err := decodeTLVLength(data, true)
	if err != nil {
		return fmt.Errorf("UnknownTLV: %w", err)
	}

	tlv.Typ = TLVType(binary.BigEndian.Uint16(data[TLVTypeOffset:TLVLengthOffset]))
	tlv.Value = data[TLVValueOffset : TLVValueOffset+valueLen]

	return nil
}

// Serialize implements TLVInterface.
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

// Type implements TLVInterface.
func (tlv *UnknownTLV) Type() TLVType {
	return tlv.Typ
}

// Len implements TLVInterface.
func (tlv *UnknownTLV) Len() int {
	return TLVValueOffset + paddedLength(len(tlv.Value), TLVAlignment)
}

func (tlv *UnknownTLV) isCapability() {}

// DecodeTLV decodes a single PCEP TLV.
func DecodeTLV(data []byte) (TLVInterface, error) {
	if len(data) < 2 {
		return nil, errors.New("insufficient data to read TLV type")
	}

	return decodeKnownTLV(data, TLVType(binary.BigEndian.Uint16(data[0:2])))
}

func decodeKnownTLV(data []byte, tlvType TLVType) (TLVInterface, error) {
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

func decodeUnknownTLV(data []byte, tlvType TLVType) (TLVInterface, error) {
	tlv := &UnknownTLV{}
	if err := tlv.DecodeFromBytes(data); err != nil {
		return nil, fmt.Errorf("error decoding unknown TLV type %x: %w", uint16(tlvType), err)
	}

	return tlv, nil
}

// DecodeTLVs decodes a sequence of PCEP TLVs.
func DecodeTLVs(data []byte) ([]TLVInterface, error) {
	return decodeTLVSequence(data, decodeKnownTLV)
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
