// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep_test

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/packet/pcep"
	"github.com/nttcom/pola/pkg/table"
)

const testPolicyName = "policy1"

func TestPCErrMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.PCErrMessage{
		"SingleError": {
			Errors: []*pcep.ErrorObject{
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1},
			},
		},
		"MultipleErrors": {
			Errors: []*pcep.ErrorObject{
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1},
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 19, ErrorValue: 1},
			},
		},
		"SingleSRPWithError": {
			SRPs: []*pcep.SrpObject{
				{ObjectType: pcep.ObjectTypeSRPSRP, SrpID: 42},
			},
			Errors: []*pcep.ErrorObject{
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 24, ErrorValue: 1},
			},
		},
		"SingleErrorWithOpen": {
			Errors: []*pcep.ErrorObject{
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 1, ErrorValue: 4},
			},
			Open: &pcep.OpenObject{ObjectType: pcep.ObjectTypeOpenOpen, Version: 1, Keepalive: 10, Deadtime: 40},
		},
		"MultipleSRPsAndErrors": {
			SRPs: []*pcep.SrpObject{
				{ObjectType: pcep.ObjectTypeSRPSRP, SrpID: 1},
				{ObjectType: pcep.ObjectTypeSRPSRP, RFlag: true, SrpID: 2},
			},
			Errors: []*pcep.ErrorObject{
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 6, ErrorValue: 8},
				{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 6, ErrorValue: 9},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")

			var commonHeader pcep.CommonHeader
			require.NoError(t, commonHeader.DecodeFromBytes(raw[:pcep.CommonHeaderLength]), "common header decode failed")
			require.Equal(t, pcep.MessageTypeError, commonHeader.MessageType, "unexpected message type")
			require.Equal(t, len(raw), int(commonHeader.MessageLength), "MessageLength must match serialized size")

			var got pcep.PCErrMessage
			require.NoError(t, got.DecodeFromBytes(raw[pcep.CommonHeaderLength:]), "DecodeFromBytes failed")
			assert.Equal(t, want, &got, "round-trip value mismatch")

			raw2, err := got.Serialize()
			require.NoError(t, err, "re-Serialize failed")
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}

func TestPCErrMessage_Serialize_Errors(t *testing.T) {
	t.Parallel()

	t.Run("SRPSerializeError", func(t *testing.T) {
		t.Parallel()

		m := pcep.PCErrMessage{SRPs: []*pcep.SrpObject{{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}}}
		_, err := m.Serialize()
		assert.Error(t, err)
	})

	t.Run("ErrorObjectSerializeError", func(t *testing.T) {
		t.Parallel()

		m := pcep.PCErrMessage{Errors: []*pcep.ErrorObject{{Tlvs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}}}
		_, err := m.Serialize()
		assert.Error(t, err)
	})

	t.Run("MessageLengthOverflow", func(t *testing.T) {
		t.Parallel()

		m := pcep.PCErrMessage{Errors: []*pcep.ErrorObject{{Tlvs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65520)}}}}}
		_, err := m.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})

	t.Run("OpenSerializeError", func(t *testing.T) {
		t.Parallel()

		m := pcep.PCErrMessage{
			Errors: []*pcep.ErrorObject{{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 1, ErrorValue: 4}},
			Open:   &pcep.OpenObject{Caps: []pcep.CapabilityInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}},
		}
		_, err := m.Serialize()
		assert.Error(t, err)
	})
}

// Verify pcep.OriginatorASN is propagated to the SRPOLICY-CPATH-ID TLV.
func TestNewPCInitiateMessage_OriginatorASNReachesWire(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001)}

	cases := map[string]struct {
		opts        []pcep.Opt
		expectedASN uint32
	}{
		"OriginatorASNSet":     {opts: []pcep.Opt{pcep.VendorSpecific(pcep.RFCCompliant), pcep.OriginatorASN(65000)}, expectedASN: 65000},
		"OriginatorASNOmitted": {opts: []pcep.Opt{pcep.VendorSpecific(pcep.RFCCompliant)}, expectedASN: 0},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := pcep.NewPCInitiateMessage(1, table.SRPolicy{
				Name: testPolicyName, SegmentList: segmentList, Color: 100, Preference: 200, SrcAddr: srcAddr, DstAddr: dstAddr,
			}, tt.opts...)
			require.NoError(t, err, "NewPCInitiateMessage failed")
			require.NotNil(t, m.AssociationObject, "RFC compliant PCInitiate must carry an ASSOCIATION object")

			var cpathID *pcep.SRPolicyCandidatePathIdentifier

			for _, tlv := range m.AssociationObject.TLVs {
				if id, ok := tlv.(*pcep.SRPolicyCandidatePathIdentifier); ok {
					cpathID = id
					break
				}
			}

			require.NotNil(t, cpathID, "SRPOLICY-CPATH-ID TLV missing from ASSOCIATION object")
			assert.Equal(t, tt.expectedASN, cpathID.OriginatorASN, "OriginatorASN not propagated to the TLV")

			raw, err := m.Serialize()
			require.NoError(t, err, "Serialize failed")

			expectedTLV := pcep.AppendByteSlices(
				[]uint8{0x00, 0x39, 0x00, 0x1c}, // SRPOLICY-CPATH-ID TLV: type=0x0039, len=28
				[]uint8{0x0a, 0x00, 0x00, 0x00}, // protocol origin + mbz
				pcep.Uint32ToByteSlice(tt.expectedASN),
				make([]uint8, 12), dstAddr.AsSlice(), // originator address (IPv4 in the 16 byte field)
				[]uint8{0x00, 0x00, 0x00, 0x01}, // discriminator
			)
			assert.True(t, bytes.Contains(raw, expectedTLV), "serialized message does not carry ASN %d in the SRPOLICY-CPATH-ID TLV", tt.expectedASN)
		})
	}
}

// Verify object selection for each pcep.PccType.
func TestNewPCInitiateMessage_VendorObjectSelection(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001)}

	cases := map[string]struct {
		pccType         pcep.PccType
		wantAssociation bool
		wantAssocType   pcep.AssocType
		wantVendorInfo  bool
	}{
		"JuniperLegacy": {
			pccType:         pcep.JuniperLegacy,
			wantAssociation: true,
			wantAssocType:   pcep.AssocTypeSRPolicyAssociationJuniper,
		},
		"CiscoLegacy": {
			pccType:        pcep.CiscoLegacy,
			wantVendorInfo: true,
		},
		"RFCCompliant": {
			pccType:         pcep.RFCCompliant,
			wantAssociation: true,
			wantAssocType:   pcep.AssocTypeSRPolicyAssociation,
			wantVendorInfo:  true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := pcep.NewPCInitiateMessage(1, table.SRPolicy{
				Name: testPolicyName, SegmentList: segmentList, Color: 100, Preference: 200, SrcAddr: srcAddr, DstAddr: dstAddr,
			}, pcep.VendorSpecific(tt.pccType))
			require.NoError(t, err, "NewPCInitiateMessage failed")

			if tt.wantAssociation {
				require.NotNil(t, m.AssociationObject, "AssociationObject should be set")
				assert.Equal(t, tt.wantAssocType, m.AssociationObject.AssocType, "unexpected AssocType")
			} else {
				assert.Nil(t, m.AssociationObject, "AssociationObject should not be set")
			}

			if tt.wantVendorInfo {
				require.NotNil(t, m.VendorInformationObject, "VendorInformationObject should be set")
				assert.Equal(t, pcep.EnterpriseNumberCisco, m.VendorInformationObject.EnterpriseNumber, "unexpected EnterpriseNumber")
			} else {
				assert.Nil(t, m.VendorInformationObject, "VendorInformationObject should not be set")
			}
		})
	}
}

func TestMessageType_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		typ  pcep.MessageType
		want string
	}{
		"Open":    {pcep.MessageTypeOpen, "Open (0x01)"},
		"Report":  {pcep.MessageTypeReport, "Report (0x0a)"},
		"Unknown": {pcep.MessageType(0x7f), "Unknown MessageType (0x7f)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.typ.String())
		})
	}
}

func TestMessageType_StringWithReference(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		typ  pcep.MessageType
		want string
	}{
		"Open":    {pcep.MessageTypeOpen, "Open (0x01) [RFC5440]"},
		"Report":  {pcep.MessageTypeReport, "Report (0x0a) [RFC8231]"},
		"Unknown": {pcep.MessageType(0x7f), "Unknown MessageType (0x7f)"},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.typ.StringWithReference())
		})
	}
}

func TestOpenMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	want := pcep.NewOpenMessage(7, 30, 120, []pcep.CapabilityInterface{
		pcep.NewSRPCECapability(false, false, 10),
	})

	raw, err := want.Serialize()
	require.NoError(t, err, "Serialize failed")

	var commonHeader pcep.CommonHeader
	require.NoError(t, commonHeader.DecodeFromBytes(raw[:pcep.CommonHeaderLength]))
	assert.Equal(t, pcep.MessageTypeOpen, commonHeader.MessageType)
	assert.Equal(t, len(raw), int(commonHeader.MessageLength))

	var got pcep.OpenMessage
	require.NoError(t, got.DecodeFromBytes(raw[pcep.CommonHeaderLength:]), "DecodeFromBytes failed")
	assert.Equal(t, want, &got)
}

func TestOpenMessage_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TruncatedHeader":         {0x01, 0x02},
		"WrongObjectClass":        pcep.NewCommonObjectHeader(pcep.ObjectClassClose, pcep.ObjectTypeCloseClose, 8).Serialize(),
		"WrongObjectType":         pcep.NewCommonObjectHeader(pcep.ObjectClassOpen, pcep.ObjectType(2), 8).Serialize(),
		"ObjectLengthZero":        pcep.NewCommonObjectHeader(pcep.ObjectClassOpen, pcep.ObjectTypeOpenOpen, 0).Serialize(),
		"ObjectLengthExceedsBody": pcep.NewCommonObjectHeader(pcep.ObjectClassOpen, pcep.ObjectTypeOpenOpen, 100).Serialize(),
		"MalformedTLV": pcep.AppendByteSlices(
			pcep.NewCommonObjectHeader(pcep.ObjectClassOpen, pcep.ObjectTypeOpenOpen, 12).Serialize(),
			[]uint8{0x20, 0x1e, 0x78, 0x01}, // version/flags, keepalive, deadtime, sid
			[]uint8{0x00, 0x27, 0x00, 0x04}, // TLV header advertising a value longer than available
		),
		"TrailingBytes": pcep.AppendByteSlices(
			pcep.NewCommonObjectHeader(pcep.ObjectClassOpen, pcep.ObjectTypeOpenOpen, 8).Serialize(),
			[]uint8{0x20, 0x1e, 0x78, 0x01}, // version/flags, keepalive, deadtime, sid
			[]uint8{0xff},                   // trailing byte past the declared OPEN object length
		),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m pcep.OpenMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestOpenMessage_Serialize_Error(t *testing.T) {
	t.Parallel()

	m := pcep.OpenMessage{OpenObject: &pcep.OpenObject{Caps: []pcep.CapabilityInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}}
	_, err := m.Serialize()
	assert.Error(t, err)
}

func TestOpenMessage_Serialize_MessageLengthOverflow(t *testing.T) {
	t.Parallel()

	m := pcep.OpenMessage{OpenObject: &pcep.OpenObject{Caps: []pcep.CapabilityInterface{
		&pcep.UnknownTLV{Value: make([]byte, 65520)},
	}}}
	_, err := m.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestCommonHeader_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TooShort":                       {0x20, 0x01, 0x00},
		"MessageLengthZero":              {0x20, 0x01, 0x00, 0x00},
		"MessageLengthBelowCommonHeader": {0x20, 0x01, 0x00, 0x03},
		"KeepaliveWithBody":              {0x20, uint8(pcep.MessageTypeKeepalive), 0x00, 0x08},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var h pcep.CommonHeader
			assert.Error(t, h.DecodeFromBytes(body))
		})
	}
}

func TestCommonHeader_DecodeFromBytes_Version(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		header  []uint8
		wantErr bool
	}{
		"Version1":           {[]uint8{0x20, uint8(pcep.MessageTypeKeepalive), 0x00, 0x04}, false},
		"UnsupportedVersion": {[]uint8{0x40, uint8(pcep.MessageTypeKeepalive), 0x00, 0x04}, true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var h pcep.CommonHeader

			err := h.DecodeFromBytes(tt.header)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, pcep.PCEPVersion, h.Version)
			}
		})
	}
}

func TestKeepaliveMessage(t *testing.T) {
	t.Parallel()

	m := pcep.NewKeepaliveMessage()

	raw, err := m.Serialize()
	require.NoError(t, err)

	var commonHeader pcep.CommonHeader
	require.NoError(t, commonHeader.DecodeFromBytes(raw))
	assert.Equal(t, pcep.MessageTypeKeepalive, commonHeader.MessageType)
	assert.Equal(t, pcep.CommonHeaderLength, commonHeader.MessageLength)
	assert.Len(t, raw, int(pcep.CommonHeaderLength))
}

func TestCloseMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]pcep.CloseReason{
		"NoExplanation":       pcep.CloseReasonNoExplanationProvided,
		"DeadTimerExpired":    pcep.CloseReasonDeadTimerExpired,
		"TooManyUnrecognized": pcep.CloseReasonTooManyUnrecognizedPCEPMessages,
	}

	for name, reason := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := pcep.NewCloseMessage(reason)

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")

			var commonHeader pcep.CommonHeader
			require.NoError(t, commonHeader.DecodeFromBytes(raw[:pcep.CommonHeaderLength]))
			assert.Equal(t, pcep.MessageTypeClose, commonHeader.MessageType)
			assert.Equal(t, len(raw), int(commonHeader.MessageLength))

			var got pcep.CloseMessage
			require.NoError(t, got.DecodeFromBytes(raw[pcep.CommonHeaderLength:]), "DecodeFromBytes failed")
			assert.Equal(t, want, &got)
		})
	}
}

func TestPCErrMessage_SRPIDs(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		msg  *pcep.PCErrMessage
		want []uint32
	}{
		"NoSRPs": {&pcep.PCErrMessage{}, nil},
		"MultipleSRPs": {
			&pcep.PCErrMessage{SRPs: []*pcep.SrpObject{{SrpID: 1}, {SrpID: 2}}},
			[]uint32{1, 2},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.msg.SRPIDs())
		})
	}
}

func TestNewPCErrMessage(t *testing.T) {
	t.Parallel()

	tlvs := []pcep.TLVInterface{&pcep.SymbolicPathName{Name: "err"}}
	m := pcep.NewPCErrMessage(6, 1, tlvs)

	want := &pcep.PCErrMessage{
		Errors: []*pcep.ErrorObject{{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1, Tlvs: tlvs}},
	}
	assert.Equal(t, want, m)
}

func TestNewPCErrMessageWithOpen(t *testing.T) {
	t.Parallel()

	openObject := pcep.NewOpenObject(0, 10, 40, nil)
	m := pcep.NewPCErrMessageWithOpen(1, 4, openObject)

	want := &pcep.PCErrMessage{
		Errors: []*pcep.ErrorObject{{ObjectType: pcep.ObjectTypeErrorError, ErrorType: 1, ErrorValue: 4}},
		Open:   openObject,
	}
	assert.Equal(t, want, m)
}

func TestNewPCRptMessage(t *testing.T) {
	t.Parallel()

	assert.Equal(t, &pcep.PCRptMessage{StateReports: []*pcep.StateReport{}}, pcep.NewPCRptMessage())
}

func TestPCRptMessage_DecodeFromBytes_MalformedObjectLength(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"ObjectLengthZero":                      pcep.NewCommonObjectHeader(pcep.ObjectClassSRP, pcep.ObjectTypeSRPSRP, 0).Serialize(),
		"ObjectLengthExceedsBody":               pcep.NewCommonObjectHeader(pcep.ObjectClassSRP, pcep.ObjectTypeSRPSRP, 100).Serialize(),
		"ObjectLengthNotMultipleOf4":            pcep.NewCommonObjectHeader(pcep.ObjectClassSRP, pcep.ObjectTypeSRPSRP, 6).Serialize(),
		"UnregisteredObjectClassWithZeroLength": pcep.NewCommonObjectHeader(pcep.ObjectClassClose, pcep.ObjectTypeCloseClose, 0).Serialize(),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m pcep.PCRptMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestPCRptMessage_DecodeFromBytes_ObjectBeforeSRPLSP(t *testing.T) {
	t.Parallel()

	metric := &pcep.MetricObject{ObjectType: pcep.ObjectType(1), CFlag: true, MetricType: 2}

	cases := map[string][]uint8{
		"MetricBeforeSRP": metric.Serialize(),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m pcep.PCRptMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestNewPCUpdMessage_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]table.Segment{
		"InvalidSegmentType":       {fakeSegment{}},
		"InvalidSecondSegmentType": {table.NewSegmentSRMPLS(16001), fakeSegment{}},
	}

	for name, segs := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := pcep.NewPCUpdMessage(1, table.SRPolicy{Name: testPolicyName, PlspID: 5, SegmentList: segs})
			assert.Error(t, err)
		})
	}
}

func TestPCUpdMessage_Serialize_Error(t *testing.T) {
	t.Parallel()

	badSubo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSRIPv4Node, // LocalAddr is required for this NAI type
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	m := &pcep.PCUpdMessage{
		SrpObject: &pcep.SrpObject{},
		LSPObject: &pcep.LSPObject{},
		EroObject: &pcep.EroObject{EroSubobjects: []pcep.EroSubobject{badSubo}},
	}

	_, err := m.Serialize()
	assert.Error(t, err)
}

func TestPCUpdMessage_Serialize_SrpAndLSPObjectErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]*pcep.PCUpdMessage{
		"SrpObjectSerializeError": {
			SrpObject: &pcep.SrpObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}},
			LSPObject: &pcep.LSPObject{},
			EroObject: &pcep.EroObject{},
		},
		"LSPObjectSerializeError": {
			SrpObject: &pcep.SrpObject{},
			LSPObject: &pcep.LSPObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}},
			EroObject: &pcep.EroObject{},
		},
	}

	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := m.Serialize()
			assert.Error(t, err)
		})
	}
}

func TestMessage_Serialize_RejectsOversizedMessage(t *testing.T) {
	t.Parallel()

	subobjects := make([]pcep.EroSubobject, 8192)
	for i := range subobjects {
		subobjects[i] = &pcep.SREroSubobject{
			SubobjectType: pcep.SubobjectTypeEROSR,
			NAIType:       pcep.NAITypeSRAbsent,
			Segment:       table.NewSegmentSRMPLS(16001),
		}
	}

	ero := &pcep.EroObject{ObjectType: pcep.ObjectTypeEROExplicitRoute, EroSubobjects: subobjects}

	pcupd := &pcep.PCUpdMessage{SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{}, EroObject: ero}
	_, err := pcupd.Serialize()
	require.ErrorContains(t, err, "exceeds")

	pcinitiate := &pcep.PCInitiateMessage{SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{}, EroObject: ero}
	_, err = pcinitiate.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestPCInitiateMessage_Serialize_Errors(t *testing.T) {
	t.Parallel()

	badLenSubo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSRUnnumberedAdjacency, // unsupported NAI type
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	badSerializeSubo := &pcep.SREroSubobject{
		SubobjectType: pcep.SubobjectTypeEROSR,
		NAIType:       pcep.NAITypeSRIPv4Node, // requires LocalAddr, which is absent here
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}

	cases := map[string]*pcep.PCInitiateMessage{
		"SrpObjectSerializeError": {
			SrpObject: &pcep.SrpObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}}, LSPObject: &pcep.LSPObject{},
		},
		"LSPObjectSerializeError": {
			SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65536)}}},
		},
		"EroObjectUnsupportedNAIError": {
			SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{},
			EroObject: &pcep.EroObject{EroSubobjects: []pcep.EroSubobject{badLenSubo}},
		},
		"EndpointsObjectLenError": {
			SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{},
			EndpointsObject: &pcep.EndpointsObject{SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("2001:db8::1")},
		},
		"EroObjectSerializeError": {
			SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{},
			EroObject: &pcep.EroObject{EroSubobjects: []pcep.EroSubobject{badSerializeSubo}},
		},
		"AssociationObjectSerializeError": {
			SrpObject: &pcep.SrpObject{}, LSPObject: &pcep.LSPObject{},
			AssociationObject: &pcep.AssociationObject{},
		},
	}

	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := m.Serialize()
			assert.Error(t, err)
		})
	}
}

func TestPCInitiateMessage_Serialize_MessageLengthBoundary(t *testing.T) {
	t.Parallel()

	m := &pcep.PCInitiateMessage{
		SrpObject: &pcep.SrpObject{TLVs: []pcep.TLVInterface{&pcep.UnknownTLV{Value: make([]byte, 65516)}}},
		LSPObject: &pcep.LSPObject{},
	}
	raw, err := m.Serialize()
	require.Nil(t, raw)
	assert.ErrorContains(t, err, "exceeds")
}

func TestNewPCInitiateDeleteMessage(t *testing.T) {
	t.Parallel()

	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001)}
	m, err := pcep.NewPCInitiateDeleteMessage(1, table.SRPolicy{
		Name: testPolicyName, PlspID: 5, SegmentList: segmentList, Color: 100, Preference: 200,
	})
	require.NoError(t, err)

	assert.True(t, m.SrpObject.RFlag, "deletion must set the SRP R flag")
	assert.Equal(t, uint32(5), m.LSPObject.PlspID)
	assert.Nil(t, m.EndpointsObject)
	assert.Nil(t, m.EroObject)
	assert.Nil(t, m.AssociationObject)
	assert.Nil(t, m.VendorInformationObject)
}

func TestNewPCInitiateDeleteMessage_InvalidSegmentType(t *testing.T) {
	t.Parallel()

	_, err := pcep.NewPCInitiateDeleteMessage(1, table.SRPolicy{
		Name: testPolicyName, PlspID: 5, SegmentList: []table.Segment{fakeSegment{}},
	})
	assert.Error(t, err)
}

func TestNewPCInitiateMessage_Errors(t *testing.T) {
	t.Parallel()

	v4a, v4b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	v6a, v6b := netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2")
	validSeg := []table.Segment{table.NewSegmentSRMPLS(16001)}

	cases := map[string]struct {
		segmentList []table.Segment
		srcAddr     netip.Addr
		dstAddr     netip.Addr
		opts        []pcep.Opt
	}{
		"InvalidSegmentType": {
			segmentList: []table.Segment{fakeSegment{}}, srcAddr: v4a, dstAddr: v4b,
		},
		"MismatchedEndpointFamilies": {
			segmentList: validSeg, srcAddr: v4a, dstAddr: v6b,
		},
		"InvalidSecondSegmentType": {
			segmentList: []table.Segment{table.NewSegmentSRMPLS(16001), fakeSegment{}}, srcAddr: v4a, dstAddr: v4b,
		},
		"JuniperLegacyRejectsIPv6": {
			segmentList: validSeg, srcAddr: v6a, dstAddr: v6b, opts: []pcep.Opt{pcep.VendorSpecific(pcep.JuniperLegacy)},
		},
		"UndefinedPccType": {
			segmentList: validSeg, srcAddr: v4a, dstAddr: v4b, opts: []pcep.Opt{pcep.VendorSpecific(pcep.PccType(99))},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := pcep.NewPCInitiateMessage(1, table.SRPolicy{
				Name: testPolicyName, SegmentList: tt.segmentList, Color: 100, Preference: 200, SrcAddr: tt.srcAddr, DstAddr: tt.dstAddr,
			}, tt.opts...)
			require.Error(t, err)
			assert.Nil(t, m)
		})
	}
}
