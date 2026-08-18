// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/nttcom/pola/pkg/table"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPCErrMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*PCErrMessage{
		"SingleError": {
			Errors: []*ErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1},
			},
		},
		"MultipleErrors": {
			Errors: []*ErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1},
				{ObjectType: ObjectTypeErrorError, ErrorType: 19, ErrorValue: 1},
			},
		},
		"SingleSRPWithError": {
			SRPs: []*SrpObject{
				{ObjectType: ObjectTypeSRPSRP, SrpID: 42},
			},
			Errors: []*ErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 24, ErrorValue: 1},
			},
		},
		"MultipleSRPsAndErrors": {
			SRPs: []*SrpObject{
				{ObjectType: ObjectTypeSRPSRP, SrpID: 1},
				{ObjectType: ObjectTypeSRPSRP, RFlag: true, SrpID: 2},
			},
			Errors: []*ErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 8},
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 9},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")

			var commonHeader CommonHeader
			require.NoError(t, commonHeader.DecodeFromBytes(raw[:CommonHeaderLength]), "common header decode failed")
			require.Equal(t, MessageTypeError, commonHeader.MessageType, "unexpected message type")
			require.Equal(t, len(raw), int(commonHeader.MessageLength), "MessageLength must match serialized size")

			var got PCErrMessage
			require.NoError(t, got.DecodeFromBytes(raw[CommonHeaderLength:]), "DecodeFromBytes failed")
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

		m := PCErrMessage{SRPs: []*SrpObject{{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}}}
		_, err := m.Serialize()
		assert.Error(t, err)
	})

	t.Run("ErrorObjectSerializeError", func(t *testing.T) {
		t.Parallel()

		m := PCErrMessage{Errors: []*ErrorObject{{Tlvs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}}}
		_, err := m.Serialize()
		assert.Error(t, err)
	})

	t.Run("MessageLengthOverflow", func(t *testing.T) {
		t.Parallel()

		m := PCErrMessage{Errors: []*ErrorObject{{Tlvs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65520)}}}}}
		_, err := m.Serialize()
		assert.ErrorContains(t, err, "exceeds")
	})
}

// Verify OriginatorASN is propagated to the SRPOLICY-CPATH-ID TLV.
func TestNewPCInitiateMessage_OriginatorASNReachesWire(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001)}

	cases := map[string]struct {
		opts        []Opt
		expectedASN uint32
	}{
		"OriginatorASNSet":     {opts: []Opt{VendorSpecific(RFCCompliant), OriginatorASN(65000)}, expectedASN: 65000},
		"OriginatorASNOmitted": {opts: []Opt{VendorSpecific(RFCCompliant)}, expectedASN: 0},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := NewPCInitiateMessage(1, "policy1", false, 0, segmentList, 100, 200, srcAddr, dstAddr, tt.opts...)
			require.NoError(t, err, "NewPCInitiateMessage failed")
			require.NotNil(t, m.AssociationObject, "RFC compliant PCInitiate must carry an ASSOCIATION object")

			var cpathID *SRPolicyCandidatePathIdentifier
			for _, tlv := range m.AssociationObject.TLVs {
				if id, ok := tlv.(*SRPolicyCandidatePathIdentifier); ok {
					cpathID = id
					break
				}
			}
			require.NotNil(t, cpathID, "SRPOLICY-CPATH-ID TLV missing from ASSOCIATION object")
			assert.Equal(t, tt.expectedASN, cpathID.OriginatorASN, "OriginatorASN not propagated to the TLV")

			raw, err := m.Serialize()
			require.NoError(t, err, "Serialize failed")

			expectedTLV := AppendByteSlices(
				[]uint8{0x00, 0x39, 0x00, 0x1c}, // SRPOLICY-CPATH-ID TLV: type=0x0039, len=28
				[]uint8{0x0a, 0x00, 0x00, 0x00}, // protocol origin + mbz
				Uint32ToByteSlice(tt.expectedASN),
				make([]uint8, 12), dstAddr.AsSlice(), // originator address (IPv4 in the 16 byte field)
				[]uint8{0x00, 0x00, 0x00, 0x01}, // discriminator
			)
			assert.True(t, bytes.Contains(raw, expectedTLV), "serialized message does not carry ASN %d in the SRPOLICY-CPATH-ID TLV", tt.expectedASN)
		})
	}
}

// Verify object selection for each PccType.
func TestNewPCInitiateMessage_VendorObjectSelection(t *testing.T) {
	t.Parallel()

	srcAddr := netip.MustParseAddr("192.0.2.1")
	dstAddr := netip.MustParseAddr("192.0.2.2")
	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001)}

	cases := map[string]struct {
		pccType         PccType
		wantAssociation bool
		wantAssocType   AssocType
		wantVendorInfo  bool
	}{
		"JuniperLegacy": {
			pccType:         JuniperLegacy,
			wantAssociation: true,
			wantAssocType:   AssociationTypeSRPolicyAssociationJuniper,
		},
		"CiscoLegacy": {
			pccType:        CiscoLegacy,
			wantVendorInfo: true,
		},
		"RFCCompliant": {
			pccType:         RFCCompliant,
			wantAssociation: true,
			wantAssocType:   AssociationTypeSRPolicyAssociation,
			wantVendorInfo:  true,
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			m, err := NewPCInitiateMessage(1, "policy1", false, 0, segmentList, 100, 200, srcAddr, dstAddr, VendorSpecific(tt.pccType))
			require.NoError(t, err, "NewPCInitiateMessage failed")

			if tt.wantAssociation {
				require.NotNil(t, m.AssociationObject, "AssociationObject should be set")
				assert.Equal(t, tt.wantAssocType, m.AssociationObject.AssocType, "unexpected AssocType")
			} else {
				assert.Nil(t, m.AssociationObject, "AssociationObject should not be set")
			}

			if tt.wantVendorInfo {
				require.NotNil(t, m.VendorInformationObject, "VendorInformationObject should be set")
				assert.Equal(t, EnterpriseNumberCisco, m.VendorInformationObject.EnterpriseNumber, "unexpected EnterpriseNumber")
			} else {
				assert.Nil(t, m.VendorInformationObject, "VendorInformationObject should not be set")
			}
		})
	}
}

func TestMessageType_String(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		typ  MessageType
		want string
	}{
		"Open":    {MessageTypeOpen, "Open (0x01)"},
		"Report":  {MessageTypeReport, "Report (0x0a)"},
		"Unknown": {MessageType(0x7f), "Unknown MessageType (0x7f)"},
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
		typ  MessageType
		want string
	}{
		"Open":    {MessageTypeOpen, "Open (0x01) [RFC5440]"},
		"Report":  {MessageTypeReport, "Report (0x0a) [RFC8231]"},
		"Unknown": {MessageType(0x7f), "Unknown MessageType (0x7f)"},
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

	want := NewOpenMessage(7, 30, []CapabilityInterface{
		&SRPCECapability{MaximumSidDepth: 10},
	})

	raw, err := want.Serialize()
	require.NoError(t, err, "Serialize failed")

	var commonHeader CommonHeader
	require.NoError(t, commonHeader.DecodeFromBytes(raw[:CommonHeaderLength]))
	assert.Equal(t, MessageTypeOpen, commonHeader.MessageType)
	assert.Equal(t, len(raw), int(commonHeader.MessageLength))

	var got OpenMessage
	require.NoError(t, got.DecodeFromBytes(raw[CommonHeaderLength:]), "DecodeFromBytes failed")
	assert.Equal(t, want, &got)
}

func TestOpenMessage_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TruncatedHeader":         {0x01, 0x02},
		"WrongObjectClass":        NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, 8).Serialize(),
		"WrongObjectType":         NewCommonObjectHeader(ObjectClassOpen, ObjectType(2), 8).Serialize(),
		"ObjectLengthZero":        NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, 0).Serialize(),
		"ObjectLengthExceedsBody": NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, 100).Serialize(),
		"MalformedTLV": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, 12).Serialize(),
			[]uint8{0x20, 0x1e, 0x78, 0x01}, // version/flags, keepalive, deadtime, sid
			[]uint8{0x00, 0x27, 0x00, 0x04}, // TLV header advertising a value longer than available
		),
		"TrailingBytes": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, 8).Serialize(),
			[]uint8{0x20, 0x1e, 0x78, 0x01}, // version/flags, keepalive, deadtime, sid
			[]uint8{0xff},                   // trailing byte past the declared OPEN object length
		),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m OpenMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestOpenMessage_Serialize_Error(t *testing.T) {
	t.Parallel()

	m := OpenMessage{OpenObject: &OpenObject{Caps: []CapabilityInterface{&UnknownTLV{Value: make([]byte, 65536)}}}}
	_, err := m.Serialize()
	assert.Error(t, err)
}

func TestOpenMessage_Serialize_MessageLengthOverflow(t *testing.T) {
	t.Parallel()

	m := OpenMessage{OpenObject: &OpenObject{Caps: []CapabilityInterface{
		&UnknownTLV{Value: make([]byte, 65520)},
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
		"KeepaliveWithBody":              {0x20, uint8(MessageTypeKeepalive), 0x00, 0x08},
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var h CommonHeader
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
		"Version1":           {[]uint8{0x20, uint8(MessageTypeKeepalive), 0x00, 0x04}, false},
		"UnsupportedVersion": {[]uint8{0x40, uint8(MessageTypeKeepalive), 0x00, 0x04}, true},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var h CommonHeader
			err := h.DecodeFromBytes(tt.header)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, PCEPVersion, h.Version)
			}
		})
	}
}

func TestKeepaliveMessage(t *testing.T) {
	t.Parallel()

	m := NewKeepaliveMessage()

	raw, err := m.Serialize()
	require.NoError(t, err)

	var commonHeader CommonHeader
	require.NoError(t, commonHeader.DecodeFromBytes(raw))
	assert.Equal(t, MessageTypeKeepalive, commonHeader.MessageType)
	assert.Equal(t, CommonHeaderLength, commonHeader.MessageLength)
	assert.Len(t, raw, int(CommonHeaderLength))
}

func TestCloseMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]CloseReason{
		"NoExplanation":       CloseReasonNoExplanationProvided,
		"DeadTimerExpired":    CloseReasonDeadTimerExpired,
		"TooManyUnrecognized": CloseReasonTooManyUnrecognizedPCEPMessages,
	}

	for name, reason := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := NewCloseMessage(reason)

			raw, err := want.Serialize()
			require.NoError(t, err, "Serialize failed")

			var commonHeader CommonHeader
			require.NoError(t, commonHeader.DecodeFromBytes(raw[:CommonHeaderLength]))
			assert.Equal(t, MessageTypeClose, commonHeader.MessageType)
			assert.Equal(t, len(raw), int(commonHeader.MessageLength))

			var got CloseMessage
			require.NoError(t, got.DecodeFromBytes(raw[CommonHeaderLength:]), "DecodeFromBytes failed")
			assert.Equal(t, want, &got)
		})
	}
}

func TestPCErrMessage_SRPIDs(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		msg  *PCErrMessage
		want []uint32
	}{
		"NoSRPs": {&PCErrMessage{}, nil},
		"MultipleSRPs": {
			&PCErrMessage{SRPs: []*SrpObject{{SrpID: 1}, {SrpID: 2}}},
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

	tlvs := []TLVInterface{&SymbolicPathName{Name: "err"}}
	m := NewPCErrMessage(6, 1, tlvs)

	want := &PCErrMessage{
		Errors: []*ErrorObject{{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1, Tlvs: tlvs}},
	}
	assert.Equal(t, want, m)
}

func TestNewPCRptMessage(t *testing.T) {
	t.Parallel()

	assert.Equal(t, &PCRptMessage{StateReports: []*StateReport{}}, NewPCRptMessage())
}

func TestPCRptMessage_DecodeFromBytes(t *testing.T) {
	t.Parallel()

	rawBandwidth := func(bw uint32) []uint8 {
		header := NewCommonObjectHeader(ObjectClassBandwidth, ObjectType(1), commonObjectHeaderLength+4)
		return AppendByteSlices(header.Serialize(), Uint32ToByteSlice(bw))
	}

	srp := &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1}
	lsp := &LSPObject{ObjectType: ObjectTypeLSPLSP, PlspID: 5, OFlag: 1, AFlag: true, DFlag: true}
	ero := &EroObject{ObjectType: ObjectTypeEROExplicitRoute}
	eroRaw, err := ero.Serialize()
	require.NoError(t, err)
	srpRaw, err := srp.Serialize()
	require.NoError(t, err)
	lspRaw, err := lsp.Serialize()
	require.NoError(t, err)

	baseReport := func() []uint8 {
		return AppendByteSlices(srpRaw, lspRaw, eroRaw)
	}

	newBaseStateReport := func() *StateReport {
		sr := NewStateReport()
		sr.SrpObject, sr.LSPObject, sr.EroObject = srp, lsp, ero
		return sr
	}

	t.Run("SingleReport", func(t *testing.T) {
		t.Parallel()

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(baseReport()))
		assert.Equal(t, []*StateReport{newBaseStateReport()}, m.StateReports)
	})

	// An LSP object starts a new StateReport even without a preceding SRP.
	t.Run("LSPOnlyStartsNewReport", func(t *testing.T) {
		t.Parallel()

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(AppendByteSlices(lspRaw, eroRaw)))

		want := newBaseStateReport()
		want.SrpObject = &SrpObject{}
		assert.Equal(t, []*StateReport{want}, m.StateReports)
	})

	t.Run("MultipleReports", func(t *testing.T) {
		t.Parallel()

		srp2 := &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 2}
		lsp2 := &LSPObject{ObjectType: ObjectTypeLSPLSP, PlspID: 6, OFlag: 1, AFlag: true, DFlag: true}
		srp2Raw, err := srp2.Serialize()
		require.NoError(t, err)
		lsp2Raw, err := lsp2.Serialize()
		require.NoError(t, err)

		raw := AppendByteSlices(baseReport(), srp2Raw, lsp2Raw, eroRaw)

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(raw))

		second := newBaseStateReport()
		second.SrpObject, second.LSPObject = srp2, lsp2

		assert.Equal(t, []*StateReport{newBaseStateReport(), second}, m.StateReports)
	})

	// An unrecognized object is skipped without breaking SRP/LSP correlation.
	t.Run("SkipsUnregisteredObjectClass", func(t *testing.T) {
		t.Parallel()

		ep, err := NewEndpointsObject(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
		require.NoError(t, err)
		epRaw, err := ep.Serialize()
		require.NoError(t, err)

		raw := AppendByteSlices(srpRaw, epRaw, lspRaw, eroRaw)

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(raw))
		assert.Equal(t, []*StateReport{newBaseStateReport()}, m.StateReports)
	})

	t.Run("WithMetricsBandwidthLSPAAssociationVendorInfo", func(t *testing.T) {
		t.Parallel()

		metric1 := &MetricObject{ObjectType: ObjectType(1), CFlag: true, MetricType: 2}
		metric2 := &MetricObject{ObjectType: ObjectType(1), BFlag: true, MetricType: 1}
		lspa := &LSPAObject{ObjectType: ObjectType(1), SetupPriority: 7, HoldingPriority: 7, LFlag: true}
		assoc := &AssociationObject{
			ObjectType: ObjectTypeAssociationIPv4, AssocType: AssociationTypeSRPolicyAssociation,
			AssocID: 1, AssocSrc: netip.MustParseAddr("192.0.2.1"),
		}
		vendorInfo := &VendorInformationObject{ObjectType: ObjectTypeVendorSpecificConstraints, EnterpriseNumber: EnterpriseNumberCisco}

		assocRaw, err := assoc.Serialize()
		require.NoError(t, err)
		vendorInfoRaw, err := vendorInfo.Serialize()
		require.NoError(t, err)

		raw := AppendByteSlices(
			srpRaw, lspRaw,
			metric1.Serialize(), metric2.Serialize(),
			rawBandwidth(1000),
			lspa.Serialize(),
			assocRaw,
			vendorInfoRaw,
			eroRaw,
		)

		var m PCRptMessage
		require.NoError(t, m.DecodeFromBytes(raw))

		want := newBaseStateReport()
		want.MetricObjects = []*MetricObject{metric1, metric2}
		want.BandwidthObjects = []*BandwidthObject{{ObjectType: ObjectType(1), Bandwidth: 1000}}
		want.LSPAObject = lspa
		want.AssociationObject = assoc
		want.VendorInformationObject = vendorInfo

		assert.Equal(t, []*StateReport{want}, m.StateReports)
	})

	t.Run("Errors", func(t *testing.T) {
		t.Parallel()

		ep, err := NewEndpointsObject(netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("192.0.2.1"))
		require.NoError(t, err)
		epRaw, err := ep.Serialize()
		require.NoError(t, err)

		cases := map[string][]uint8{
			"TruncatedObjectHeader":       {0x01, 0x02},
			"EmptyBody":                   {},
			"OnlyUnregisteredObjectClass": epRaw,
			"MalformedSRPBody": AppendByteSlices(
				NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, commonObjectHeaderLength+4).Serialize(),
				make([]uint8, 4),
			),
			"MalformedBandwidthBody": NewCommonObjectHeader(ObjectClassBandwidth, ObjectType(1), commonObjectHeaderLength).Serialize(),
			"MalformedMetricBody":    NewCommonObjectHeader(ObjectClassMetric, ObjectType(1), commonObjectHeaderLength).Serialize(),
			// An SRP in a state report must be followed by an LSP.
			"SRPWithNoLSP":       srpRaw,
			"TwoSRPsInARowNoLSP": AppendByteSlices(srpRaw, srpRaw),
		}

		for name, body := range cases {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				var m PCRptMessage
				assert.Error(t, m.DecodeFromBytes(body))
			})
		}
	})
}

func TestPCRptMessage_DecodeFromBytes_MalformedNestedObjectBody(t *testing.T) {
	t.Parallel()

	srp := &SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1}
	lsp := &LSPObject{ObjectType: ObjectTypeLSPLSP, PlspID: 5, OFlag: 1, AFlag: true, DFlag: true}
	srpRaw, err := srp.Serialize()
	require.NoError(t, err)
	lspRaw, err := lsp.Serialize()
	require.NoError(t, err)
	prefix := AppendByteSlices(srpRaw, lspRaw)

	cases := map[string][]uint8{
		"TruncatedBandwidthBody": AppendByteSlices(prefix, NewCommonObjectHeader(ObjectClassBandwidth, ObjectType(1), commonObjectHeaderLength).Serialize()),
		"TruncatedMetricBody":    AppendByteSlices(prefix, NewCommonObjectHeader(ObjectClassMetric, ObjectType(1), commonObjectHeaderLength).Serialize()),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m PCRptMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestPCRptMessage_DecodeFromBytes_MalformedObjectLength(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"ObjectLengthZero":                      NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, 0).Serialize(),
		"ObjectLengthExceedsBody":               NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, 100).Serialize(),
		"ObjectLengthNotMultipleOf4":            NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, 6).Serialize(),
		"UnregisteredObjectClassWithZeroLength": NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, 0).Serialize(),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m PCRptMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestPCRptMessage_DecodeFromBytes_ObjectBeforeSRPLSP(t *testing.T) {
	t.Parallel()

	metric := &MetricObject{ObjectType: ObjectType(1), CFlag: true, MetricType: 2}

	cases := map[string][]uint8{
		"MetricBeforeSRP": metric.Serialize(),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m PCRptMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestNewPCUpdMessage(t *testing.T) {
	t.Parallel()

	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001), table.NewSegmentSRMPLS(16002)}

	m, err := NewPCUpdMessage(1, "policy1", 5, segmentList)
	require.NoError(t, err)

	raw, err := m.Serialize()
	require.NoError(t, err)

	var commonHeader CommonHeader
	require.NoError(t, commonHeader.DecodeFromBytes(raw[:CommonHeaderLength]))
	assert.Equal(t, MessageTypeUpdate, commonHeader.MessageType)
	assert.Equal(t, len(raw), int(commonHeader.MessageLength))

	body := raw[CommonHeaderLength:]

	var srpHeader CommonObjectHeader
	require.NoError(t, srpHeader.DecodeFromBytes(body))
	var srp SrpObject
	require.NoError(t, srp.DecodeFromBytes(srpHeader.ObjectType, body[commonObjectHeaderLength:srpHeader.ObjectLength]))
	assert.Equal(t, m.SrpObject, &srp)
	body = body[srpHeader.ObjectLength:]

	var lspHeader CommonObjectHeader
	require.NoError(t, lspHeader.DecodeFromBytes(body))
	var lsp LSPObject
	require.NoError(t, lsp.DecodeFromBytes(lspHeader.ObjectType, body[commonObjectHeaderLength:lspHeader.ObjectLength]))
	assert.Equal(t, m.LSPObject, &lsp)
	body = body[lspHeader.ObjectLength:]

	var eroHeader CommonObjectHeader
	require.NoError(t, eroHeader.DecodeFromBytes(body))
	var ero EroObject
	require.NoError(t, ero.DecodeFromBytes(eroHeader.ObjectType, body[commonObjectHeaderLength:eroHeader.ObjectLength]))
	assert.Equal(t, m.EroObject, &ero)
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

			_, err := NewPCUpdMessage(1, "policy1", 5, segs)
			assert.Error(t, err)
		})
	}
}

func TestPCUpdMessage_Serialize_Error(t *testing.T) {
	t.Parallel()

	badSubo := &SREroSubobject{
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       NAITypeSRIPv4Node, // LocalAddr is required for this NAI type
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	m := &PCUpdMessage{
		SrpObject: &SrpObject{},
		LSPObject: &LSPObject{},
		EroObject: &EroObject{EroSubobjects: []EroSubobject{badSubo}},
	}

	_, err := m.Serialize()
	assert.Error(t, err)
}

func TestPCUpdMessage_Serialize_SrpAndLSPObjectErrors(t *testing.T) {
	t.Parallel()

	cases := map[string]*PCUpdMessage{
		"SrpObjectSerializeError": {
			SrpObject: &SrpObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}},
			LSPObject: &LSPObject{},
			EroObject: &EroObject{},
		},
		"LSPObjectSerializeError": {
			SrpObject: &SrpObject{},
			LSPObject: &LSPObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}},
			EroObject: &EroObject{},
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

	subobjects := make([]EroSubobject, 8192)
	for i := range subobjects {
		subobjects[i] = &SREroSubobject{
			SubobjectType: SubobjectTypeEROSR,
			NAIType:       NAITypeSRAbsent,
			Segment:       table.NewSegmentSRMPLS(16001),
		}
	}
	ero := &EroObject{ObjectType: ObjectTypeEROExplicitRoute, EroSubobjects: subobjects}

	pcupd := &PCUpdMessage{SrpObject: &SrpObject{}, LSPObject: &LSPObject{}, EroObject: ero}
	_, err := pcupd.Serialize()
	assert.ErrorContains(t, err, "exceeds")

	pcinitiate := &PCInitiateMessage{SrpObject: &SrpObject{}, LSPObject: &LSPObject{}, EroObject: ero}
	_, err = pcinitiate.Serialize()
	assert.ErrorContains(t, err, "exceeds")
}

func TestCloseMessage_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	cases := map[string][]uint8{
		"TruncatedObjectHeader":   {0x01, 0x02},
		"WrongObjectClass":        NewCommonObjectHeader(ObjectClassOpen, ObjectTypeOpenOpen, 8).Serialize(),
		"WrongObjectType":         NewCommonObjectHeader(ObjectClassClose, ObjectType(2), 8).Serialize(),
		"ObjectLengthHeaderOnly":  NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, commonObjectHeaderLength).Serialize(),
		"ObjectLengthZero":        NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, 0).Serialize(),
		"ObjectLengthExceedsBody": NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, 100).Serialize(),
		"PartialBody": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, commonObjectHeaderLength+2).Serialize(),
			make([]uint8, 2),
		),
		"TrailingBytes": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassClose, ObjectTypeCloseClose, commonObjectHeaderLength+4).Serialize(),
			make([]uint8, 4),
			[]uint8{0xff}, // trailing byte past the declared CLOSE object length
		),
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m CloseMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestPCErrMessage_DecodeFromBytes_Errors(t *testing.T) {
	t.Parallel()

	validSRP, err := (&SrpObject{ObjectType: ObjectTypeSRPSRP, SrpID: 1}).Serialize()
	require.NoError(t, err)

	cases := map[string][]uint8{
		"TruncatedObjectHeader":        {0x01, 0x02},
		"InvalidObjectLength":          NewCommonObjectHeader(ObjectClassPCEPError, ObjectTypeErrorError, 5).Serialize(),
		"ObjectBodyExtendsPastMessage": NewCommonObjectHeader(ObjectClassPCEPError, ObjectTypeErrorError, 12).Serialize(),
		"MalformedPCEPErrorTLV": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassPCEPError, ObjectTypeErrorError, 12).Serialize(),
			[]uint8{0x00, 0x00, 0x06, 0x01}, // Error-Type=6, Error-Value=1
			[]uint8{0x00, 0x27, 0x00, 0xff}, // TLV length exceeds available data
		),
		"MalformedSRPBody": AppendByteSlices(
			NewCommonObjectHeader(ObjectClassSRP, ObjectTypeSRPSRP, commonObjectHeaderLength+4).Serialize(),
			make([]uint8, 4),
		),
		// RFC 5440 §6.7 requires at least one PCEP-ERROR object.
		"NoErrorObjectPresent": validSRP,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var m PCErrMessage
			assert.Error(t, m.DecodeFromBytes(body))
		})
	}
}

func TestPCInitiateMessage_Serialize_Errors(t *testing.T) {
	t.Parallel()

	badLenSubo := &SREroSubobject{
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       NAITypeSRUnnumberedAdjacency, // unsupported NAI type
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}
	badSerializeSubo := &SREroSubobject{
		SubobjectType: SubobjectTypeEROSR,
		NAIType:       NAITypeSRIPv4Node, // requires LocalAddr, which is absent here
		MFlag:         true,
		Segment:       table.NewSegmentSRMPLS(16001),
	}

	cases := map[string]*PCInitiateMessage{
		"SrpObjectSerializeError": {
			SrpObject: &SrpObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}}, LSPObject: &LSPObject{},
		},
		"LSPObjectSerializeError": {
			SrpObject: &SrpObject{}, LSPObject: &LSPObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65536)}}},
		},
		"EroObjectUnsupportedNAIError": {
			SrpObject: &SrpObject{}, LSPObject: &LSPObject{},
			EroObject: &EroObject{EroSubobjects: []EroSubobject{badLenSubo}},
		},
		"EndpointsObjectLenError": {
			SrpObject: &SrpObject{}, LSPObject: &LSPObject{},
			EndpointsObject: &EndpointsObject{SrcAddr: netip.MustParseAddr("10.0.0.1"), DstAddr: netip.MustParseAddr("2001:db8::1")},
		},
		"EroObjectSerializeError": {
			SrpObject: &SrpObject{}, LSPObject: &LSPObject{},
			EroObject: &EroObject{EroSubobjects: []EroSubobject{badSerializeSubo}},
		},
		"AssociationObjectSerializeError": {
			SrpObject: &SrpObject{}, LSPObject: &LSPObject{},
			AssociationObject: &AssociationObject{},
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

	m := &PCInitiateMessage{
		SrpObject: &SrpObject{TLVs: []TLVInterface{&UnknownTLV{Value: make([]byte, 65516)}}},
		LSPObject: &LSPObject{},
	}
	raw, err := m.Serialize()
	require.Nil(t, raw)
	assert.ErrorContains(t, err, "exceeds")
}

func TestNewPCInitiateMessage_LSPDelete(t *testing.T) {
	t.Parallel()

	segmentList := []table.Segment{table.NewSegmentSRMPLS(16001)}
	m, err := NewPCInitiateMessage(1, "policy1", true, 5, segmentList, 100, 200, netip.Addr{}, netip.Addr{})
	require.NoError(t, err)

	assert.Equal(t, uint32(5), m.LSPObject.PlspID)
	assert.Nil(t, m.EndpointsObject)
	assert.Nil(t, m.EroObject)
	assert.Nil(t, m.AssociationObject)
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
		opts        []Opt
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
			segmentList: validSeg, srcAddr: v6a, dstAddr: v6b, opts: []Opt{VendorSpecific(JuniperLegacy)},
		},
		"UndefinedPccType": {
			segmentList: validSeg, srcAddr: v4a, dstAddr: v4b, opts: []Opt{VendorSpecific(PccType(99))},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewPCInitiateMessage(1, "policy1", false, 0, tt.segmentList, 100, 200, tt.srcAddr, tt.dstAddr, tt.opts...)
			assert.Error(t, err)
		})
	}
}
