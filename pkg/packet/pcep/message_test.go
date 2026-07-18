// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPCErrMessage_RoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]*PCErrMessage{
		"SingleError": {
			Errors: []*PCEPErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1},
			},
		},
		"MultipleErrors": {
			Errors: []*PCEPErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 1},
				{ObjectType: ObjectTypeErrorError, ErrorType: 19, ErrorValue: 1},
			},
		},
		"SingleSRPWithError": {
			SRPs: []*SrpObject{
				{ObjectType: ObjectTypeSRPSRP, SrpID: 42},
			},
			Errors: []*PCEPErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 24, ErrorValue: 1},
			},
		},
		"MultipleSRPsAndErrors": {
			SRPs: []*SrpObject{
				{ObjectType: ObjectTypeSRPSRP, SrpID: 1},
				{ObjectType: ObjectTypeSRPSRP, RFlag: true, SrpID: 2},
			},
			Errors: []*PCEPErrorObject{
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 8},
				{ObjectType: ObjectTypeErrorError, ErrorType: 6, ErrorValue: 9},
			},
		},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := want.Serialize()

			var commonHeader CommonHeader
			require.NoError(t, commonHeader.DecodeFromBytes(raw[:CommonHeaderLength]), "common header decode failed")
			require.Equal(t, MessageTypeError, commonHeader.MessageType, "unexpected message type")
			require.Equal(t, len(raw), int(commonHeader.MessageLength), "MessageLength must match serialized size")

			var got PCErrMessage
			require.NoError(t, got.DecodeFromBytes(raw[CommonHeaderLength:]), "DecodeFromBytes failed")
			assert.Equal(t, want, &got, "round-trip value mismatch")

			raw2 := got.Serialize()
			assert.Equal(t, raw, raw2, "re-serialized bytes differ")
		})
	}
}
