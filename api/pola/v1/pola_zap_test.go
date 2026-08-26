// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/proto"
)

func TestSrCapability_MarshalLogObject(t *testing.T) {
	cap := &SrCapability{NaiSupported: true, Msd: proto.Uint32(8)}

	enc := zapcore.NewMapObjectEncoder()
	require.NoError(t, cap.MarshalLogObject(enc))

	assert.Equal(t, map[string]any{
		"UnlimitedMsd": false,
		"NaiSupported": true,
		"Msd":          uint32(8),
	}, enc.Fields)
}

func TestSrCapability_MarshalLogObject_MsdNotAdvertised(t *testing.T) {
	cap := &SrCapability{NaiSupported: true}

	enc := zapcore.NewMapObjectEncoder()
	require.NoError(t, cap.MarshalLogObject(enc))

	assert.Equal(t, map[string]any{
		"UnlimitedMsd": false,
		"NaiSupported": true,
	}, enc.Fields)
}

func TestCapability_MarshalLogObject_Sr(t *testing.T) {
	cap := &Capability{
		Type: CapabilityType_CAPABILITY_TYPE_SR,
		Detail: &Capability_Sr{Sr: &SrCapability{
			Msd: proto.Uint32(0),
		}},
	}

	enc := zapcore.NewMapObjectEncoder()
	require.NoError(t, cap.MarshalLogObject(enc))

	assert.Equal(t, "CAPABILITY_TYPE_SR", enc.Fields["Type"])
	sr, ok := enc.Fields["Sr"].(map[string]any)
	require.True(t, ok, "Sr field must be a nested object")
	assert.Equal(t, uint32(0), sr["Msd"])
}

func TestPathSetupTypeCapability_MarshalLogObject_SubCapabilities(t *testing.T) {
	cap := &PathSetupTypeCapability{
		PathSetupTypes: []uint32{1},
		SubCapabilities: []*Capability{
			{
				Type: CapabilityType_CAPABILITY_TYPE_SR,
				Detail: &Capability_Sr{Sr: &SrCapability{
					UnlimitedMsd: true,
				}},
			},
		},
	}

	enc := zapcore.NewMapObjectEncoder()
	require.NoError(t, cap.MarshalLogObject(enc))

	subCapabilities, ok := enc.Fields["SubCapabilities"].([]any)
	require.True(t, ok, "SubCapabilities field must be an array")
	require.Len(t, subCapabilities, 1)

	sr, ok := subCapabilities[0].(map[string]any)["Sr"].(map[string]any)
	require.True(t, ok, "Sr field must be a nested object")
	assert.Equal(t, true, sr["UnlimitedMsd"])
}

func TestPathSetupTypeCapability_MarshalLogObject_NoSubCapabilities(t *testing.T) {
	cap := &PathSetupTypeCapability{PathSetupTypes: []uint32{1}}

	enc := zapcore.NewMapObjectEncoder()
	require.NoError(t, cap.MarshalLogObject(enc))

	assert.NotContains(t, enc.Fields, "SubCapabilities")
}

func TestCapability_MarshalLogObject_NoDetail(t *testing.T) {
	cap := &Capability{Type: CapabilityType_CAPABILITY_TYPE_UNSPECIFIED}

	enc := zapcore.NewMapObjectEncoder()
	require.NoError(t, cap.MarshalLogObject(enc))

	assert.Equal(t, "CAPABILITY_TYPE_UNSPECIFIED", enc.Fields["Type"])
	assert.NotContains(t, enc.Fields, "Sr")
}
