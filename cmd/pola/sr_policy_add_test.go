// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/pkg/server"
)

// TestReasonConstantsMatchServer ensures the duplicated Reason constants stay in sync.
// cmd/pola duplicates these values to avoid depending on pkg/server.
func TestReasonConstantsMatchServer(t *testing.T) {
	assert.Equal(t, server.ReasonTEDDisabled, reasonTEDDisabled)
	assert.Equal(t, server.ReasonTEDNotSynced, reasonTEDNotSynced)
	assert.Equal(t, server.ReasonDestinationUnreachable, reasonDestinationUnreach)
	assert.Equal(t, server.ReasonMetricNotCarried, reasonMetricNotCarried)
	assert.Equal(t, server.ReasonPCEPSessionNotSynced, reasonPCEPSessionNotSynced)
	assert.Equal(t, server.ReasonSIDValidationFailed, reasonSIDValidationFailed)
}

func TestTranslateCreateSRPolicyError(t *testing.T) {
	newErr := func(code codes.Code, reason, msg string) error {
		st := status.New(code, msg)
		withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "pola"})
		if err != nil {
			t.Fatalf("failed to attach ErrorInfo: %v", err)
		}
		return withDetails.Err()
	}

	tests := []struct {
		name     string
		err      error
		wantHint string
	}{
		{"SID validation failure gets the no-sid-validate hint", newErr(codes.FailedPrecondition, "SID_VALIDATION_FAILED", "SID validation failed"), "--no-sid-validate"},
		{"TED disabled gets a TED hint, not the SID hint", newErr(codes.FailedPrecondition, "TED_DISABLED", "ted is disabled"), "enable TED sync"},
		{"TED not synced gets a retry hint", newErr(codes.FailedPrecondition, "TED_NOT_SYNCED", "no node in TED"), "retry shortly"},
		{"unsynced PCEP session gets a session hint", newErr(codes.FailedPrecondition, "PCEP_SESSION_NOT_SYNCED", "no synced session with 10.0.0.1"), "PCEP session"},
		{"unreachable destination gets a topology hint", newErr(codes.FailedPrecondition, "DESTINATION_UNREACHABLE", "next node not found"), "no path exists"},
		{"uncarried metric gets a metric hint", newErr(codes.FailedPrecondition, "METRIC_NOT_CARRIED", "metric METRIC_TYPE_TE not defined"), "not advertised"},
		{"invalid argument gets no hint", newErr(codes.InvalidArgument, "INVALID_REQUEST", "ASN must not be zero"), ""},
		{"a plain error passes through unchanged", assert.AnError, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := translateCreateSRPolicyError(tt.err)
			if tt.wantHint == "" {
				assert.NotContains(t, got.Error(), "hint:")
				return
			}
			assert.Contains(t, got.Error(), tt.wantHint)
		})
	}
}

func TestTranslateCreateSRPolicyError_SkipsNonErrorInfoDetails(t *testing.T) {
	st := status.New(codes.FailedPrecondition, "some failure")
	withDetails, err := st.WithDetails(&errdetails.RetryInfo{})
	require.NoError(t, err)

	got := translateCreateSRPolicyError(withDetails.Err())
	assert.NotContains(t, got.Error(), "hint:")
	assert.Contains(t, got.Error(), "some failure")
}

func validEndpointInput() inputFormat {
	return inputFormat{
		ASN: 65000,
		SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcAddr:         netip.MustParseAddr("192.0.2.1"),
			DstAddr:         netip.MustParseAddr("192.0.2.2"),
			Color:           100,
			SegmentList:     []segment{{SID: "16003"}},
		},
	}
}

func TestNewSRPolicyAddCmd_RunE(t *testing.T) {
	t.Run("no-sid-validate flag not registered", func(t *testing.T) {
		cmd := newSRPolicyAddCmd()
		err := cmd.RunE(&cobra.Command{}, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no-sid-validate")
	})

	t.Run("file flag not registered", func(t *testing.T) {
		cmd := newSRPolicyAddCmd()
		bare := &cobra.Command{}
		bare.Flags().Bool("no-sid-validate", false, "")
		err := cmd.RunE(bare, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'file' flag")
	})

	t.Run("missing file flag", func(t *testing.T) {
		cmd := newSRPolicyAddCmd()
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mandatory")
	})

	t.Run("file does not exist", func(t *testing.T) {
		cmd := newSRPolicyAddCmd()
		require.NoError(t, cmd.Flags().Set("file", filepath.Join(t.TempDir(), "missing.yaml")))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("not: [valid"), 0o600))
		cmd := newSRPolicyAddCmd()
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "YAML syntax error")
	})

	t.Run("success delegates to addSRPolicy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		yamlContent := "srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  srcAddr: 192.0.2.1\n" +
			"  dstAddr: 192.0.2.2\n" +
			"  name: pol1\n" +
			"  color: 100\n" +
			"  segmentList:\n" +
			"    - sid: \"16003\"\n"
		require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o600))

		client = &fakePCEServiceClient{}
		cmd := newSRPolicyAddCmd()
		require.NoError(t, cmd.Flags().Set("file", path))
		captureStdout(t, func() {
			require.NoError(t, cmd.RunE(cmd, []string{}))
		})
	})

	t.Run("addSRPolicy error is wrapped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("srPolicy:\n  name: incomplete\n"), 0o600))
		cmd := newSRPolicyAddCmd()
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add SR policy")
	})
}

func TestAddSRPolicy(t *testing.T) {
	t.Run("srcRouterID/dstRouterID and srcAddr/dstAddr are mutually exclusive", func(t *testing.T) {
		input := inputFormat{SRPolicy: srPolicy{
			SrcRouterID: "0000.0aff.0001",
			SrcAddr:     netip.MustParseAddr("192.0.2.1"),
		}}
		err := addSRPolicy(input, false, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("no-sid-validate prints a warning to stderr", func(t *testing.T) {
		client = &fakePCEServiceClient{}
		var stderr string
		captureStdout(t, func() {
			stderr = captureStderr(t, func() {
				require.NoError(t, addSRPolicy(validEndpointInput(), false, true))
			})
		})
		assert.Contains(t, stderr, "no-sid-validate")
	})

	t.Run("json output on success", func(t *testing.T) {
		client = &fakePCEServiceClient{}
		out := captureStdout(t, func() {
			require.NoError(t, addSRPolicy(validEndpointInput(), true, false))
		})
		assert.JSONEq(t, "{\"status\": \"success\"}\n", out)
	})

	t.Run("plain text output on success", func(t *testing.T) {
		client = &fakePCEServiceClient{}
		out := captureStdout(t, func() {
			require.NoError(t, addSRPolicy(validEndpointInput(), false, false))
		})
		assert.Equal(t, "success!\n", out)
	})

	t.Run("router ID form is used when router IDs are set", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		client = fake
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0002",
			Color:           100,
			Type:            "explicit",
			SegmentList:     []segment{{SID: "16003"}},
		}}
		captureStdout(t, func() {
			require.NoError(t, addSRPolicy(input, false, false))
		})
		require.NotNil(t, fake.createSRPolicyReq)
		assert.Equal(t, "0000.0aff.0001", fake.createSRPolicyReq.SrPolicy.SrcRouterId)
	})

	t.Run("router ID form grpc error is translated too", func(t *testing.T) {
		client = &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0002",
			Color:           100,
			Type:            "explicit",
			SegmentList:     []segment{{SID: "16003"}},
		}}
		err := addSRPolicy(input, false, false)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("grpc error is translated with its hint", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "SID validation failed")
		withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: "SID_VALIDATION_FAILED", Domain: "pola"})
		require.NoError(t, err)
		client = &fakePCEServiceClient{createSRPolicyErr: withDetails.Err()}

		err = addSRPolicy(validEndpointInput(), false, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--no-sid-validate")
	})
}

func TestAddSRPolicyWithEndpointAddr(t *testing.T) {
	base := func() srPolicy {
		return srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcAddr:         netip.MustParseAddr("192.0.2.1"),
			DstAddr:         netip.MustParseAddr("192.0.2.2"),
			Color:           100,
			SegmentList:     []segment{{SID: "16003"}},
		}
	}

	t.Run("type must be explicit (or empty)", func(t *testing.T) {
		p := base()
		p.Type = "dynamic"
		err := addSRPolicyWithEndpointAddr(inputFormat{SRPolicy: p}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "explicit")
	})

	t.Run("metric and waypoints require a dynamic path", func(t *testing.T) {
		p := base()
		p.Metric = "igp"
		err := addSRPolicyWithEndpointAddr(inputFormat{SRPolicy: p}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dynamic path")
	})

	t.Run("missing mandatory fields", func(t *testing.T) {
		err := addSRPolicyWithEndpointAddr(inputFormat{}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("success builds the explicit request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		client = fake
		p := base()
		p.Name = "pol1"
		p.SegmentList = []segment{{SID: "16003", LocalAddr: "192.0.2.1", RemoteAddr: "192.0.2.2", SIDStructure: "32,16,0,80"}}

		require.NoError(t, addSRPolicyWithEndpointAddr(inputFormat{ASN: 65000, SRPolicy: p}, true))

		require.NotNil(t, fake.createSRPolicyReq)
		want := &pb.SRPolicy{
			PcepSessionAddr: netip.MustParseAddr("192.0.2.1").AsSlice(),
			SrcAddr:         netip.MustParseAddr("192.0.2.1").AsSlice(),
			DstAddr:         netip.MustParseAddr("192.0.2.2").AsSlice(),
			SegmentList:     []*pb.Segment{{Sid: "16003", LocalAddr: "192.0.2.1", RemoteAddr: "192.0.2.2", SidStructure: "32,16,0,80"}},
			Color:           100,
			PolicyName:      "pol1",
			Type:            pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
		}
		assert.Equal(t, want, fake.createSRPolicyReq.SrPolicy)
		assert.Equal(t, uint32(65000), fake.createSRPolicyReq.Asn)
		assert.True(t, fake.createSRPolicyReq.DisablePathCompute)
		assert.True(t, fake.createSRPolicyReq.NoSidValidate)
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		err := addSRPolicyWithEndpointAddr(inputFormat{SRPolicy: base()}, false)
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestAddSRPolicyWithRouterID(t *testing.T) {
	t.Run("invalid common input", func(t *testing.T) {
		err := addSRPolicyWithRouterID(inputFormat{}, false)
		require.Error(t, err)
	})

	t.Run("dynamic path builds the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		client = fake
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0002",
			Name:            "pol1",
			Color:           100,
			Type:            "dynamic",
			Metric:          "delay",
			Waypoints:       []waypoint{{RouterID: "0000.0aff.0003"}},
		}}
		require.NoError(t, addSRPolicyWithRouterID(input, true))

		require.NotNil(t, fake.createSRPolicyReq)
		want := &pb.SRPolicy{
			PcepSessionAddr: netip.MustParseAddr("192.0.2.1").AsSlice(),
			SrcRouterId:     "0000.0aff.0001",
			DstRouterId:     "0000.0aff.0002",
			Color:           100,
			PolicyName:      "pol1",
			Type:            pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
			Metric:          pb.MetricType_METRIC_TYPE_DELAY,
			Waypoints:       []*pb.Waypoint{{RouterId: "0000.0aff.0003"}},
		}
		assert.Equal(t, want, fake.createSRPolicyReq.SrPolicy)
		assert.Equal(t, uint32(65000), fake.createSRPolicyReq.Asn)
		assert.True(t, fake.createSRPolicyReq.NoSidValidate)
		assert.False(t, fake.createSRPolicyReq.DisablePathCompute)
	})

	t.Run("explicit path builds the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		client = fake
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0002",
			Color:           100,
			Type:            "explicit",
			SegmentList:     []segment{{SID: "16003"}},
		}}
		require.NoError(t, addSRPolicyWithRouterID(input, false))

		require.NotNil(t, fake.createSRPolicyReq)
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, fake.createSRPolicyReq.SrPolicy.Type)
		assert.Equal(t, []*pb.Segment{{Sid: "16003"}}, fake.createSRPolicyReq.SrPolicy.SegmentList)
	})

	t.Run("invalid type is rejected", func(t *testing.T) {
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0002",
			Color:           100,
			Type:            "unknown",
		}}
		err := addSRPolicyWithRouterID(input, false)
		require.Error(t, err)
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		client = &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
			SrcRouterID:     "0000.0aff.0001",
			DstRouterID:     "0000.0aff.0002",
			Color:           100,
			Type:            "explicit",
			SegmentList:     []segment{{SID: "16003"}},
		}}
		err := addSRPolicyWithRouterID(input, false)
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestSampleInputs(t *testing.T) {
	dynamic, explicit := sampleInputs()
	assert.Contains(t, dynamic, "type: dynamic")
	assert.Contains(t, explicit, "type: explicit")
}

func TestValidateCommonInput(t *testing.T) {
	valid := srPolicy{
		PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"),
		Color:           100,
		SrcRouterID:     "0000.0aff.0001",
		DstRouterID:     "0000.0aff.0002",
	}

	t.Run("all mandatory fields present", func(t *testing.T) {
		require.NoError(t, validateCommonInput(inputFormat{ASN: 65000, SRPolicy: valid}, "dynamic-sample", "explicit-sample"))
	})

	tests := []struct {
		name  string
		input inputFormat
	}{
		{"missing ASN", inputFormat{SRPolicy: valid}},
		{"missing pcepSessionAddr", inputFormat{ASN: 65000, SRPolicy: srPolicy{Color: 100, SrcRouterID: "a", DstRouterID: "b"}}},
		{"missing color", inputFormat{ASN: 65000, SRPolicy: srPolicy{PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"), SrcRouterID: "a", DstRouterID: "b"}}},
		{"missing srcRouterID", inputFormat{ASN: 65000, SRPolicy: srPolicy{PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"), Color: 100, DstRouterID: "b"}}},
		{"missing dstRouterID", inputFormat{ASN: 65000, SRPolicy: srPolicy{PCEPSessionAddr: netip.MustParseAddr("192.0.2.1"), Color: 100, SrcRouterID: "a"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCommonInput(tt.input, "dynamic-sample", "explicit-sample")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "dynamic-sample")
			assert.Contains(t, err.Error(), "explicit-sample")
		})
	}
}

func TestBuildPolicyByType(t *testing.T) {
	t.Run("explicit", func(t *testing.T) {
		input := inputFormat{SRPolicy: srPolicy{Type: "explicit", SegmentList: []segment{{SID: "16003"}}}}
		typ, metric, segs, waypoints, err := buildPolicyByType(input, "d", "e")
		require.NoError(t, err)
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, typ)
		assert.Equal(t, pb.MetricType_METRIC_TYPE_UNSPECIFIED, metric)
		assert.Equal(t, []*pb.Segment{{Sid: "16003"}}, segs)
		assert.Nil(t, waypoints)
	})

	t.Run("dynamic", func(t *testing.T) {
		input := inputFormat{SRPolicy: srPolicy{Type: "dynamic", Metric: "igp", Waypoints: []waypoint{{RouterID: "r1"}}}}
		typ, metric, segs, waypoints, err := buildPolicyByType(input, "d", "e")
		require.NoError(t, err)
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, typ)
		assert.Equal(t, pb.MetricType_METRIC_TYPE_IGP, metric)
		assert.Nil(t, segs)
		assert.Equal(t, []*pb.Waypoint{{RouterId: "r1"}}, waypoints)
	})

	t.Run("unrecognized type is rejected", func(t *testing.T) {
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: "unknown"}}, "d", "e")
		require.Error(t, err)
	})

	t.Run("explicit with no segments", func(t *testing.T) {
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: "explicit"}}, "d", "sample-explicit")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sample-explicit")
	})

	t.Run("dynamic with no metric", func(t *testing.T) {
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: "dynamic"}}, "sample-dynamic", "e")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sample-dynamic")
	})

	t.Run("dynamic with invalid metric", func(t *testing.T) {
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: "dynamic", Metric: "bandwidth"}}, "d", "e")
		require.Error(t, err)
	})
}

func TestParseMetric(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want pb.MetricType
	}{
		{"igp", "igp", pb.MetricType_METRIC_TYPE_IGP},
		{"delay", "delay", pb.MetricType_METRIC_TYPE_DELAY},
		{"te", "te", pb.MetricType_METRIC_TYPE_TE},
		{"hopcount", "hopcount", pb.MetricType_METRIC_TYPE_HOPCOUNT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMetric(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("unrecognized metric name is rejected", func(t *testing.T) {
		_, err := parseMetric("bandwidth")
		require.Error(t, err)
	})
}
