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

func newTestSRPolicyAddCmd(client pb.PCEServiceClient) *cobra.Command {
	jsonFmt := false
	return newSRPolicyAddCmd(&client, &jsonFmt)
}

const testErrorDomain = "pola"

// TestReasonConstantsMatchServer ensures the duplicated Reason constants stay in sync.
// cmd/pola duplicates these values to avoid depending on pkg/server.
func TestReasonConstantsMatchServer(t *testing.T) {
	assert.Equal(t, server.ReasonTEDDisabled, reasonTEDDisabled)
	assert.Equal(t, server.ReasonTEDNotSynced, reasonTEDNotSynced)
	assert.Equal(t, server.ReasonDestinationUnreachable, reasonDestinationUnreach)
	assert.Equal(t, server.ReasonMetricNotCarried, reasonMetricNotCarried)
	assert.Equal(t, server.ReasonPCEPSessionNotSynced, reasonPCEPSessionNotSynced)
	assert.Equal(t, server.ReasonPCEPSessionNotFound, reasonPCEPSessionNotFound)
	assert.Equal(t, server.ReasonSIDValidationFailed, reasonSIDValidationFailed)
}

func TestTranslateCreateSRPolicyError(t *testing.T) {
	newErr := func(code codes.Code, reason, msg string) error {
		st := status.New(code, msg)
		withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: testErrorDomain})
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
		{"missing PCEP session gets a `pola session` hint", newErr(codes.NotFound, "PCEP_SESSION_NOT_FOUND", "no session with address 10.0.0.1 found"), "pola session"},
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
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcAddr:         netip.MustParseAddr(testPeerAddr1),
			DstAddr:         netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			SegmentList:     []segment{{SID: "16003"}},
		},
	}
}

func TestNewSRPolicyAddCmd_RunE(t *testing.T) {
	t.Run("no-sid-validate flag not registered", func(t *testing.T) {
		cmd := newTestSRPolicyAddCmd(nil)
		err := cmd.RunE(&cobra.Command{}, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no-sid-validate")
	})

	t.Run("file flag not registered", func(t *testing.T) {
		cmd := newTestSRPolicyAddCmd(nil)
		bare := &cobra.Command{}
		bare.Flags().Bool("no-sid-validate", false, "")
		err := cmd.RunE(bare, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'file' flag")
	})

	t.Run("missing file flag", func(t *testing.T) {
		cmd := newTestSRPolicyAddCmd(nil)
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mandatory")
	})

	t.Run("file does not exist", func(t *testing.T) {
		cmd := newTestSRPolicyAddCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", filepath.Join(t.TempDir(), "missing.yaml")))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("not: [valid"), 0o600))
		cmd := newTestSRPolicyAddCmd(nil)
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

		cmd := newTestSRPolicyAddCmd(&fakePCEServiceClient{})
		require.NoError(t, cmd.Flags().Set("file", path))
		captureStdout(t, func() {
			require.NoError(t, cmd.RunE(cmd, []string{}))
		})
	})

	t.Run("addSRPolicy error is wrapped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("srPolicy:\n  name: incomplete\n"), 0o600))
		cmd := newTestSRPolicyAddCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to add SR policy")
	})
}

func TestAddSRPolicy(t *testing.T) {
	t.Run("srcRouterID/dstRouterID and srcAddr/dstAddr are mutually exclusive", func(t *testing.T) {
		input := inputFormat{SRPolicy: srPolicy{
			SrcRouterID: testRouterID1,
			SrcAddr:     netip.MustParseAddr(testPeerAddr1),
		}}
		err := addSRPolicy(input, false, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("no-sid-validate prints a warning to stderr", func(t *testing.T) {
		var stderr string
		captureStdout(t, func() {
			stderr = captureStderr(t, func() {
				require.NoError(t, addSRPolicy(validEndpointInput(), false, true, &fakePCEServiceClient{}))
			})
		})
		assert.Contains(t, stderr, "no-sid-validate")
	})

	t.Run("json output on success", func(t *testing.T) {
		out := captureStdout(t, func() {
			require.NoError(t, addSRPolicy(validEndpointInput(), true, false, &fakePCEServiceClient{}))
		})
		assert.JSONEq(t, "{\"status\": \"success\"}\n", out)
	})

	t.Run("plain text output on success", func(t *testing.T) {
		out := captureStdout(t, func() {
			require.NoError(t, addSRPolicy(validEndpointInput(), false, false, &fakePCEServiceClient{}))
		})
		assert.Equal(t, "success!\n", out)
	})

	t.Run("router ID form is used when router IDs are set", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcRouterID:     testRouterID1,
			DstRouterID:     testRouterID2,
			Color:           100,
			Type:            srPolicyTypeExplicit,
			SegmentList:     []segment{{SID: "16003"}},
		}}
		captureStdout(t, func() {
			require.NoError(t, addSRPolicy(input, false, false, fake))
		})
		require.NotNil(t, fake.createSRPolicyReq)
		assert.Equal(t, testRouterID1, fake.createSRPolicyReq.SrPolicy.SrcRouterId)
	})

	t.Run("router ID form grpc error is translated too", func(t *testing.T) {
		fake := &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcRouterID:     testRouterID1,
			DstRouterID:     testRouterID2,
			Color:           100,
			Type:            srPolicyTypeExplicit,
			SegmentList:     []segment{{SID: "16003"}},
		}}
		err := addSRPolicy(input, false, false, fake)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("grpc error is translated with its hint", func(t *testing.T) {
		st := status.New(codes.FailedPrecondition, "SID validation failed")
		withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: "SID_VALIDATION_FAILED", Domain: testErrorDomain})
		require.NoError(t, err)
		fake := &fakePCEServiceClient{createSRPolicyErr: withDetails.Err()}

		err = addSRPolicy(validEndpointInput(), false, false, fake)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--no-sid-validate")
	})
}

func TestAddSRPolicyWithEndpointAddr(t *testing.T) {
	base := func() srPolicy {
		return srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcAddr:         netip.MustParseAddr(testPeerAddr1),
			DstAddr:         netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			SegmentList:     []segment{{SID: "16003"}},
		}
	}

	t.Run("type must be explicit (or empty)", func(t *testing.T) {
		p := base()
		p.Type = srPolicyTypeDynamic
		err := addSRPolicyWithEndpointAddr(inputFormat{SRPolicy: p}, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), srPolicyTypeExplicit)
	})

	t.Run("metric and waypoints require a dynamic path", func(t *testing.T) {
		p := base()
		p.Metric = metricTypeIGP
		err := addSRPolicyWithEndpointAddr(inputFormat{SRPolicy: p}, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dynamic path")
	})

	t.Run("missing mandatory fields", func(t *testing.T) {
		err := addSRPolicyWithEndpointAddr(inputFormat{}, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("success builds the explicit request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		p := base()
		p.Name = testPolicyName
		p.SegmentList = []segment{{SID: "16003", LocalAddr: testPeerAddr1, RemoteAddr: testPeerAddr2, SIDStructure: "32,16,0,80"}}

		require.NoError(t, addSRPolicyWithEndpointAddr(inputFormat{ASN: 65000, SRPolicy: p}, true, fake))

		require.NotNil(t, fake.createSRPolicyReq)
		want := &pb.SRPolicy{
			PeerAddr:    netip.MustParseAddr(testPeerAddr1).AsSlice(),
			SrcAddr:     netip.MustParseAddr(testPeerAddr1).AsSlice(),
			DstAddr:     netip.MustParseAddr(testPeerAddr2).AsSlice(),
			SegmentList: []*pb.Segment{{Sid: "16003", LocalAddr: testPeerAddr1, RemoteAddr: testPeerAddr2, SidStructure: "32,16,0,80"}},
			Color:       100,
			PolicyName:  testPolicyName,
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
		}
		assert.Equal(t, want, fake.createSRPolicyReq.SrPolicy)
		assert.Equal(t, uint32(65000), fake.createSRPolicyReq.Asn)
		assert.True(t, fake.createSRPolicyReq.DisablePathCompute)
		assert.True(t, fake.createSRPolicyReq.NoSidValidate)
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		fake := &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		err := addSRPolicyWithEndpointAddr(inputFormat{SRPolicy: base()}, false, fake)
		require.ErrorIs(t, err, assert.AnError)
	})
}

func TestAddSRPolicyWithRouterID(t *testing.T) {
	t.Run("invalid common input", func(t *testing.T) {
		err := addSRPolicyWithRouterID(inputFormat{}, false, nil)
		require.Error(t, err)
	})

	t.Run("dynamic path builds the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcRouterID:     testRouterID1,
			DstRouterID:     testRouterID2,
			Name:            testPolicyName,
			Color:           100,
			Type:            srPolicyTypeDynamic,
			Metric:          metricTypeDelay,
			Waypoints:       []waypoint{{RouterID: "0000.0aff.0003"}},
		}}
		require.NoError(t, addSRPolicyWithRouterID(input, true, fake))

		require.NotNil(t, fake.createSRPolicyReq)
		want := &pb.SRPolicy{
			PeerAddr:    netip.MustParseAddr(testPeerAddr1).AsSlice(),
			SrcRouterId: testRouterID1,
			DstRouterId: testRouterID2,
			Color:       100,
			PolicyName:  testPolicyName,
			Type:        pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC,
			Metric:      pb.MetricType_METRIC_TYPE_DELAY,
			Waypoints:   []*pb.Waypoint{{RouterId: "0000.0aff.0003"}},
		}
		assert.Equal(t, want, fake.createSRPolicyReq.SrPolicy)
		assert.Equal(t, uint32(65000), fake.createSRPolicyReq.Asn)
		assert.True(t, fake.createSRPolicyReq.NoSidValidate)
		assert.False(t, fake.createSRPolicyReq.DisablePathCompute)
	})

	t.Run("explicit path builds the request", func(t *testing.T) {
		fake := &fakePCEServiceClient{}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcRouterID:     testRouterID1,
			DstRouterID:     testRouterID2,
			Color:           100,
			Type:            srPolicyTypeExplicit,
			SegmentList:     []segment{{SID: "16003"}},
		}}
		require.NoError(t, addSRPolicyWithRouterID(input, false, fake))

		require.NotNil(t, fake.createSRPolicyReq)
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, fake.createSRPolicyReq.SrPolicy.Type)
		assert.Equal(t, []*pb.Segment{{Sid: "16003"}}, fake.createSRPolicyReq.SrPolicy.SegmentList)
	})

	t.Run("invalid type is rejected", func(t *testing.T) {
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcRouterID:     testRouterID1,
			DstRouterID:     testRouterID2,
			Color:           100,
			Type:            "unknown",
		}}
		err := addSRPolicyWithRouterID(input, false, nil)
		require.Error(t, err)
	})

	t.Run("grpc error propagates", func(t *testing.T) {
		fake := &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			SrcRouterID:     testRouterID1,
			DstRouterID:     testRouterID2,
			Color:           100,
			Type:            srPolicyTypeExplicit,
			SegmentList:     []segment{{SID: "16003"}},
		}}
		err := addSRPolicyWithRouterID(input, false, fake)
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
		PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
		Color:           100,
		SrcRouterID:     testRouterID1,
		DstRouterID:     testRouterID2,
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
		{"missing color", inputFormat{ASN: 65000, SRPolicy: srPolicy{PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1), SrcRouterID: "a", DstRouterID: "b"}}},
		{"missing srcRouterID", inputFormat{ASN: 65000, SRPolicy: srPolicy{PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1), Color: 100, DstRouterID: "b"}}},
		{"missing dstRouterID", inputFormat{ASN: 65000, SRPolicy: srPolicy{PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1), Color: 100, SrcRouterID: "a"}}},
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
	t.Run(srPolicyTypeExplicit, func(t *testing.T) {
		input := inputFormat{SRPolicy: srPolicy{Type: srPolicyTypeExplicit, SegmentList: []segment{{SID: "16003"}}}}
		typ, metric, segs, waypoints, err := buildPolicyByType(input, "d", "e")
		require.NoError(t, err)
		assert.Equal(t, pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, typ)
		assert.Equal(t, pb.MetricType_METRIC_TYPE_UNSPECIFIED, metric)
		assert.Equal(t, []*pb.Segment{{Sid: "16003"}}, segs)
		assert.Nil(t, waypoints)
	})

	t.Run(srPolicyTypeDynamic, func(t *testing.T) {
		input := inputFormat{SRPolicy: srPolicy{Type: srPolicyTypeDynamic, Metric: metricTypeIGP, Waypoints: []waypoint{{RouterID: "r1"}}}}
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
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: srPolicyTypeExplicit}}, "d", "sample-explicit")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sample-explicit")
	})

	t.Run("dynamic with no metric", func(t *testing.T) {
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: srPolicyTypeDynamic}}, "sample-dynamic", "e")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sample-dynamic")
	})

	t.Run("dynamic with invalid metric", func(t *testing.T) {
		_, _, _, _, err := buildPolicyByType(inputFormat{SRPolicy: srPolicy{Type: srPolicyTypeDynamic, Metric: "bandwidth"}}, "d", "e")
		require.Error(t, err)
	})
}

func TestParseMetric(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want pb.MetricType
	}{
		{metricTypeIGP, metricTypeIGP, pb.MetricType_METRIC_TYPE_IGP},
		{metricTypeDelay, metricTypeDelay, pb.MetricType_METRIC_TYPE_DELAY},
		{"te", "te", pb.MetricType_METRIC_TYPE_TE},
		{metricTypeHopcount, metricTypeHopcount, pb.MetricType_METRIC_TYPE_HOPCOUNT},
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
