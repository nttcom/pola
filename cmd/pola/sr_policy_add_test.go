// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"bytes"
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
	return newSRPolicyAddCmd(&cli{client: client})
}

const testErrorDomain = "pola"

// TestReasonConstantsMatchServer ensures the duplicated Reason constants stay in sync.
// cmd/pola duplicates these values to avoid depending on pkg/server.
func TestReasonConstantsMatchServer(t *testing.T) {
	t.Parallel()

	assert.Equal(t, server.ReasonTEDDisabled, reasonTEDDisabled)
	assert.Equal(t, server.ReasonTEDNotSynced, reasonTEDNotSynced)
	assert.Equal(t, server.ReasonDestinationUnreachable, reasonDestinationUnreach)
	assert.Equal(t, server.ReasonMetricNotCarried, reasonMetricNotCarried)
	assert.Equal(t, server.ReasonPCEPSessionNotSynced, reasonPCEPSessionNotSynced)
	assert.Equal(t, server.ReasonPCEPSessionNotFound, reasonPCEPSessionNotFound)
	assert.Equal(t, server.ReasonSIDValidationFailed, reasonSIDValidationFailed)
}

func TestTranslateCreateSRPolicyError(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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
	t.Parallel()

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
			Headend:         netip.MustParseAddr(testPeerAddr1),
			Endpoint:        netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			CandidatePath: candidatePath{
				Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}},
			},
		},
	}
}

func TestNewSRPolicyAddCmd_RunE(t *testing.T) {
	t.Parallel()

	t.Run("no-sid-validate flag not registered", func(t *testing.T) {
		t.Parallel()

		cmd := newTestSRPolicyAddCmd(nil)
		err := cmd.RunE(&cobra.Command{}, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no-sid-validate")
	})

	t.Run("file flag not registered", func(t *testing.T) {
		t.Parallel()

		cmd := newTestSRPolicyAddCmd(nil)
		bare := &cobra.Command{}
		bare.Flags().Bool("no-sid-validate", false, "")
		err := cmd.RunE(bare, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "'file' flag")
	})

	t.Run("missing file flag", func(t *testing.T) {
		t.Parallel()

		cmd := newTestSRPolicyAddCmd(nil)
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mandatory")
	})

	t.Run("file does not exist", func(t *testing.T) {
		t.Parallel()

		cmd := newTestSRPolicyAddCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", filepath.Join(t.TempDir(), "missing.yaml")))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open file")
	})

	t.Run("invalid YAML syntax", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "policy.yaml")
		require.NoError(t, os.WriteFile(path, []byte("not: [valid"), 0o600))

		cmd := newTestSRPolicyAddCmd(nil)
		require.NoError(t, cmd.Flags().Set("file", path))
		err := cmd.RunE(cmd, []string{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "YAML syntax error")
	})

	t.Run("success delegates to addSRPolicy", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "policy.yaml")
		yamlContent := "asn: 65000\n" +
			"srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  headend: 192.0.2.1\n" +
			"  endpoint: 192.0.2.2\n" +
			"  name: pol1\n" +
			"  color: 100\n" +
			"  candidatePath:\n" +
			"    explicit:\n" +
			"      segmentList:\n" +
			"        - sid: \"16003\"\n"
		require.NoError(t, os.WriteFile(path, []byte(yamlContent), 0o600))

		cmd := newTestSRPolicyAddCmd(&fakePCEServiceClient{})
		require.NoError(t, cmd.Flags().Set("file", path))
		cmd.SetOut(&bytes.Buffer{})
		require.NoError(t, cmd.RunE(cmd, []string{}))
	})

	t.Run("addSRPolicy error is wrapped", func(t *testing.T) {
		t.Parallel()
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
	t.Parallel()

	t.Run("headendRouterID/endpointRouterID and headend/endpoint are mutually exclusive", func(t *testing.T) {
		t.Parallel()

		input := inputFormat{SRPolicy: srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			Color:            100,
			HeadendRouterID:  testRouterID1,
			Headend:          netip.MustParseAddr(testPeerAddr1),
			EndpointRouterID: testRouterID2,
			Endpoint:         netip.MustParseAddr(testPeerAddr2),
			CandidatePath:    candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}}
		err := addSRPolicy(&bytes.Buffer{}, &bytes.Buffer{}, input, false, false, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mutually exclusive")
	})

	t.Run("no-sid-validate prints a warning to stderr", func(t *testing.T) {
		t.Parallel()

		var out, errOut bytes.Buffer
		require.NoError(t, addSRPolicy(&out, &errOut, validEndpointInput(), false, true, &fakePCEServiceClient{}))
		assert.Contains(t, errOut.String(), "no-sid-validate")
	})

	t.Run("json output on success", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer
		require.NoError(t, addSRPolicy(&out, &bytes.Buffer{}, validEndpointInput(), true, false, &fakePCEServiceClient{}))
		assert.JSONEq(t, "{\"status\": \"success\"}\n", out.String())
	})

	t.Run("plain text output on success", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer
		require.NoError(t, addSRPolicy(&out, &bytes.Buffer{}, validEndpointInput(), false, false, &fakePCEServiceClient{}))
		assert.Equal(t, "success!\n", out.String())
	})

	t.Run("error writing no-sid-validate warning to stderr", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer

		failingErrOut := &condFailWriter{fail: containsFail("no-sid-validate")}
		err := addSRPolicy(&out, failingErrOut, validEndpointInput(), false, true, &fakePCEServiceClient{})
		require.Error(t, err)
	})

	t.Run("router ID form is used when router IDs are set", func(t *testing.T) {
		t.Parallel()

		fake := &fakePCEServiceClient{}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath:    candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}}
		require.NoError(t, addSRPolicy(&bytes.Buffer{}, &bytes.Buffer{}, input, false, false, fake))
		require.NotNil(t, fake.createSRPolicyReq)
		assert.Equal(t, testRouterID1, fake.createSRPolicyReq.GetSrPolicy().GetHeadendRouterId())
	})

	t.Run("router ID form grpc error is translated too", func(t *testing.T) {
		t.Parallel()

		fake := &fakePCEServiceClient{createSRPolicyErr: assert.AnError}
		input := inputFormat{ASN: 65000, SRPolicy: srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath:    candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}}
		err := addSRPolicy(&bytes.Buffer{}, &bytes.Buffer{}, input, false, false, fake)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("grpc error is translated with its hint", func(t *testing.T) {
		t.Parallel()

		st := status.New(codes.FailedPrecondition, "SID validation failed")
		withDetails, err := st.WithDetails(&errdetails.ErrorInfo{Reason: "SID_VALIDATION_FAILED", Domain: testErrorDomain})
		require.NoError(t, err)

		fake := &fakePCEServiceClient{createSRPolicyErr: withDetails.Err()}

		err = addSRPolicy(&bytes.Buffer{}, &bytes.Buffer{}, validEndpointInput(), false, false, fake)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--no-sid-validate")
	})
}

func TestBuildCreateSRPolicyRequest(t *testing.T) {
	t.Parallel()

	t.Run("missing mandatory fields", func(t *testing.T) {
		t.Parallel()

		_, err := buildCreateSRPolicyRequest(inputFormat{}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("explicit path builds the request", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			Headend:         netip.MustParseAddr(testPeerAddr1),
			Endpoint:        netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			Name:            testPolicyName,
			CandidatePath: candidatePath{
				Preference: 200,
				Explicit: &explicitPath{SegmentList: []segment{
					{SID: "16003", LocalAddr: testPeerAddr1, RemoteAddr: testPeerAddr2, SIDStructure: "32,16,0,80"},
				}},
			},
		}

		req, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, true)
		require.NoError(t, err)

		want := &pb.SRPolicy{
			PeerAddr:   netip.MustParseAddr(testPeerAddr1).AsSlice(),
			Headend:    netip.MustParseAddr(testPeerAddr1).AsSlice(),
			Endpoint:   netip.MustParseAddr(testPeerAddr2).AsSlice(),
			Color:      100,
			PolicyName: testPolicyName,
			CandidatePath: &pb.CandidatePath{
				Preference: 200,
				Path: &pb.CandidatePath_Explicit{Explicit: &pb.ExplicitPath{
					SegmentList: []*pb.Segment{{Sid: "16003", LocalAddr: testPeerAddr1, RemoteAddr: testPeerAddr2, SidStructure: "32,16,0,80"}},
				}},
			},
		}
		assert.Equal(t, want, req.GetSrPolicy())
		assert.Equal(t, uint32(65000), req.GetAsn())
		assert.True(t, req.GetNoSidValidate())
	})

	t.Run("dynamic path builds the request", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Name:             testPolicyName,
			Color:            100,
			CandidatePath: candidatePath{
				Dynamic: &dynamicPath{
					Metric:    metricTypeDelay,
					Waypoints: []waypoint{{RouterID: "0000.0aff.0003"}},
				},
			},
		}

		req, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.NoError(t, err)

		want := &pb.SRPolicy{
			PeerAddr:         netip.MustParseAddr(testPeerAddr1).AsSlice(),
			HeadendRouterId:  testRouterID1,
			EndpointRouterId: testRouterID2,
			Color:            100,
			PolicyName:       testPolicyName,
			CandidatePath: &pb.CandidatePath{
				Path: &pb.CandidatePath_Dynamic{Dynamic: &pb.DynamicPath{
					Metric:    pb.MetricType_METRIC_TYPE_DELAY,
					Waypoints: []*pb.Waypoint{{RouterId: "0000.0aff.0003"}},
				}},
			},
		}
		assert.Equal(t, want, req.GetSrPolicy())
	})

	t.Run("dynamic path with underlayFamily=ipv6 and dataPlane=srv6", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath: candidatePath{
				Dynamic: &dynamicPath{Metric: metricTypeIGP, UnderlayFamily: underlayFamilyIPv6, DataPlane: dataPlaneSRv6},
			},
		}

		req, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.NoError(t, err)

		dyn := req.GetSrPolicy().GetCandidatePath().GetDynamic()
		require.NotNil(t, dyn)
		assert.Equal(t, pb.AddressFamily_ADDRESS_FAMILY_IPV6, dyn.GetUnderlayFamily())
		assert.Equal(t, pb.DataPlane_DATA_PLANE_SRV6, dyn.GetDataPlane())
	})

	t.Run("endpointFamily is valid only with the router ID form", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			Headend:         netip.MustParseAddr(testPeerAddr1),
			Endpoint:        netip.MustParseAddr(testPeerAddr2),
			EndpointFamily:  underlayFamilyIPv4,
			Color:           100,
			CandidatePath:   candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "endpointFamily")
	})

	t.Run("invalid endpointFamily is rejected", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			EndpointFamily:   "ipv5",
			Color:            100,
			CandidatePath:    candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("invalid underlayFamily is rejected", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath:    candidatePath{Dynamic: &dynamicPath{Metric: metricTypeIGP, UnderlayFamily: "ipv5"}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("invalid dataPlane is rejected", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath:    candidatePath{Dynamic: &dynamicPath{Metric: metricTypeIGP, DataPlane: "srv7"}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("only headend set without endpoint", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			Headend:         netip.MustParseAddr(testPeerAddr1),
			Color:           100,
			CandidatePath:   candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("only headendRouterID set without endpointRouterID", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID: testRouterID1,
			Color:           100,
			CandidatePath:   candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("neither address nor router ID form is specified", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			Color:           100,
			CandidatePath:   candidatePath{Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input")
	})

	t.Run("dynamic and explicit are mutually exclusive", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath: candidatePath{
				Dynamic:  &dynamicPath{Metric: metricTypeIGP},
				Explicit: &explicitPath{SegmentList: []segment{{SID: "16003"}}},
			},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("candidatePath must specify either dynamic or explicit", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("explicit with no segments", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr: netip.MustParseAddr(testPeerAddr1),
			Headend:         netip.MustParseAddr(testPeerAddr1),
			Endpoint:        netip.MustParseAddr(testPeerAddr2),
			Color:           100,
			CandidatePath:   candidatePath{Explicit: &explicitPath{}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("dynamic with no metric", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath:    candidatePath{Dynamic: &dynamicPath{}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})

	t.Run("dynamic with invalid metric", func(t *testing.T) {
		t.Parallel()

		p := srPolicy{
			PCEPSessionAddr:  netip.MustParseAddr(testPeerAddr1),
			HeadendRouterID:  testRouterID1,
			EndpointRouterID: testRouterID2,
			Color:            100,
			CandidatePath:    candidatePath{Dynamic: &dynamicPath{Metric: "bandwidth"}},
		}

		_, err := buildCreateSRPolicyRequest(inputFormat{ASN: 65000, SRPolicy: p}, false)
		require.Error(t, err)
	})
}

func TestToPBSegment(t *testing.T) {
	t.Parallel()

	localIfaceID, remoteIfaceID := uint32(5), uint32(6)
	got := toPBSegment(segment{
		SID:               "16003",
		LocalAddr:         testPeerAddr1,
		RemoteAddr:        testPeerAddr2,
		SIDStructure:      "32,16,0,80",
		LocalInterfaceID:  &localIfaceID,
		RemoteInterfaceID: &remoteIfaceID,
	})

	want := &pb.Segment{
		Sid:           "16003",
		LocalAddr:     testPeerAddr1,
		RemoteAddr:    testPeerAddr2,
		SidStructure:  "32,16,0,80",
		LocalIfaceId:  &localIfaceID,
		RemoteIfaceId: &remoteIfaceID,
	}
	assert.Equal(t, want, got)
}

func TestParseAddressFamily(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want pb.AddressFamily
	}{
		{"unset", "", pb.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED},
		{underlayFamilyIPv4, underlayFamilyIPv4, pb.AddressFamily_ADDRESS_FAMILY_IPV4},
		{underlayFamilyIPv6, underlayFamilyIPv6, pb.AddressFamily_ADDRESS_FAMILY_IPV6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseAddressFamily(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("unrecognized value is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := parseAddressFamily("ipv5")
		require.Error(t, err)
	})
}

func TestParseDataPlane(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want pb.DataPlane
	}{
		{"unset", "", pb.DataPlane_DATA_PLANE_UNSPECIFIED},
		{dataPlaneSRMPLS, dataPlaneSRMPLS, pb.DataPlane_DATA_PLANE_SR_MPLS},
		{dataPlaneSRv6, dataPlaneSRv6, pb.DataPlane_DATA_PLANE_SRV6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDataPlane(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("unrecognized value is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := parseDataPlane("srv7")
		require.Error(t, err)
	})
}

func TestParseMetric(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			got, err := parseMetric(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("unrecognized metric name is rejected", func(t *testing.T) {
		t.Parallel()

		_, err := parseMetric("bandwidth")
		require.Error(t, err)
	})
}
