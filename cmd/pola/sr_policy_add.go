// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
	yaml "gopkg.in/yaml.v2"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyAddCmd(c *cli) *cobra.Command {
	srPolicyAddCmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, _ []string) error {
			noSIDValidateFlag, err := cmd.Flags().GetBool("no-sid-validate")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'no-sid-validate' flag: %w", err)
			}

			filepath, err := cmd.Flags().GetString("file")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'file' flag: %w", err)
			}

			if filepath == "" {
				return errors.New("file path option \"-f filepath\" is mandatory")
			}

			//nolint:gosec // path is provided by the operator.
			f, err := os.Open(filepath)
			if err != nil {
				return fmt.Errorf("failed to open file \"%s\": %w", filepath, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					//nolint:errcheck // best-effort warning; no fallback if stderr fails
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: failed to close file \"%s\": %v\n", filepath, err)
				}
			}()

			inputData := inputFormat{}
			if err := yaml.NewDecoder(f).Decode(&inputData); err != nil {
				return fmt.Errorf("YAML syntax error in file \"%s\": %w", filepath, err)
			}

			if err := addSRPolicy(cmd.OutOrStdout(), cmd.ErrOrStderr(), inputData, c.jsonFmt, noSIDValidateFlag, c.client); err != nil {
				return fmt.Errorf("failed to add SR policy: %w", err)
			}

			return nil
		},
	}

	srPolicyAddCmd.Flags().Bool("no-sid-validate", false, "skip the SID existence check against the TED")
	srPolicyAddCmd.Flags().StringP("file", "f", "", "[mandatory] path to YAML formatted LSP information file")

	return srPolicyAddCmd
}

type segment struct {
	SID               string  `yaml:"sid"`
	LocalAddr         string  `yaml:"localAddr"`
	RemoteAddr        string  `yaml:"remoteAddr"`
	SIDStructure      string  `yaml:"sidStructure"`
	LocalInterfaceID  *uint32 `yaml:"localInterfaceId"`
	RemoteInterfaceID *uint32 `yaml:"remoteInterfaceId"`
}

func toPBSegment(s segment) *pb.Segment {
	return &pb.Segment{
		Sid:           s.SID,
		LocalAddr:     s.LocalAddr,
		RemoteAddr:    s.RemoteAddr,
		SidStructure:  s.SIDStructure,
		LocalIfaceId:  s.LocalInterfaceID,
		RemoteIfaceId: s.RemoteInterfaceID,
	}
}

type waypoint struct {
	RouterID string `yaml:"routerID"`
	SID      string `yaml:"sid"` // optional: fixed SID override
}

type dynamicPath struct {
	Metric         string     `yaml:"metric"`
	DataPlane      string     `yaml:"dataPlane"`
	UnderlayFamily string     `yaml:"underlayFamily"`
	Waypoints      []waypoint `yaml:"waypoints"`
}

type explicitPath struct {
	SegmentList []segment `yaml:"segmentList"`
}

type candidatePath struct {
	Preference uint32        `yaml:"preference"`
	Dynamic    *dynamicPath  `yaml:"dynamic"`
	Explicit   *explicitPath `yaml:"explicit"`
}

// Endpoints use either address or router-ID form, mutually exclusively (RFC 9256 §2.1).
type srPolicy struct {
	PCEPSessionAddr netip.Addr `yaml:"pcepSessionAddr"`

	Headend  netip.Addr `yaml:"headend"`
	Endpoint netip.Addr `yaml:"endpoint"`

	HeadendRouterID  string `yaml:"headendRouterID"`
	EndpointRouterID string `yaml:"endpointRouterID"`
	EndpointFamily   string `yaml:"endpointFamily"`

	Name          string        `yaml:"name"`
	Color         uint32        `yaml:"color"`
	CandidatePath candidatePath `yaml:"candidatePath"`
}

type inputFormat struct {
	SRPolicy srPolicy `yaml:"srPolicy"`
	ASN      uint32   `yaml:"asn"`
}

const (
	metricTypeIGP      = "igp"
	metricTypeDelay    = "delay"
	metricTypeTE       = "te"
	metricTypeHopcount = "hopcount"
)

const (
	underlayFamilyIPv4 = "ipv4"
	underlayFamilyIPv6 = "ipv6"
)

const (
	dataPlaneSRMPLS = "sr-mpls"
	dataPlaneSRv6   = "srv6"
)

// Empty input leaves the choice to the server's default.
func parseAddressFamily(s string) (pb.AddressFamily, error) {
	switch s {
	case "":
		return pb.AddressFamily_ADDRESS_FAMILY_UNSPECIFIED, nil
	case underlayFamilyIPv4:
		return pb.AddressFamily_ADDRESS_FAMILY_IPV4, nil
	case underlayFamilyIPv6:
		return pb.AddressFamily_ADDRESS_FAMILY_IPV6, nil
	default:
		return 0, fmt.Errorf("invalid address family %q", s)
	}
}

// Empty input leaves the choice to the server's default.
func parseDataPlane(s string) (pb.DataPlane, error) {
	switch s {
	case "":
		return pb.DataPlane_DATA_PLANE_UNSPECIFIED, nil
	case dataPlaneSRMPLS:
		return pb.DataPlane_DATA_PLANE_SR_MPLS, nil
	case dataPlaneSRv6:
		return pb.DataPlane_DATA_PLANE_SRV6, nil
	default:
		return 0, fmt.Errorf("invalid input `dataPlane`: %q", s)
	}
}

func addSRPolicy(out, errOut io.Writer, input inputFormat, jsonFlag, noSIDValidate bool, client pb.PCEServiceClient) error {
	if noSIDValidate {
		if _, err := fmt.Fprintln(errOut, "warning: skipping SID validation (--no-sid-validate)"); err != nil {
			return err
		}
	}

	req, err := buildCreateSRPolicyRequest(input, noSIDValidate)
	if err != nil {
		return err
	}

	if err := grpc.CreateSRPolicy(client, req); err != nil {
		return translateCreateSRPolicyError(err)
	}

	if jsonFlag {
		return writeJSON(out, statusResult{Status: statusSuccess})
	}

	_, err = fmt.Fprintln(out, "success!")

	return err
}

func translateCreateSRPolicyError(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}

	msg := st.Message()
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}

		switch info.GetReason() {
		case reasonSIDValidationFailed:
			return fmt.Errorf("%s\n  hint: use --no-sid-validate to provision without validation", msg)
		case reasonTEDDisabled:
			return fmt.Errorf("%s\n  hint: enable TED sync on the PCE", msg)
		case reasonTEDNotSynced:
			return fmt.Errorf("%s\n  hint: the PCE has not finished syncing the TED yet; retry shortly", msg)
		case reasonPCEPSessionNotSynced:
			return fmt.Errorf("%s\n  hint: check that a PCEP session to the target PCC is established and synced", msg)
		case reasonPCEPSessionNotFound:
			return fmt.Errorf("%s\n  hint: run `pola session` to check the PCEP session address", msg)
		case reasonDestinationUnreach:
			return fmt.Errorf("%s\n  hint: no path exists to the destination in the current topology", msg)
		case reasonMetricNotCarried:
			return fmt.Errorf("%s\n  hint: the requested metric type is not advertised on this topology", msg)
		}
	}

	return errors.New(msg)
}

const sampleInput = "asn: 65000\n" +
	"srPolicy:\n" +
	"  pcepSessionAddr: 192.0.2.1\n" +
	"  headend: 192.0.2.1\n" +
	"  endpoint: 192.0.2.2\n" +
	"  name: name\n" +
	"  color: 100\n" +
	"  candidatePath:\n" +
	"    explicit:\n" +
	"      segmentList:\n" +
	"        - sid: 16003\n" +
	"        - sid: 16002\n\n" +
	"or, to resolve endpoints from the TED by router ID and compute a dynamic path,\n" +
	"use headendRouterID / endpointRouterID and candidatePath.dynamic:\n\n" +
	"asn: 65000\n" +
	"srPolicy:\n" +
	"  pcepSessionAddr: 192.0.2.1\n" +
	"  headendRouterID: 0000.0aff.0001\n" +
	"  endpointRouterID: 0000.0aff.0004\n" +
	"  name: name\n" +
	"  color: 100\n" +
	"  candidatePath:\n" +
	"    dynamic:\n" +
	"      metric: igp\n"

func invalidInputError() error {
	return fmt.Errorf("invalid input, example below:\n\n%s", sampleInput)
}

func buildCreateSRPolicyRequest(input inputFormat, noSIDValidate bool) (*pb.CreateSRPolicyRequest, error) {
	if !input.SRPolicy.PCEPSessionAddr.IsValid() || input.SRPolicy.Color == 0 {
		return nil, invalidInputError()
	}

	endpointFields, err := buildEndpointFields(input.SRPolicy)
	if err != nil {
		return nil, err
	}

	candidatePath, err := buildPBCandidatePath(input.SRPolicy.CandidatePath)
	if err != nil {
		return nil, err
	}

	srPolicy := &pb.SRPolicy{
		PeerAddr:      input.SRPolicy.PCEPSessionAddr.AsSlice(),
		Color:         input.SRPolicy.Color,
		PolicyName:    input.SRPolicy.Name,
		CandidatePath: candidatePath,
	}
	endpointFields(srPolicy)

	return &pb.CreateSRPolicyRequest{
		SrPolicy:      srPolicy,
		Asn:           input.ASN,
		NoSidValidate: noSIDValidate,
	}, nil
}

func buildEndpointFields(policy srPolicy) (func(*pb.SRPolicy), error) {
	usesAddr := policy.Headend.IsValid() || policy.Endpoint.IsValid()
	usesRouterID := policy.HeadendRouterID != "" || policy.EndpointRouterID != ""

	switch {
	case usesAddr && usesRouterID:
		return nil, errors.New("headend/endpoint and headendRouterID/endpointRouterID are mutually exclusive, use one form only")
	case usesAddr:
		if policy.EndpointFamily != "" {
			return nil, errors.New("endpointFamily is valid only with the headendRouterID/endpointRouterID form")
		}

		if !policy.Headend.IsValid() || !policy.Endpoint.IsValid() {
			return nil, invalidInputError()
		}

		return func(p *pb.SRPolicy) {
			p.Headend = policy.Headend.AsSlice()
			p.Endpoint = policy.Endpoint.AsSlice()
		}, nil
	case usesRouterID:
		if policy.HeadendRouterID == "" || policy.EndpointRouterID == "" {
			return nil, invalidInputError()
		}

		endpointFamily, err := parseAddressFamily(policy.EndpointFamily)
		if err != nil {
			return nil, err
		}

		return func(p *pb.SRPolicy) {
			p.HeadendRouterId = policy.HeadendRouterID
			p.EndpointRouterId = policy.EndpointRouterID
			p.EndpointFamily = endpointFamily
		}, nil
	default:
		return nil, invalidInputError()
	}
}

func buildPBCandidatePath(cp candidatePath) (*pb.CandidatePath, error) {
	switch {
	case cp.Dynamic != nil && cp.Explicit != nil:
		return nil, errors.New("candidatePath.dynamic and candidatePath.explicit are mutually exclusive")
	case cp.Dynamic != nil:
		dynamic, err := buildPBDynamicPath(*cp.Dynamic)
		if err != nil {
			return nil, err
		}

		return &pb.CandidatePath{
			Preference: cp.Preference,
			Path:       &pb.CandidatePath_Dynamic{Dynamic: dynamic},
		}, nil
	case cp.Explicit != nil:
		if len(cp.Explicit.SegmentList) == 0 {
			return nil, invalidInputError()
		}

		segmentList := make([]*pb.Segment, 0, len(cp.Explicit.SegmentList))
		for _, s := range cp.Explicit.SegmentList {
			segmentList = append(segmentList, toPBSegment(s))
		}

		return &pb.CandidatePath{
			Preference: cp.Preference,
			Path:       &pb.CandidatePath_Explicit{Explicit: &pb.ExplicitPath{SegmentList: segmentList}},
		}, nil
	default:
		return nil, errors.New("candidatePath must specify either dynamic or explicit")
	}
}

func buildPBDynamicPath(d dynamicPath) (*pb.DynamicPath, error) {
	if d.Metric == "" {
		return nil, invalidInputError()
	}

	metric, err := parseMetric(d.Metric)
	if err != nil {
		return nil, err
	}

	dataPlane, err := parseDataPlane(d.DataPlane)
	if err != nil {
		return nil, err
	}

	underlayFamily, err := parseAddressFamily(d.UnderlayFamily)
	if err != nil {
		return nil, err
	}

	var waypoints []*pb.Waypoint
	for _, wp := range d.Waypoints {
		waypoints = append(waypoints, &pb.Waypoint{
			RouterId: wp.RouterID,
			Sid:      wp.SID,
		})
	}

	return &pb.DynamicPath{
		Metric:         metric,
		DataPlane:      dataPlane,
		UnderlayFamily: underlayFamily,
		Waypoints:      waypoints,
	}, nil
}

func parseMetric(metric string) (pb.MetricType, error) {
	switch metric {
	case metricTypeIGP:
		return pb.MetricType_METRIC_TYPE_IGP, nil
	case metricTypeDelay:
		return pb.MetricType_METRIC_TYPE_DELAY, nil
	case metricTypeTE:
		return pb.MetricType_METRIC_TYPE_TE, nil
	case metricTypeHopcount:
		return pb.MetricType_METRIC_TYPE_HOPCOUNT, nil
	default:
		return 0, errors.New("invalid input `metric`")
	}
}
