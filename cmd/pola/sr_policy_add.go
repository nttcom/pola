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

			//nolint:gosec // G304: the file path comes from the operator's -f flag.
			f, err := os.Open(filepath)
			if err != nil {
				return fmt.Errorf("failed to open file \"%s\": %w", filepath, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
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
	SID          string `yaml:"sid"`
	LocalAddr    string `yaml:"localAddr"`
	RemoteAddr   string `yaml:"remoteAddr"`
	SIDStructure string `yaml:"sidStructure"`
}

type waypoint struct {
	RouterID string `yaml:"routerID"`
	SID      string `yaml:"sid"` // optional: fixed SID override
}

type srPolicy struct {
	PCEPSessionAddr netip.Addr `yaml:"pcepSessionAddr"`
	SrcAddr         netip.Addr `yaml:"srcAddr"`
	DstAddr         netip.Addr `yaml:"dstAddr"`
	SrcRouterID     string     `yaml:"srcRouterID"`
	DstRouterID     string     `yaml:"dstRouterID"`
	Name            string     `yaml:"name"`
	SegmentList     []segment  `yaml:"segmentList"`
	Color           uint32     `yaml:"color"`
	Type            string     `yaml:"type"`
	Metric          string     `yaml:"metric"`
	Waypoints       []waypoint `yaml:"waypoints"`
}

type inputFormat struct {
	SRPolicy srPolicy `yaml:"srPolicy"`
	ASN      uint32   `yaml:"asn"`
}

const (
	srPolicyTypeExplicit = "explicit"
	srPolicyTypeDynamic  = "dynamic"
)

const (
	metricTypeIGP      = "igp"
	metricTypeDelay    = "delay"
	metricTypeTE       = "te"
	metricTypeHopcount = "hopcount"
)

func addSRPolicy(out, errOut io.Writer, input inputFormat, jsonFlag, noSIDValidate bool, client pb.PCEServiceClient) error {
	if noSIDValidate {
		fmt.Fprintln(errOut, "warning: skipping SID validation (--no-sid-validate)")
	}

	usesRouterID := input.SRPolicy.SrcRouterID != "" || input.SRPolicy.DstRouterID != ""
	usesEndpointAddr := input.SRPolicy.SrcAddr.IsValid() || input.SRPolicy.DstAddr.IsValid()
	if usesRouterID && usesEndpointAddr {
		return errors.New("srcRouterID / dstRouterID and srcAddr / dstAddr are mutually exclusive, use one form only")
	}

	if usesRouterID {
		if err := addSRPolicyWithRouterID(input, noSIDValidate, client); err != nil {
			return translateCreateSRPolicyError(err)
		}
	} else {
		if err := addSRPolicyWithEndpointAddr(input, noSIDValidate, client); err != nil {
			return translateCreateSRPolicyError(err)
		}
	}

	if jsonFlag {
		return writeJSON(out, statusResult{Status: statusSuccess})
	}
	fmt.Fprintln(out, "success!")

	return nil
}

// translateCreateSRPolicyError converts gRPC errors into CLI-friendly messages.
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
		switch info.Reason {
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

func addSRPolicyWithEndpointAddr(input inputFormat, noSIDValidate bool, client pb.PCEServiceClient) error {
	if input.SRPolicy.Type != "" && input.SRPolicy.Type != srPolicyTypeExplicit {
		return fmt.Errorf("the srcAddr / dstAddr form supports `type: explicit` only, got %q", input.SRPolicy.Type)
	}
	if input.SRPolicy.Metric != "" || len(input.SRPolicy.Waypoints) > 0 {
		return errors.New("`metric` and `waypoints` require a dynamic path, which the srcAddr / dstAddr form does not support")
	}

	if !input.SRPolicy.PCEPSessionAddr.IsValid() || input.SRPolicy.Color == 0 || !input.SRPolicy.SrcAddr.IsValid() || !input.SRPolicy.DstAddr.IsValid() || len(input.SRPolicy.SegmentList) == 0 {
		sampleInput := "srPolicy:\n" +
			"  pcepSessionAddr: 192.0.2.1\n" +
			"  srcAddr: 192.0.2.1\n" +
			"  dstAddr: 192.0.2.2\n" +
			"  name: name\n" +
			"  color: 100\n" +
			"  segmentList:\n" +
			"    - sid: 16003\n" +
			"    - sid: 16002\n\n"

		errMsg := "invalid input\n" +
			"input example is below\n\n" +
			sampleInput +
			"or, to resolve endpoints from the TED by router ID instead,\n" +
			"use the srcRouterID / dstRouterID form\n"
		return errors.New(errMsg)
	}

	segmentList := []*pb.Segment{}
	for _, segment := range input.SRPolicy.SegmentList {
		pbSeg := &pb.Segment{
			Sid:          segment.SID,
			LocalAddr:    segment.LocalAddr,
			RemoteAddr:   segment.RemoteAddr,
			SidStructure: segment.SIDStructure,
		}
		segmentList = append(segmentList, pbSeg)
	}
	srPolicy := &pb.SRPolicy{
		PeerAddr:    input.SRPolicy.PCEPSessionAddr.AsSlice(),
		SrcAddr:     input.SRPolicy.SrcAddr.AsSlice(),
		DstAddr:     input.SRPolicy.DstAddr.AsSlice(),
		SegmentList: segmentList,
		Color:       input.SRPolicy.Color,
		PolicyName:  input.SRPolicy.Name,
		Type:        pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT,
	}

	request := &pb.CreateSRPolicyRequest{
		SrPolicy:           srPolicy,
		Asn:                input.ASN,
		DisablePathCompute: true,
		NoSidValidate:      noSIDValidate,
	}
	return grpc.CreateSRPolicy(client, request)
}

func addSRPolicyWithRouterID(input inputFormat, noSIDValidate bool, client pb.PCEServiceClient) error {
	sampleInputDynamic, sampleInputExplicit := sampleInputs()

	if err := validateCommonInput(input, sampleInputDynamic, sampleInputExplicit); err != nil {
		return err
	}

	srPolicyType, metric, segmentList, waypoints, err := buildPolicyByType(input, sampleInputDynamic, sampleInputExplicit)
	if err != nil {
		return err
	}

	srPolicy := &pb.SRPolicy{
		PeerAddr:    input.SRPolicy.PCEPSessionAddr.AsSlice(),
		SrcRouterId: input.SRPolicy.SrcRouterID,
		DstRouterId: input.SRPolicy.DstRouterID,
		Color:       input.SRPolicy.Color,
		PolicyName:  input.SRPolicy.Name,
		Type:        srPolicyType,
		SegmentList: segmentList,
		Metric:      metric,
		Waypoints:   waypoints,
	}

	req := &pb.CreateSRPolicyRequest{
		SrPolicy:      srPolicy,
		Asn:           input.ASN,
		NoSidValidate: noSIDValidate,
	}

	return grpc.CreateSRPolicy(client, req)
}

func sampleInputs() (dynamic, explicit string) {
	dynamic = "#case: dynamic path\n" +
		"asn: 65000\n" +
		"srPolicy:\n" +
		"  pcepSessionAddr: 192.0.2.1\n" +
		"  srcRouterID: 0000.0aff.0001\n" +
		"  dstRouterID: 0000.0aff.0004\n" +
		"  name: name\n" +
		"  color: 100\n" +
		"  type: dynamic\n" +
		"  metric: igp / te / delay\n"

	explicit = "#case: explicit path\n" +
		"asn: 65000\n" +
		"srPolicy:\n" +
		"  pcepSessionAddr: 192.0.2.1\n" +
		"  srcRouterID: 0000.0aff.0001\n" +
		"  dstRouterID: 0000.0aff.0002\n" +
		"  name: name\n" +
		"  color: 100\n" +
		"  type: explicit\n" +
		"  segmentList:\n" +
		"    - sid: 16003\n" +
		"    - sid: 16002\n"

	return
}

func validateCommonInput(input inputFormat, sampleDynamic, sampleExplicit string) error {
	if input.ASN == 0 ||
		!input.SRPolicy.PCEPSessionAddr.IsValid() ||
		input.SRPolicy.Color == 0 ||
		input.SRPolicy.SrcRouterID == "" ||
		input.SRPolicy.DstRouterID == "" {

		return errors.New(
			"invalid input\n" +
				"input example is below\n\n" +
				sampleDynamic +
				sampleExplicit +
				"or, to specify endpoints directly instead of resolving router IDs from the TED,\n" +
				"use the srcAddr / dstAddr form\n",
		)
	}
	return nil
}

func buildPolicyByType(
	input inputFormat,
	sampleDynamic, sampleExplicit string,
) (
	pb.SRPolicyType,
	pb.MetricType,
	[]*pb.Segment,
	[]*pb.Waypoint,
	error,
) {
	switch input.SRPolicy.Type {
	case srPolicyTypeExplicit:
		return buildExplicitPolicy(input, sampleExplicit)
	case srPolicyTypeDynamic:
		return buildDynamicPolicy(input, sampleDynamic)
	default:
		return 0, 0, nil, nil, errors.New("invalid input `type`")
	}
}

func buildExplicitPolicy(
	input inputFormat,
	sampleExplicit string,
) (
	pb.SRPolicyType,
	pb.MetricType,
	[]*pb.Segment,
	[]*pb.Waypoint,
	error,
) {
	if len(input.SRPolicy.SegmentList) == 0 {
		return 0, 0, nil, nil, errors.New(
			"invalid input\n" +
				"input example is below\n\n" +
				sampleExplicit,
		)
	}

	var segments []*pb.Segment
	for _, s := range input.SRPolicy.SegmentList {
		segments = append(segments, &pb.Segment{
			Sid:          s.SID,
			LocalAddr:    s.LocalAddr,
			RemoteAddr:   s.RemoteAddr,
			SidStructure: s.SIDStructure,
		})
	}

	return pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, 0, segments, nil, nil
}

func buildDynamicPolicy(
	input inputFormat,
	sampleDynamic string,
) (
	pb.SRPolicyType,
	pb.MetricType,
	[]*pb.Segment,
	[]*pb.Waypoint,
	error,
) {
	if input.SRPolicy.Metric == "" {
		return 0, 0, nil, nil, errors.New(
			"invalid input\n" +
				"input example is below\n\n" +
				sampleDynamic,
		)
	}

	metric, err := parseMetric(input.SRPolicy.Metric)
	if err != nil {
		return 0, 0, nil, nil, err
	}

	var waypoints []*pb.Waypoint
	for _, wp := range input.SRPolicy.Waypoints {
		waypoints = append(waypoints, &pb.Waypoint{
			RouterId: wp.RouterID,
			Sid:      wp.SID,
		})
	}

	return pb.SRPolicyType_SR_POLICY_TYPE_DYNAMIC, metric, nil, waypoints, nil
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
