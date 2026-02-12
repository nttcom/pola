// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"

	pb "github.com/nttcom/pola/api/pola/v1"
	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyAddCmd() *cobra.Command {
	srPolicyAddCmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {
			noSIDValidateFlag, err := cmd.Flags().GetBool("no-sid-validate")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'no-sid-validate' flag: %v", err)
			}

			filepath, err := cmd.Flags().GetString("file")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'file' flag: %v", err)
			}
			if filepath == "" {
				return fmt.Errorf("file path option \"-f filepath\" is mandatory")
			}

			f, err := os.Open(filepath)
			if err != nil {
				return fmt.Errorf("failed to open file \"%s\": %v", filepath, err)
			}
			defer func() {
				if err := f.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "warning: failed to close file \"%s\": %v\n", filepath, err)
				}
			}()

			inputData := InputFormat{}
			if err := yaml.NewDecoder(f).Decode(&inputData); err != nil {
				return fmt.Errorf("YAML syntax error in file \"%s\": %v", filepath, err)
			}

			if err := addSRPolicy(inputData, jsonFmt, noSIDValidateFlag); err != nil {
				return fmt.Errorf("failed to add SR policy: %v", err)
			}
			return nil
		},
	}

	srPolicyAddCmd.Flags().BoolP("no-sid-validate", "s", false, "disable SR policy SID validation")
	srPolicyAddCmd.Flags().StringP("file", "f", "", "[mandatory] path to YAML formatted LSP information file")

	return srPolicyAddCmd
}

type Segment struct {
	SID          string `yaml:"sid"`
	LocalAddr    string `yaml:"localAddr"`
	RemoteAddr   string `yaml:"remoteAddr"`
	SIDStructure string `yaml:"sidStructure"`
}

type Waypoint struct {
	RouterID string `yaml:"routerID"`
	SID      string `yaml:"sid"` // optional: fixed SID override
}

type SRPolicy struct {
	PCEPSessionAddr netip.Addr `yaml:"pcepSessionAddr"`
	SrcAddr         netip.Addr `yaml:"srcAddr"`
	DstAddr         netip.Addr `yaml:"dstAddr"`
	SrcRouterID     string     `yaml:"srcRouterID"`
	DstRouterID     string     `yaml:"dstRouterID"`
	Name            string     `yaml:"name"`
	SegmentList     []Segment  `yaml:"segmentList"`
	Color           uint32     `yaml:"color"`
	Type            string     `yaml:"type"`
	Metric          string     `yaml:"metric"`
	Waypoints       []Waypoint `yaml:"waypoints"`
}

type InputFormat struct {
	SRPolicy SRPolicy `yaml:"srPolicy"`
	ASN      uint32   `yaml:"asn"`
}

func addSRPolicy(input InputFormat, jsonFlag bool, explicitPathFlag bool) error {
	if explicitPathFlag {
		if err := addSRPolicyWithoutSIDValidation(input); err != nil {
			return err
		}
	} else {
		if err := addSRPolicyWithSIDValidation(input); err != nil {
			return err
		}
	}
	if jsonFlag {
		fmt.Printf("{\"status\": \"success\"}\n")
	} else {
		fmt.Printf("success!\n")
	}

	return nil
}

func addSRPolicyWithoutSIDValidation(input InputFormat) error {
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
			sampleInput
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
		PcepSessionAddr: input.SRPolicy.PCEPSessionAddr.AsSlice(),
		SrcAddr:         input.SRPolicy.SrcAddr.AsSlice(),
		DstAddr:         input.SRPolicy.DstAddr.AsSlice(),
		SegmentList:     segmentList,
		Color:           input.SRPolicy.Color,
		PolicyName:      input.SRPolicy.Name,
	}

	request := &pb.CreateSRPolicyRequest{
		SrPolicy: srPolicy,
	}
	if err := grpc.CreateSRPolicy(client, request); err != nil {
		return err
	}

	return nil
}

func addSRPolicyWithSIDValidation(input InputFormat) error {
	sampleInputDynamic, sampleInputExplicit := sampleInputs()

	if err := validateCommonInput(input, sampleInputDynamic, sampleInputExplicit); err != nil {
		return err
	}

	srPolicyType, metric, segmentList, waypoints, err :=
		buildPolicyByType(input, sampleInputDynamic, sampleInputExplicit)
	if err != nil {
		return err
	}

	srPolicy := &pb.SRPolicy{
		PcepSessionAddr: input.SRPolicy.PCEPSessionAddr.AsSlice(),
		SrcRouterId:     input.SRPolicy.SrcRouterID,
		DstRouterId:     input.SRPolicy.DstRouterID,
		Color:           input.SRPolicy.Color,
		PolicyName:      input.SRPolicy.Name,
		Type:            srPolicyType,
		SegmentList:     segmentList,
		Metric:          metric,
		Waypoints:       waypoints,
	}

	req := &pb.CreateSRPolicyRequest{
		SrPolicy: srPolicy,
		Asn:      input.ASN,
	}

	if err := grpc.CreateSRPolicy(client, req); err != nil {
		return fmt.Errorf("gRPC Server Error: %w", err)
	}

	return nil
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

func validateCommonInput(input InputFormat, sampleDynamic, sampleExplicit string) error {
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
				"or, if create SR Policy without TED, then use `--no-sid-validate` flag\n",
		)
	}
	return nil
}

func buildPolicyByType(
	input InputFormat,
	sampleDynamic, sampleExplicit string,
) (
	pb.SRPolicyType,
	pb.MetricType,
	[]*pb.Segment,
	[]*pb.Waypoint,
	error,
) {
	switch input.SRPolicy.Type {
	case "explicit":
		return buildExplicitPolicy(input, sampleExplicit)
	case "dynamic":
		return buildDynamicPolicy(input, sampleDynamic)
	default:
		return 0, 0, nil, nil, fmt.Errorf("invalid input `type`")
	}
}

func buildExplicitPolicy(
	input InputFormat,
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
		segments = append(segments, &pb.Segment{Sid: s.SID})
	}

	return pb.SRPolicyType_SR_POLICY_TYPE_EXPLICIT, 0, segments, nil, nil
}

func buildDynamicPolicy(
	input InputFormat,
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
	case "igp":
		return pb.MetricType_METRIC_TYPE_IGP, nil
	case "delay":
		return pb.MetricType_METRIC_TYPE_DELAY, nil
	case "te":
		return pb.MetricType_METRIC_TYPE_TE, nil
	default:
		return 0, fmt.Errorf("invalid input `metric`")
	}
}
