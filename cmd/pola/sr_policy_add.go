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

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyAddCmd() *cobra.Command {
	srPolicyAddCmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {
			noLinkStateFlag, err := cmd.Flags().GetBool("no-link-state")
			if err != nil {
				return fmt.Errorf("failed to retrieve 'no-link-state' flag: %v", err)
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

			if err := addSRPolicy(inputData, jsonFmt, noLinkStateFlag); err != nil {
				return fmt.Errorf("failed to add SR policy: %v", err)
			}
			return nil
		},
	}

	srPolicyAddCmd.Flags().BoolP("no-link-state", "l", false, "add SR Policy without Link State")
	srPolicyAddCmd.Flags().StringP("file", "f", "", "[mandatory] path to YAML formatted LSP information file")

	return srPolicyAddCmd
}

// Unify with table.Segment
type Segment struct {
	Sid          string `yaml:"sid"`
	LocalAddr    string `yaml:"localAddr"`
	RemoteAddr   string `yaml:"remoteAddr"`
	SidStructure string `yaml:"sidStructure"`
}

// Unify with table.SRPolciy
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
}

type InputFormat struct {
	SRPolicy SRPolicy `yaml:"srPolicy"`
	ASN      uint32   `yaml:"asn"`
}

func addSRPolicy(input InputFormat, jsonFlag bool, noLinkStateFlag bool) error {
	if noLinkStateFlag {
		if err := addSRPolicyNoLinkState(input); err != nil {
			return err
		}
	} else {
		if err := addSRPolicyLinkState(input); err != nil {
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

func addSRPolicyNoLinkState(input InputFormat) error {
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
			Sid:          segment.Sid,
			LocalAddr:    segment.LocalAddr,
			RemoteAddr:   segment.RemoteAddr,
			SidStructure: segment.SidStructure,
		}
		segmentList = append(segmentList, pbSeg)
	}
	srPolicy := &pb.SRPolicy{
		PCEPSessionAddr: input.SRPolicy.PCEPSessionAddr.AsSlice(),
		SrcAddr:         input.SRPolicy.SrcAddr.AsSlice(),
		DstAddr:         input.SRPolicy.DstAddr.AsSlice(),
		SegmentList:     segmentList,
		Color:           input.SRPolicy.Color,
		PolicyName:      input.SRPolicy.Name,
	}

	inputData := &pb.CreateSRPolicyInput{
		SRPolicy: srPolicy,
	}
	if err := grpc.CreateSRPolicyWithoutLinkState(client, inputData); err != nil {
		return err
	}

	return nil
}

func addSRPolicyLinkState(input InputFormat) error {
	sampleInputDynamic := "#case: dynamic path\n" +
		"asn: 65000\n" +
		"srPolicy:\n" +
		"  pcepSessionAddr: 192.0.2.1\n" +
		"  srcRouterID: 0000.0aff.0001\n" +
		"  dstRouterID: 0000.0aff.0004\n" +
		"  name: name\n" +
		"  color: 100\n" +
		"  type: dynamic\n" +
		"  metric: igp / te / delay\n"
	sampleInputExplicit := "#case: explicit path\n" +
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
	if input.ASN == 0 || !input.SRPolicy.PCEPSessionAddr.IsValid() || input.SRPolicy.Color == 0 || input.SRPolicy.SrcRouterID == "" || input.SRPolicy.DstRouterID == "" {
		errMsg := "invalid input\n" +
			"input example is below\n\n" +
			sampleInputDynamic +
			sampleInputExplicit +
			"or, if create SR Policy without TED, then use `--no-link-state` flag\n"

		return errors.New(errMsg)
	}
	var srPolicyType pb.SRPolicyType
	var metric pb.MetricType
	var segmentList []*pb.Segment
	switch input.SRPolicy.Type {
	case "explicit":
		if len(input.SRPolicy.SegmentList) == 0 {
			errMsg := "invalid input\n" +
				"input example is below\n\n" +
				sampleInputExplicit

			return errors.New(errMsg)
		}
		srPolicyType = pb.SRPolicyType_EXPLICIT
		for _, segment := range input.SRPolicy.SegmentList {
			segmentList = append(segmentList, &pb.Segment{Sid: segment.Sid})
		}
	case "dynamic":
		if input.SRPolicy.Metric == "" {
			errMsg := "invalid input\n" +
				"input example is below\n\n" +
				sampleInputDynamic
			return errors.New(errMsg)
		}
		srPolicyType = pb.SRPolicyType_DYNAMIC
		switch input.SRPolicy.Metric {
		case "igp":
			metric = pb.MetricType_IGP
		case "delay":
			metric = pb.MetricType_DELAY
		case "te":
			metric = pb.MetricType_TE
		default:
			return fmt.Errorf("invalid input `metric`")
		}

	default:
		return fmt.Errorf("invalid input `type`")
	}

	srPolicy := &pb.SRPolicy{
		PCEPSessionAddr: input.SRPolicy.PCEPSessionAddr.AsSlice(),
		SrcRouterID:     input.SRPolicy.SrcRouterID,
		DstRouterID:     input.SRPolicy.DstRouterID,
		Color:           input.SRPolicy.Color,
		PolicyName:      input.SRPolicy.Name,
		Type:            srPolicyType,
		SegmentList:     segmentList,
		Metric:          metric,
	}
	inputData := &pb.CreateSRPolicyInput{
		SRPolicy: srPolicy,
		Asn:      input.ASN,
	}
	if err := grpc.CreateSRPolicy(client, inputData); err != nil {
		return fmt.Errorf("gRPC Server Error: %s", err.Error())

	}

	return nil
}
