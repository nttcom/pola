// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"os"

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"

	"github.com/nttcom/pola/cmd/pola/grpc"
)

func newSRPolicyDeleteCmd() *cobra.Command {
	srPolicyDeleteCmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {

			filepath, err := cmd.Flags().GetString("file")
			if err != nil {
				return err
			}
			if filepath == "" {
				return fmt.Errorf("file path option \"-f filepath\" is mandatory")

			}
			f, openErr := os.Open(filepath)
			if openErr != nil {
				return fmt.Errorf("file \"%s\" can't open", filepath)
			}
			defer f.Close()
			InputData := InputFormat{}
			if err := yaml.NewDecoder(f).Decode(&InputData); err != nil {
				return fmt.Errorf("file \"%s\" can't open", filepath)

			}
			if err := deleteSRPolicy(InputData, jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	srPolicyDeleteCmd.Flags().StringP("file", "f", "", "[mandatory] path to yaml formatted LSP information file")

	return srPolicyDeleteCmd

}

func deleteSRPolicy(input InputFormat, jsonFlag bool) error {
	if err := deleteSRPolicyLinkState(input); err != nil {
		return err
	}

	if jsonFlag {
		fmt.Printf("{\"status\": \"success\"}\n")
	} else {
		fmt.Printf("success!\n")
	}

	return nil
}

func deleteSRPolicyLinkState(input InputFormat) error {
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
	if input.Asn == 0 || !input.SRPolicy.PcepSessionAddr.IsValid() || input.SRPolicy.Color == 0 || input.SRPolicy.SrcRouterID == "" || input.SRPolicy.DstRouterID == "" {
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
		for _, seg := range input.SRPolicy.SegmentList {
			segmentList = append(segmentList, &pb.Segment{Sid: seg.Sid})
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
		PcepSessionAddr: input.SRPolicy.PcepSessionAddr.AsSlice(),
		SrcRouterID:     input.SRPolicy.SrcRouterID,
		DstRouterID:     input.SRPolicy.DstRouterID,
		Color:           input.SRPolicy.Color,
		PolicyName:      input.SRPolicy.Name,
		Type:            srPolicyType,
		SegmentList:     segmentList,
		Metric:          metric,
	}
	inputData := &pb.DeleteSRPolicyInput{
		SRPolicy: srPolicy,
		Asn:      input.Asn,
	}
	if err := grpc.DeleteSRPolicy(client, inputData); err != nil {
		return fmt.Errorf("gRPC Server Error: %s", err.Error())
	}

	return nil
}
