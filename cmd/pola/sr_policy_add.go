// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

func newSrPolicyAddCmd() *cobra.Command {

	srPolicyAddCmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {

			noLinkStateFlag, err := cmd.Flags().GetBool("no-link-state")
			if err != nil {
				return fmt.Errorf("flag error")

			}

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
			if err := addSrPolicy(InputData, jsonFmt, noLinkStateFlag); err != nil {
				return err
			}
			return nil
		},
	}

	srPolicyAddCmd.Flags().BoolP("no-link-state", "l", false, "add SR Policy without Link State")
	srPolicyAddCmd.Flags().StringP("file", "f", "", "[mandatory] path to yaml formatted LSP information file")

	return srPolicyAddCmd

}

type Segment struct {
	Sid uint32 `yaml:"sid"`
	Nai net.IP `yaml:"nai"`
}

type SrPolicy struct {
	PcepSessionAddr net.IP    `yaml:"pcepSessionAddr"`
	SrcAddr         net.IP    `yaml:"srcAddr"`
	DstAddr         net.IP    `yaml:"dstAddr"`
	SrcRouterId     string    `yaml:"srcRouterId"`
	DstRouterId     string    `yaml:"dstRouterId"`
	Name            string    `yaml:"name"`
	SegmentList     []Segment `yaml:"segmentList"`
	Color           uint32    `yaml:"color"`
	Type            string    `yaml:"type"`
	Metric          string    `yaml:"metric"`
}

type InputFormat struct {
	SrPolicy SrPolicy `yaml:"srPolicy"`
	Asn      uint32   `yaml:"asn"`
}

func addSrPolicy(input InputFormat, jsonFlag bool, noLinkStateFlag bool) error {
	if noLinkStateFlag {
		if input.SrPolicy.PcepSessionAddr == nil || input.SrPolicy.Color == 0 || input.SrPolicy.SrcAddr == nil || input.SrPolicy.DstAddr == nil || len(input.SrPolicy.SegmentList) == 0 || input.SrPolicy.Color == 0 {
			sampleInput := "srPolicy:\n" +
				"    pcepSessionAddr: 192.0.2.1\n" +
				"    srcAddr: 192.0.2.1\n" +
				"    dstAddr: 192.0.2.2\n" +
				"    name: name\n" +
				"    color: 100\n" +
				"    segmentList:\n" +
				"        - sid: 16003\n" +
				"          nai: 192.0.2.3\n" +
				"        - sid: 16002\n" +
				"          nai: 192.0.2.2\n\n"

			errMsg := "invalid input\n" +
				"input examplse is below\n\n" +
				sampleInput
			return errors.New(errMsg)
		}

		segmentList := []*pb.Segment{}
		for _, seg := range input.SrPolicy.SegmentList {
			segment := pb.Segment{
				Sid:    seg.Sid,
				LoAddr: []byte(seg.Nai.To4()), //supported only ipv4 address
			}
			segmentList = append(segmentList, &segment)
		}
		srPolicy := &pb.SrPolicy{
			PcepSessionAddr: []byte(input.SrPolicy.PcepSessionAddr.To4()),
			SrcAddr:         []byte(input.SrPolicy.SrcAddr.To4()),
			DstAddr:         []byte(input.SrPolicy.DstAddr.To4()),
			SegmentList:     segmentList,
			Color:           input.SrPolicy.Color,
			PolicyName:      input.SrPolicy.Name,
		}

		inputData := &pb.CreateSrPolicyInput{
			SrPolicy: srPolicy,
		}
		if err := createSrPolicyWithoutLinkState(client, inputData); err != nil {
			return err
		}
	} else {
		sampleInputDynamic := "#case: dynamic path\n" +
			"asn: 65000\n" +
			"srPolicy:\n" +
			"    pcepSessionAddr: 192.0.2.1\n" +
			"    srcRouterId: 0000.0aff.0001\n" +
			"    dstRouterId: 0000.0aff.0004\n" +
			"    name: name\n" +
			"    color: 100\n" +
			"    type: dynamic\n" +
			"    metric: igp / te / delay\n"
		sampleInputExplicit := "#case: explicit path\n" +
			"asn: 65000\n" +
			"srPolicy:\n" +
			"    pcepSessionAddr: 192.0.2.1\n" +
			"    srcRouterId: 0000.0aff.0001\n" +
			"    dstRouterId: 0000.0aff.0002\n" +
			"    name: name\n" +
			"    color: 100\n" +
			"    type: explicit\n" +
			"    segmentList:\n" +
			"        - sid: 16003\n" +
			"        - sid: 16002\n"
		if input.Asn == 0 || input.SrPolicy.PcepSessionAddr == nil || input.SrPolicy.Color == 0 || input.SrPolicy.SrcRouterId == "" || input.SrPolicy.DstRouterId == "" {
			errMsg := "invalid input\n" +
				"input example is below\n\n" +
				sampleInputDynamic +
				sampleInputExplicit +
				"or, if create SR Policy without TED, then use `--no-link-state` flag\n"

			return errors.New(errMsg)
		}
		var srPolicyType pb.SrPolicyType
		var metric pb.MetricType
		var segmentList []*pb.Segment
		switch input.SrPolicy.Type {
		case "explicit":
			if len(input.SrPolicy.SegmentList) == 0 {
				errMsg := "invalid input\n" +
					"input example is below\n\n" +
					sampleInputExplicit

				return errors.New(errMsg)
			}
			srPolicyType = pb.SrPolicyType_EXPLICIT
			for _, seg := range input.SrPolicy.SegmentList {
				segmentList = append(segmentList, &pb.Segment{Sid: seg.Sid})
			}

		case "dynamic":
			if input.SrPolicy.Metric == "" {
				errMsg := "invalid input\n" +
					"input example is below\n\n" +
					sampleInputDynamic
				return errors.New(errMsg)
			}
			srPolicyType = pb.SrPolicyType_DYNAMIC
			switch input.SrPolicy.Metric {
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

		srPolicy := &pb.SrPolicy{
			PcepSessionAddr: []byte(input.SrPolicy.PcepSessionAddr.To4()),
			SrcRouterId:     input.SrPolicy.SrcRouterId,
			DstRouterId:     input.SrPolicy.DstRouterId,
			Color:           input.SrPolicy.Color,
			PolicyName:      input.SrPolicy.Name,
			Type:            srPolicyType,
			SegmentList:     segmentList,
			Metric:          metric,
		}
		inputData := &pb.CreateSrPolicyInput{
			SrPolicy: srPolicy,
			Asn:      input.Asn,
		}
		if err := createSrPolicy(client, inputData); err != nil {
			return fmt.Errorf("gRPC Server Error: %s", err.Error())

		}
	}
	if jsonFlag {
		fmt.Printf("{\"status\": \"success\"}\n")
	} else {
		fmt.Printf("success!\n")
	}

	return nil
}
