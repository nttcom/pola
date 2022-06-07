package main

import (
	"fmt"
	"net"
	"os"

	pb "github.com/nttcom/pola/api/grpc"
	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
)

func newLspAddCmd() *cobra.Command {

	lspAddCmd := &cobra.Command{
		Use: "add",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonFmt, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			filepath, err := cmd.Flags().GetString("file")
			if err != nil {
				return err
			}
			if filepath == "" {
				fmt.Printf("File path option \"-f filepath\" is mandatory\n")
				cmd.HelpFunc()(cmd, args)
				return nil
			}
			f, openErr := os.Open(filepath)
			if openErr != nil {
				return err
			}
			defer f.Close()
			InputData := InputFormat{}
			if err := yaml.NewDecoder(f).Decode(&InputData); err != nil {
				return err
			}
			if err = addLsp(InputData.SrPolicy, jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	lspAddCmd.Flags().BoolP("json", "j", false, "output json format")
	lspAddCmd.Flags().StringP("file", "f", "", "[mandatory] path to yaml formatted LSP infomation file")
	return lspAddCmd

}

type Segment struct {
	Sid uint32 `yaml:"sid"`
	Nai net.IP `yaml:"nai"`
}

type SrPolicy struct {
	PeerAddr    net.IP    `yaml:"peerAddr"`
	Name        string    `yaml:"name"`
	Segmentlist []Segment `yaml:"segmentlist"`
	SrcAddr     net.IP    `yaml:"srcAddr"`
	DstAddr     net.IP    `yaml:"dstAddr"`
	Color       uint32    `yaml:"color"`
}

type InputFormat struct {
	SrPolicy SrPolicy `yaml:"srPolicy"`
}

func addLsp(srPolicy SrPolicy, jsonFlag bool) error {
	labels := []*pb.Label{}
	for _, segment := range srPolicy.Segmentlist {
		label := pb.Label{
			Sid:    segment.Sid,
			LoAddr: []byte(segment.Nai.To4()), //supported only ipv4 address
		}
		labels = append(labels, &label)
	}
	lspData := &pb.LspData{
		PcepSessionAddr: []byte(srPolicy.PeerAddr.To4()),
		SrcAddr:         []byte(srPolicy.SrcAddr.To4()),
		DstAddr:         []byte(srPolicy.DstAddr.To4()),
		Labels:          labels,
		Color:           srPolicy.Color,
		PolicyName:      srPolicy.Name,
	}
	if err := createLsp(client, lspData); err != nil {
		return err
	} else {
		if jsonFlag {
			fmt.Printf("{\"status\": \"success\"}\n")
		} else {
			fmt.Printf("success!\n")
		}
	}

	return nil
}
