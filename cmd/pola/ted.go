// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newTEDCmd() *cobra.Command {
	return &cobra.Command{
		Use: "ted",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := print(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}
}

func print(jsonFlag bool) error {
	ted, err := grpc.GetTED(client)
	if err != nil {
		return err
	}

	if ted == nil {
		fmt.Println("TED is disabled by polad")
		return nil
	}

	if jsonFlag {
		// Output JSON format
		nodes := []map[string]any{}
		for _, as := range ted.Nodes {
			for _, node := range as {
				nodeMap := map[string]any{ // TODO: Fix format according to readme
					"asn":        node.ASN,
					"routerID":   node.RouterID,
					"isisAreaID": node.IsisAreaID,
					"hostname":   node.Hostname,
					"srgbBegin":  node.SrgbBegin,
					"srgbEnd":    node.SrgbEnd,
					"prefixes":   []map[string]any{},
					"links":      []map[string]any{},
				}

				links := []map[string]any{}
				for _, link := range node.Links {
					metrics := []map[string]any{}
					for _, metric := range link.Metrics {
						metricMap := map[string]any{
							"type":  metric.Type.String(),
							"value": metric.Value,
						}
						metrics = append(metrics, metricMap)
					}

					var localIP string
					var remoteIP string
					if link.LocalIP.IsValid() {
						localIP = link.LocalIP.String()
					} else {
						localIP = "None"
					}
					if link.RemoteIP.IsValid() {
						remoteIP = link.RemoteIP.String()
					} else {
						remoteIP = "None"
					}

					linkMap := map[string]any{
						"localIP":    localIP,
						"remoteIP":   remoteIP,
						"remoteNode": link.RemoteNode.RouterID,
						"metrics":    metrics,
						"adjSid":     link.AdjSid,
					}
					links = append(links, linkMap)
				}
				nodeMap["links"] = links

				prefixes := []map[string]any{}
				for _, prefix := range node.Prefixes {
					prefixMap := map[string]any{
						"prefix": prefix.Prefix.String(),
					}
					if prefix.SidIndex != 0 {
						prefixMap["sidIndex"] = prefix.SidIndex
					}
					prefixes = append(prefixes, prefixMap)
				}
				nodeMap["prefixes"] = prefixes

				srv6SIDs := []map[string]any{}
				for _, srv6SID := range node.SRv6SIDs {
					srv6SIDMap := map[string]any{
						"sids":             srv6SID.Sids,
						"endpointBehavior": srv6SID.EndpointBehavior,
						"multiTopoIDs":     srv6SID.MultiTopoIDs,
					}
					srv6SIDs = append(srv6SIDs, srv6SIDMap)
				}
				nodeMap["srv6SIDs"] = srv6SIDs

				nodes = append(nodes, nodeMap)
			}
		}

		outputMap := map[string]any{
			"ted": nodes,
		}

		outputJSON, err := json.Marshal(outputMap)
		if err != nil {
			return err
		}
		fmt.Println(string(outputJSON))

	} else {
		// Output user-friendly format
		ted.Print()
	}

	return nil
}
