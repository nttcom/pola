// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/spf13/cobra"
)

func newTedCmd() *cobra.Command {
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
	ted, err := grpc.GetTed(client)
	if err != nil {
		return err
	}

	if ted == nil {
		fmt.Println("TED is disabled by polad")
		return nil
	}

	if jsonFlag {
		// Output JSON format
		nodes := []map[string]interface{}{}
		for _, as := range ted.Nodes {
			for _, node := range as {
				tmpNode := map[string]interface{}{ // TODO: Fix format according to readme
					"asn":        node.Asn,
					"routerID":   node.RouterID,
					"isisAreaID": node.IsisAreaID,
					"hostname":   node.Hostname,
					"srgbBegin":  node.SrgbBegin,
					"srgbEnd":    node.SrgbEnd,
					"prefixes":   []map[string]interface{}{},
					"links":      []map[string]interface{}{},
				}

				links := []map[string]interface{}{}
				for _, link := range node.Links {
					metrics := []map[string]interface{}{}
					for _, metric := range link.Metrics {
						tmpMetric := map[string]interface{}{
							"type":  metric.Type.String(),
							"value": metric.Value,
						}
						metrics = append(metrics, tmpMetric)
					}

					tmpLink := map[string]interface{}{
						"localIP":    link.LocalIP.String(),
						"remoteIP":   link.RemoteIP.String(),
						"remoteNode": link.RemoteNode.RouterID,
						"metrics":    metrics,
						"adjSid":     link.AdjSid,
					}
					links = append(links, tmpLink)
				}
				tmpNode["links"] = links

				prefixes := []map[string]interface{}{}
				for _, prefix := range node.Prefixes {
					tmpPrefix := map[string]interface{}{
						"prefix": prefix.Prefix.String(),
					}
					if prefix.SidIndex != 0 {
						tmpPrefix["sidIndex"] = prefix.SidIndex
					}
					prefixes = append(prefixes, tmpPrefix)
				}
				tmpNode["prefixes"] = prefixes

				srv6SIDs := []map[string]interface{}{}
				for _, srv6SID := range node.SRv6SIDs {
					tmpSrv6SID := map[string]interface{}{
						"sids":             srv6SID.Sids,
						"endpointBehavior": srv6SID.EndpointBehavior,
						"multiTopoIDs":     srv6SID.MultiTopoIDs,
						"serviceType":      srv6SID.ServiceType,
						"trafficType":      srv6SID.TrafficType,
						"opaqueType":       srv6SID.OpaqueType,
						"value":            hex.EncodeToString(srv6SID.Value),
					}
					srv6SIDs = append(srv6SIDs, tmpSrv6SID)
				}
				tmpNode["srv6SIDs"] = srv6SIDs

				nodes = append(nodes, tmpNode)
			}
		}

		outputMap := map[string]interface{}{
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
