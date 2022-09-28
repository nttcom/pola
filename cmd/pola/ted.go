// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

func newTedCmd() *cobra.Command {

	tedCmd := &cobra.Command{
		Use: "ted",
		RunE: func(cmd *cobra.Command, args []string) error {
			jsonFmt, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			if err := showTed(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}

	tedCmd.Flags().BoolP("json", "j", false, "output json format")
	return tedCmd
}

func showTed(jsonFlag bool) error {
	ted, err := getTed(client)
	if err != nil {
		return err
	}

	if ted == nil {
		fmt.Printf("TED is disabled by polad\n")
		return nil
	}
	if jsonFlag {
		// output json format
		nodes := []map[string]interface{}{}
		for _, as := range ted.Nodes {
			for _, node := range as {
				tmpNode := map[string]interface{}{ // TODO: Fix format according to readme
					"asn":        node.Asn,
					"routerId":   node.RouterId,
					"isisAreaId": node.IsisAreaId,
					"hostname":   node.Hostname,
					"srgbBegin":  node.SrgbBegin,
					"srgbEnd":    node.SrgbEnd,
					"prefixes":   []map[string]interface{}{},
					"links":      []map[string]interface{}{},
				}
				links := []map[string]interface{}{}
				for _, link := range node.Links {
					tmpLink := map[string]interface{}{
						"localIP":    link.LocalIP.String(),
						"remoteIP":   link.RemoteIP.String(),
						"remoteNode": link.RemoteNode.RouterId,
						"metrics":    []map[string]interface{}{},
						"adjSid":     link.AdjSid,
					}
					metrics := []map[string]interface{}{}
					for _, metric := range link.Metrics {
						tmpMetric := map[string]interface{}{
							"type":  metric.Type.String(),
							"value": metric.Value,
						}
						metrics = append(metrics, tmpMetric)
					}
					tmpLink["metrics"] = metrics
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
				nodes = append(nodes, tmpNode)

			}
		}
		output_map := map[string]interface{}{
			"ted": nodes,
		}
		output_json, err := json.Marshal(output_map)
		if err != nil {
			return err
		}
		fmt.Printf("%+v\n", string(output_json))

	} else {
		//output user-friendly format
		ted.ShowTed()
	}
	return nil
}
