// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"encoding/json"
	"fmt"

	"github.com/nttcom/pola/cmd/pola/grpc"
	"github.com/nttcom/pola/pkg/table"
	"github.com/spf13/cobra"
)

func newTEDCmd() *cobra.Command {
	return &cobra.Command{
		Use: "ted",
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := printTED(jsonFmt); err != nil {
				return err
			}
			return nil
		},
	}
}

func printTED(jsonFlag bool) error {
	ted, err := grpc.GetTED(client)
	if err != nil {
		return err
	}

	if ted == nil {
		fmt.Println("TED is disabled by polad")
		return nil
	}

	if jsonFlag {
		outputJSON, err := json.Marshal(tedToJSONMap(ted))
		if err != nil {
			return err
		}
		fmt.Println(string(outputJSON))
	} else {
		ted.Print()
	}

	return nil
}

// tedToJSONMap converts ted into the map shape marshalled by printTED.
func tedToJSONMap(ted *table.LsTED) map[string]any {
	nodes := []map[string]any{}
	for _, node := range ted.Nodes {
		nodes = append(nodes, tedNodeToJSONMap(node))
	}

	return map[string]any{
		"ted": nodes,
	}
}

func tedNodeToJSONMap(node *table.LsNode) map[string]any {
	links := []map[string]any{}
	for _, link := range node.Links {
		links = append(links, tedLinkToJSONMap(link))
	}

	prefixes := []map[string]any{}
	for _, prefix := range node.Prefixes {
		prefixMap := map[string]any{
			"prefix": prefix.Prefix.String(),
		}
		if prefix.HasPrefixSID() {
			prefixMap["sidIndex"] = prefix.SidIndex
		}
		prefixes = append(prefixes, prefixMap)
	}

	srv6SIDs := []map[string]any{}
	for _, srv6SID := range node.SRv6SIDs {
		srv6SIDs = append(srv6SIDs, map[string]any{
			"sids":             srv6SID.Sids,
			"endpointBehavior": srv6SID.EndpointBehavior,
			"multiTopoIDs":     srv6SID.MultiTopoIDs,
		})
	}

	return map[string]any{ // TODO: Fix format according to readme
		"asn":        node.ASN,
		"routerID":   node.RouterID,
		"isisAreaID": node.IsisAreaID,
		"hostname":   node.Hostname,
		"srgbBegin":  node.SrgbBegin,
		"srgbEnd":    node.SrgbEnd,
		"prefixes":   prefixes,
		"links":      links,
		"srv6SIDs":   srv6SIDs,
	}
}

func tedLinkToJSONMap(link *table.LsLink) map[string]any {
	metrics := []map[string]any{}
	for _, metric := range link.Metrics {
		metrics = append(metrics, map[string]any{
			"type":  metric.Type.String(),
			"value": metric.Value,
		})
	}

	// Links whose BGP-LS descriptor carried no interface address report "None",
	// matching table.LsTED.Print.
	localIP := "None"
	if link.LocalIP.IsValid() {
		localIP = link.LocalIP.String()
	}
	remoteIP := "None"
	if link.RemoteIP.IsValid() {
		remoteIP = link.RemoteIP.String()
	}

	return map[string]any{
		"localIP":    localIP,
		"remoteIP":   remoteIP,
		"remoteNode": link.RemoteNode.RouterID,
		"metrics":    metrics,
		"adjSid":     link.AdjSid,
	}
}
