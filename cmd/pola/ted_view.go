// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package main

import (
	"slices"

	"github.com/nttcom/pola/pkg/table"
)

type tedNodeView struct {
	ASN        uint32           `json:"asn"`
	RouterID   string           `json:"routerId"`
	Hostname   string           `json:"hostname"`
	IsisAreaID string           `json:"isisAreaId"`
	Srgb       srgbView         `json:"srgb"`
	Prefixes   []tedPrefixView  `json:"prefixes"`
	Links      []tedLinkView    `json:"links"`
	SRv6SIDs   []tedSrv6SIDView `json:"srv6Sids"`
}

type srgbView struct {
	Begin uint32 `json:"begin"`
	End   uint32 `json:"end"`
}

type tedPrefixView struct {
	Prefix   string  `json:"prefix"`
	SidIndex *uint32 `json:"sidIndex,omitempty"`
}

type tedLinkView struct {
	LocalIP        string              `json:"localIp,omitempty"`
	RemoteIP       string              `json:"remoteIp,omitempty"`
	RemoteRouterID string              `json:"remoteRouterId"`
	Metrics        []tedMetricView     `json:"metrics"`
	AdjSid         uint32              `json:"adjSid"`
	Srv6EndXSID    *tedSrv6EndXSIDView `json:"srv6EndXSid,omitempty"`
}

type tedMetricView struct {
	Type  string `json:"type"` // igp | te | delay | hopcount
	Value uint32 `json:"value"`
}

type tedSrv6SIDView struct {
	Sids             []string             `json:"sids"`
	EndpointBehavior endpointBehaviorView `json:"endpointBehavior"`
	SidStructure     sidStructureView     `json:"sidStructure"`
	MultiTopoIDs     []uint32             `json:"multiTopoIds"`
}

type tedSrv6EndXSIDView struct {
	EndpointBehavior endpointBehaviorView `json:"endpointBehavior"`
	Sids             []string             `json:"sids"`
	SidStructure     sidStructureView     `json:"sidStructure"`
}

// endpointBehaviorView omits Flags and Algorithm for End.X SIDs, which carry only the behavior.
type endpointBehaviorView struct {
	Behavior  uint16 `json:"behavior"`
	Name      string `json:"name"` // table.BehaviorToString
	Flags     *uint8 `json:"flags,omitempty"`
	Algorithm *uint8 `json:"algorithm,omitempty"`
}

type sidStructureView struct {
	LocalBlock uint8 `json:"localBlock"`
	LocalNode  uint8 `json:"localNode"`
	LocalFunc  uint8 `json:"localFunc"`
	LocalArg   uint8 `json:"localArg"`
}

// newTEDNodeViews derives CLI/JSON views from a TED in router ID order
// for deterministic output.
func newTEDNodeViews(nodes map[string]*table.LsNode) []tedNodeView {
	routerIDs := make([]string, 0, len(nodes))
	for routerID := range nodes {
		routerIDs = append(routerIDs, routerID)
	}
	slices.Sort(routerIDs)

	views := make([]tedNodeView, 0, len(routerIDs))
	for _, routerID := range routerIDs {
		if node := nodes[routerID]; node != nil {
			views = append(views, newTEDNodeView(node))
		}
	}
	return views
}

func newTEDNodeView(node *table.LsNode) tedNodeView {
	return tedNodeView{
		ASN:        node.ASN,
		RouterID:   node.RouterID,
		Hostname:   node.Hostname,
		IsisAreaID: node.IsisAreaID,
		Srgb:       srgbView{Begin: node.SrgbBegin, End: node.SrgbEnd},
		Prefixes:   newTEDPrefixViews(node.Prefixes),
		Links:      newTEDLinkViews(node.Links),
		SRv6SIDs:   newTEDSrv6SIDViews(node.SRv6SIDs),
	}
}

func newTEDPrefixViews(prefixes []*table.LsPrefix) []tedPrefixView {
	views := make([]tedPrefixView, 0, len(prefixes))
	for _, p := range prefixes {
		if p == nil {
			continue
		}
		v := tedPrefixView{Prefix: p.Prefix.String()}
		if p.HasPrefixSID() {
			sidIndex := p.SidIndex
			v.SidIndex = &sidIndex
		}
		views = append(views, v)
	}
	return views
}

func newTEDLinkViews(links []*table.LsLink) []tedLinkView {
	views := make([]tedLinkView, 0, len(links))
	for _, l := range links {
		if l == nil {
			continue
		}
		views = append(views, newTEDLinkView(l))
	}
	return views
}

func newTEDLinkView(l *table.LsLink) tedLinkView {
	v := tedLinkView{
		Metrics: newTEDMetricViews(l.Metrics),
		AdjSid:  l.AdjSid,
	}
	if l.LocalIP.IsValid() {
		v.LocalIP = l.LocalIP.String()
	}
	if l.RemoteIP.IsValid() {
		v.RemoteIP = l.RemoteIP.String()
	}
	if l.RemoteNode != nil {
		v.RemoteRouterID = l.RemoteNode.RouterID
	}
	if l.Srv6EndXSID != nil {
		sid := newTEDSrv6EndXSIDView(l.Srv6EndXSID)
		v.Srv6EndXSID = &sid
	}
	return v
}

func newTEDMetricViews(metrics []*table.Metric) []tedMetricView {
	views := make([]tedMetricView, 0, len(metrics))
	for _, m := range metrics {
		if m == nil {
			continue
		}
		views = append(views, tedMetricView{Type: m.Type.DisplayString(), Value: m.Value})
	}
	return views
}

func newTEDSrv6SIDViews(sids []*table.LsSrv6SID) []tedSrv6SIDView {
	views := make([]tedSrv6SIDView, 0, len(sids))
	for _, s := range sids {
		if s == nil {
			continue
		}
		views = append(views, tedSrv6SIDView{
			Sids:             s.Sids,
			EndpointBehavior: endpointBehaviorViewFrom(s.EndpointBehavior),
			SidStructure:     sidStructureViewFrom(s.SIDStructure),
			MultiTopoIDs:     s.MultiTopoIDs,
		})
	}
	return views
}

func newTEDSrv6EndXSIDView(s *table.Srv6EndXSID) tedSrv6EndXSIDView {
	return tedSrv6EndXSIDView{
		EndpointBehavior: endpointBehaviorViewFromBehavior(s.EndpointBehavior),
		Sids:             s.Sids,
		SidStructure:     sidStructureViewFrom(s.Srv6SIDStructure),
	}
}

func endpointBehaviorViewFrom(eb table.EndpointBehavior) endpointBehaviorView {
	flags := eb.Flags
	algorithm := eb.Algorithm
	return endpointBehaviorView{
		Behavior:  eb.Behavior,
		Name:      table.BehaviorToString(eb.Behavior),
		Flags:     &flags,
		Algorithm: &algorithm,
	}
}

func endpointBehaviorViewFromBehavior(behavior uint16) endpointBehaviorView {
	return endpointBehaviorView{
		Behavior: behavior,
		Name:     table.BehaviorToString(behavior),
	}
}

func sidStructureViewFrom(s table.SIDStructure) sidStructureView {
	return sidStructureView{
		LocalBlock: s.LocalBlock,
		LocalNode:  s.LocalNode,
		LocalFunc:  s.LocalFunc,
		LocalArg:   s.LocalArg,
	}
}
