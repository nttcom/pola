// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"errors"
	"fmt"
	"net/netip"
)

// EndpointSpec identifies how the policy endpoints are specified (RFC 9256 §2.1).
// Address and router-ID forms are mutually exclusive.
type EndpointSpec struct {
	Headend          netip.Addr
	Endpoint         netip.Addr
	HeadendRouterID  string
	EndpointRouterID string
	Family           AddressFamily
}

// UsesRouterID reports whether s names its endpoints by router ID.
func (s EndpointSpec) UsesRouterID() bool {
	return s.HeadendRouterID != "" || s.EndpointRouterID != ""
}

// Resolve returns the policy endpoints as addresses.
// Explicit address-family selections must be supported by both endpoints;
// otherwise, the unique common loopback family is used.
func (s EndpointSpec) Resolve(ted *LsTED, underlayFamily AddressFamily) (headend, endpoint netip.Addr, err error) {
	usesAddr := s.Headend.IsValid() || s.Endpoint.IsValid()
	usesRouterID := s.UsesRouterID()

	switch {
	case usesAddr && usesRouterID:
		return netip.Addr{}, netip.Addr{}, errors.New("headend/endpoint and headendRouterID/endpointRouterID are mutually exclusive")
	case usesAddr:
		if s.Family.IsValid() {
			return netip.Addr{}, netip.Addr{}, errors.New("endpointFamily is valid only with the headendRouterID/endpointRouterID form")
		}

		if !s.Headend.IsValid() || !s.Endpoint.IsValid() {
			return netip.Addr{}, netip.Addr{}, errors.New("both headend and endpoint must be set")
		}

		return s.Headend, s.Endpoint, nil
	case usesRouterID:
		if s.HeadendRouterID == "" || s.EndpointRouterID == "" {
			return netip.Addr{}, netip.Addr{}, errors.New("both headendRouterID and endpointRouterID must be set")
		}

		return s.resolveViaTED(ted, underlayFamily)
	default:
		return netip.Addr{}, netip.Addr{}, errors.New("either headend/endpoint or headendRouterID/endpointRouterID must be set")
	}
}

func (s EndpointSpec) resolveViaTED(ted *LsTED, underlayFamily AddressFamily) (headend, endpoint netip.Addr, err error) {
	if ted == nil {
		return netip.Addr{}, netip.Addr{}, errors.New("ted is nil")
	}

	headendNode, ok := ted.Nodes[s.HeadendRouterID]
	if !ok || headendNode == nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("no node with router ID %s", s.HeadendRouterID)
	}

	endpointNode, ok := ted.Nodes[s.EndpointRouterID]
	if !ok || endpointNode == nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("no node with router ID %s", s.EndpointRouterID)
	}

	family, err := s.resolveFamily(headendNode, endpointNode, underlayFamily)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}

	headend, err = headendNode.LoopbackAddr(family)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("headend %s: %w", s.HeadendRouterID, err)
	}

	endpoint, err = endpointNode.LoopbackAddr(family)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("endpoint %s: %w", s.EndpointRouterID, err)
	}

	return headend, endpoint, nil
}

func (s EndpointSpec) resolveFamily(headendNode, endpointNode *LsNode, underlayFamily AddressFamily) (AddressFamily, error) {
	if s.Family.IsValid() {
		return s.Family, nil
	}

	if underlayFamily.IsValid() {
		if headendNode.HasLoopback(underlayFamily) && endpointNode.HasLoopback(underlayFamily) {
			return underlayFamily, nil
		}

		return AFUnspecified, fmt.Errorf("underlay family %v has no loopback on headend %s and/or endpoint %s; specify endpointFamily", underlayFamily, s.HeadendRouterID, s.EndpointRouterID)
	}

	var candidates []AddressFamily

	for _, af := range []AddressFamily{AFIPv4, AFIPv6} {
		if headendNode.HasLoopback(af) && endpointNode.HasLoopback(af) {
			candidates = append(candidates, af)
		}
	}

	switch len(candidates) {
	case 0:
		return AFUnspecified, fmt.Errorf("headend %s and endpoint %s share no common loopback address family; specify endpointFamily", s.HeadendRouterID, s.EndpointRouterID)
	case 1:
		return candidates[0], nil
	default:
		return AFUnspecified, fmt.Errorf("headend %s and endpoint %s share multiple loopback address families %v; specify endpointFamily", s.HeadendRouterID, s.EndpointRouterID, candidates)
	}
}
