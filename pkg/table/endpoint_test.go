// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nttcom/pola/pkg/table"
)

func lsNodeWithLoopbacks(routerID string, addrs ...string) *table.LsNode {
	n := &table.LsNode{RouterID: routerID}

	for _, a := range addrs {
		bits := 32
		if netip.MustParseAddr(a).Is6() {
			bits = 128
		}

		n.Prefixes = append(n.Prefixes, &table.LsPrefix{Prefix: netip.PrefixFrom(netip.MustParseAddr(a), bits)})
	}

	return n
}

func TestEndpointSpecResolve(t *testing.T) {
	t.Parallel()

	addrV4A := netip.MustParseAddr("10.0.0.1")
	addrV4B := netip.MustParseAddr("10.0.0.2")

	tests := []struct {
		name         string
		spec         table.EndpointSpec
		ted          *table.LsTED
		wantHeadend  netip.Addr
		wantEndpoint netip.Addr
		wantErr      bool
	}{
		{
			name:         "address form passes through without touching the TED",
			spec:         table.EndpointSpec{Headend: addrV4A, Endpoint: addrV4B},
			ted:          nil,
			wantHeadend:  addrV4A,
			wantEndpoint: addrV4B,
		},
		{
			name: "router ID form resolves via the unique common loopback family (IPv4)",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1"),
				lsNodeWithLoopbacks(testRouterIDB, "10.0.0.2"),
			),
			wantHeadend:  netip.MustParseAddr("10.0.0.1"),
			wantEndpoint: netip.MustParseAddr("10.0.0.2"),
		},
		{
			name: "router ID form resolves via the unique common loopback family (IPv6)",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, testSRv6SID1),
				lsNodeWithLoopbacks(testRouterIDB, testSRv6SID2),
			),
			wantHeadend:  netip.MustParseAddr(testSRv6SID1),
			wantEndpoint: netip.MustParseAddr(testSRv6SID2),
		},
		{
			name: "explicit endpointFamily picks among multiple shared loopback families",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB, Family: table.AFIPv4},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1", testSRv6SID1),
				lsNodeWithLoopbacks(testRouterIDB, "10.0.0.2", testSRv6SID2),
			),
			wantHeadend:  netip.MustParseAddr("10.0.0.1"),
			wantEndpoint: netip.MustParseAddr("10.0.0.2"),
		},
		{
			name: "endpoint family resolution is independent of the underlay plane",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1"),
				lsNodeWithLoopbacks(testRouterIDB, "10.0.0.2"),
			),
			wantHeadend:  netip.MustParseAddr("10.0.0.1"),
			wantEndpoint: netip.MustParseAddr("10.0.0.2"),
		},
		{
			name: "dual-stack nodes with no explicit family is ambiguous",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1", testSRv6SID1),
				lsNodeWithLoopbacks(testRouterIDB, "10.0.0.2", testSRv6SID2),
			),
			wantErr: true,
		},
		{
			name: "no shared address family is an error",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1"),
				lsNodeWithLoopbacks(testRouterIDB, testSRv6SID2),
			),
			wantErr: true,
		},
		{
			name:    "address form combined with endpointFamily is rejected",
			spec:    table.EndpointSpec{Headend: addrV4A, Endpoint: addrV4B, Family: table.AFIPv4},
			ted:     nil,
			wantErr: true,
		},
		{
			name:    "mixing address and router ID forms is rejected",
			spec:    table.EndpointSpec{Headend: addrV4A, HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted:     nil,
			wantErr: true,
		},
		{
			name:    "address form with only headend set is rejected",
			spec:    table.EndpointSpec{Headend: addrV4A},
			ted:     nil,
			wantErr: true,
		},
		{
			name:    "router ID form with only headendRouterID set is rejected",
			spec:    table.EndpointSpec{HeadendRouterID: testRouterIDA},
			ted:     nil,
			wantErr: true,
		},
		{
			name:    "neither form set is rejected",
			spec:    table.EndpointSpec{},
			ted:     nil,
			wantErr: true,
		},
		{
			name:    "router ID form with a nil TED is rejected",
			spec:    table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted:     nil,
			wantErr: true,
		},
		{
			name:    "unknown headend router ID is rejected",
			spec:    table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted:     newTestTED(lsNodeWithLoopbacks(testRouterIDB, "10.0.0.2")),
			wantErr: true,
		},
		{
			name: "unknown endpoint router ID is rejected",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1"),
			),
			wantErr: true,
		},
		{
			name: "explicit endpointFamily unavailable on the headend is rejected",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB, Family: table.AFIPv6},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, "10.0.0.1"),
				lsNodeWithLoopbacks(testRouterIDB, testSRv6SID2),
			),
			wantErr: true,
		},
		{
			name: "explicit endpointFamily unavailable on the endpoint is rejected",
			spec: table.EndpointSpec{HeadendRouterID: testRouterIDA, EndpointRouterID: testRouterIDB, Family: table.AFIPv6},
			ted: newTestTED(
				lsNodeWithLoopbacks(testRouterIDA, testSRv6SID1),
				lsNodeWithLoopbacks(testRouterIDB, "10.0.0.2"),
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			headend, endpoint, err := tt.spec.Resolve(tt.ted)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHeadend, headend)
			assert.Equal(t, tt.wantEndpoint, endpoint)
		})
	}
}
