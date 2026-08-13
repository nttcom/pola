// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package table

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func newTestSegmentSRMPLS(sid uint32, local, remote string) SegmentSRMPLS {
	seg := NewSegmentSRMPLS(sid)
	if local != "" {
		seg.LocalAddr = netip.MustParseAddr(local)
	}
	if remote != "" {
		seg.RemoteAddr = netip.MustParseAddr(remote)
	}
	return seg
}

func newTestSegmentSRv6(sid, local, remote string) SegmentSRv6 {
	seg := NewSegmentSRv6(netip.MustParseAddr(sid))
	if local != "" {
		seg.LocalAddr = netip.MustParseAddr(local)
	}
	if remote != "" {
		seg.RemoteAddr = netip.MustParseAddr(remote)
	}
	return seg
}

func TestSegmentsEqual(t *testing.T) {
	tests := []struct {
		name string
		a    Segment
		b    Segment
		want bool
	}{
		{
			name: "SR-MPLS same label",
			a:    newTestSegmentSRMPLS(16001, "", ""),
			b:    newTestSegmentSRMPLS(16001, "", ""),
			want: true,
		},
		{
			// Same label with a different NAI is still the same hop.
			name: "SR-MPLS same label with different NAI",
			a:    newTestSegmentSRMPLS(16001, "10.0.0.1", ""),
			b:    newTestSegmentSRMPLS(16001, "10.0.0.2", "10.0.0.3"),
			want: true,
		},
		{
			name: "SR-MPLS different label",
			a:    newTestSegmentSRMPLS(16001, "10.0.0.1", ""),
			b:    newTestSegmentSRMPLS(16002, "10.0.0.1", ""),
			want: false,
		},
		{
			name: "SRv6 same SID and NAI",
			a:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			b:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			want: true,
		},
		{
			name: "SRv6 same SID with different NAI",
			a:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			b:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::2", ""),
			want: false,
		},
		{
			name: "different segment types",
			a:    newTestSegmentSRMPLS(16001, "", ""),
			b:    newTestSegmentSRv6("fc00:0:1::", "2001:db8::1", ""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, SegmentsEqual(tt.a, tt.b))
		})
	}
}
