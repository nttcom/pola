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

func TestAddressFamily_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		af   AddressFamily
		want string
	}{
		{"IPv4", AFIPv4, "ipv4"},
		{"IPv6", AFIPv6, "ipv6"},
		{"unspecified", AFUnspecified, "unspecified"},
		{"unknown value", AddressFamily(99), "unspecified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.af.String())
		})
	}
}

func TestAddressFamilySet_Has(t *testing.T) {
	t.Parallel()

	s := AddressFamilySetIPv4 | AddressFamilySetIPv6

	tests := []struct {
		name string
		s    AddressFamilySet
		af   AddressFamily
		want bool
	}{
		{"set with IPv4 bit has IPv4", s, AFIPv4, true},
		{"set with IPv6 bit has IPv6", s, AFIPv6, true},
		{"empty set does not have IPv4", AddressFamilySet(0), AFIPv4, false},
		{"empty set does not have IPv6", AddressFamilySet(0), AFIPv6, false},
		{"unspecified family is never a member", s, AFUnspecified, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.s.Has(tt.af))
		})
	}
}

func TestDataPlane_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		dp   DataPlane
		want string
	}{
		{"SR-MPLS", DPSRMPLS, "sr-mpls"},
		{"SRv6", DPSRv6, "srv6"},
		{"unspecified", DPUnspecified, "unspecified"},
		{"unknown value", DataPlane(99), "unspecified"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.dp.String())
		})
	}
}

func TestPlane_Validate(t *testing.T) {
	t.Parallel()

	families := []AddressFamily{AFUnspecified, AFIPv4, AFIPv6}
	dataPlanes := []DataPlane{DPUnspecified, DPSRMPLS, DPSRv6}

	for _, af := range families {
		for _, dp := range dataPlanes {
			p := Plane{Family: af, DataPlane: dp}
			wantErr := af == AFUnspecified || dp == DPUnspecified || (af == AFIPv4 && dp == DPSRv6)

			err := p.Validate()
			if wantErr {
				assert.Errorf(t, err, "Plane{%v, %v} should be invalid", af, dp)
			} else {
				assert.NoErrorf(t, err, "Plane{%v, %v} should be valid", af, dp)
			}
		}
	}
}

func TestFamilyOfAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want AddressFamily
	}{
		{"plain IPv4", "192.0.2.1", AFIPv4},
		{"IPv4-mapped IPv6", "::ffff:192.0.2.1", AFIPv4},
		{"ordinary IPv6", "2001:db8::1", AFIPv6},
		{"link-local IPv6", "fe80::1", AFIPv6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, FamilyOfAddr(netip.MustParseAddr(tt.addr)))
		})
	}

	t.Run("invalid address is unspecified", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, AFUnspecified, FamilyOfAddr(netip.Addr{}))
	})
}
