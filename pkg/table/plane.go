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

// AddressFamily identifies an IP address family.
// AFUnspecified is never valid where a concrete family is required.
type AddressFamily uint8

const (
	// AFUnspecified means no address family was specified.
	AFUnspecified AddressFamily = iota
	// AFIPv4 means IPv4.
	AFIPv4
	// AFIPv6 means IPv6.
	AFIPv6
)

// IsValid reports whether af is a concrete address family.
func (af AddressFamily) IsValid() bool {
	switch af {
	case AFIPv4, AFIPv6:
		return true
	default:
		return false
	}
}

// String returns the lowercase name of af.
func (af AddressFamily) String() string {
	switch af {
	case AFIPv4:
		return "ipv4"
	case AFIPv6:
		return "ipv6"
	default:
		return "unspecified"
	}
}

// AddressFamilySet is a bitset of AddressFamily values.
// Bit 0 is IPv4; bit 1 is IPv6.
type AddressFamilySet uint8

const (
	// AddressFamilySetIPv4 is the IPv4 bit.
	AddressFamilySetIPv4 AddressFamilySet = 1 << iota
	// AddressFamilySetIPv6 is the IPv6 bit.
	AddressFamilySetIPv6
)

// Has reports whether af is a member of s.
func (s AddressFamilySet) Has(af AddressFamily) bool {
	switch af {
	case AFIPv4:
		return s&AddressFamilySetIPv4 != 0
	case AFIPv6:
		return s&AddressFamilySetIPv6 != 0
	default:
		return false
	}
}

// DataPlane identifies a forwarding plane.
// DPUnspecified must be resolved explicitly where a concrete plane is required.
type DataPlane uint8

const (
	// DPUnspecified means no data plane was specified.
	DPUnspecified DataPlane = iota
	// DPSRMPLS means SR-MPLS.
	DPSRMPLS
	// DPSRv6 means SRv6.
	DPSRv6
)

// String returns the lowercase name of dp.
func (dp DataPlane) String() string {
	switch dp {
	case DPSRMPLS:
		return "sr-mpls"
	case DPSRv6:
		return "srv6"
	default:
		return "unspecified"
	}
}

// Plane pairs an address family with a data plane.
// It is the unit of scope used by the TED, CSPF, and SR abstractions.
type Plane struct {
	Family    AddressFamily
	DataPlane DataPlane
}

// Validate reports an error for an unspecified or unsupported plane combination.
// SRv6 requires IPv6.
func (p Plane) Validate() error {
	if !p.Family.IsValid() {
		return errors.New("address family must be specified")
	}

	switch p.DataPlane {
	case DPSRMPLS:
		return nil
	case DPSRv6:
		if p.Family != AFIPv6 {
			return fmt.Errorf("SRv6 requires IPv6, got %s", p.Family)
		}

		return nil
	default:
		return errors.New("data plane must be specified")
	}
}

// FamilyOfAddr returns the address family of addr.
// IPv4-mapped IPv6 addresses are normalized to AFIPv4.
func FamilyOfAddr(addr netip.Addr) AddressFamily {
	if !addr.IsValid() {
		return AFUnspecified
	}

	addr = addr.Unmap()

	switch {
	case addr.Is4():
		return AFIPv4
	case addr.Is6():
		return AFIPv6
	default:
		return AFUnspecified
	}
}
