// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// RefKind classifies the document defining a PCEP code point.
type RefKind uint8

// Reference kinds.
const (
	RefKindUnknown RefKind = iota
	RefKindRFC
	RefKindDraft
	RefKindVendor
	// RefKindNotIANAAssigned is used for code points without an IANA assignment,
	// typically for legacy PCC interoperability.
	RefKindNotIANAAssigned
)

// String returns a machine-readable slug for the reference kind.
func (k RefKind) String() string {
	switch k {
	case RefKindRFC:
		return "rfc"
	case RefKindDraft:
		return "draft"
	case RefKindVendor:
		return "vendor-specific"
	case RefKindNotIANAAssigned:
		return "not-iana-assigned"
	default:
		return "unknown"
	}
}

// Reference identifies the document defining a PCEP code point. Its kind is
// fixed at construction rather than inferred from the name. The zero value
// represents an unregistered code point.
type Reference struct {
	kind RefKind
	name string // document name, empty when there is no document
	base string // draft name without its revision suffix
	num  uint16 // RFC number, or draft revision
}

// rfc returns a reference to an RFC.
func rfc(n uint16) Reference {
	return Reference{kind: RefKindRFC, name: "RFC" + strconv.Itoa(int(n)), num: n}
}

// draft returns a reference to an Internet-Draft revision.
func draft(base string, rev uint16) Reference {
	return Reference{
		kind: RefKindDraft,
		name: fmt.Sprintf("%s-%02d", base, rev),
		base: base,
		num:  rev,
	}
}

// Internet-Drafts referenced by this package. Update revisions here only.
var (
	refDraftPCESRBidirPath            = draft("draft-ietf-pce-sr-bidir-path", 25)
	refDraftPCEMultipath              = draft("draft-ietf-pce-multipath", 7)
	refDraftPCESegmentRoutingPolicyCP = draft("draft-ietf-pce-segment-routing-policy-cp", 14)
	refDraftPCESRP2MPPolicy           = draft("draft-ietf-pce-sr-p2mp-policy", 11)
	refDraftPCECircuitStyle           = draft("draft-ietf-pce-circuit-style-pcep-extensions", 16)
)

var refNotIANAAssigned = Reference{kind: RefKindNotIANAAssigned}

// Kind returns the reference kind.
func (r Reference) Kind() RefKind { return r.kind }

// Name returns the document name.
func (r Reference) Name() string { return r.name }

// HasDocument reports whether the reference names an IETF document.
func (r Reference) HasDocument() bool {
	return r.kind == RefKindRFC || r.kind == RefKindDraft
}

// RFCNumber returns the RFC number and whether the reference is an RFC.
func (r Reference) RFCNumber() (uint16, bool) {
	if r.kind != RefKindRFC {
		return 0, false
	}

	return r.num, true
}

// Draft returns the draft name without its revision suffix and the revision.
func (r Reference) Draft() (base string, rev uint16, ok bool) {
	if r.kind != RefKindDraft {
		return "", 0, false
	}

	return r.base, r.num, true
}

// URL returns the canonical location of the referenced document, or "" if none.
// URLs are derived rather than stored.
func (r Reference) URL() string {
	switch r.kind {
	case RefKindRFC:
		return "https://www.rfc-editor.org/rfc/rfc" + strconv.Itoa(int(r.num)) + ".html"
	case RefKindDraft:
		return "https://datatracker.ietf.org/doc/html/" + r.name
	default:
		return ""
	}
}

// String returns a human-readable form of the reference.
func (r Reference) String() string {
	if r.name != "" {
		return r.name
	}

	switch r.kind {
	case RefKindVendor:
		return "vendor-specific"
	case RefKindNotIANAAssigned:
		return "not IANA-assigned"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes the reference as a JSON object.
func (r Reference) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind string `json:"kind"`
		Name string `json:"name,omitempty"`
		URL  string `json:"url,omitempty"`
	}{
		Kind: r.kind.String(),
		Name: r.name,
		URL:  r.URL(),
	})
}

// withReference appends a reference unless the code point is unregistered.
func withReference(s string, r Reference) string {
	if r.kind == RefKindUnknown {
		return s
	}

	return s + " [" + r.String() + "]"
}

// codePointInfo is a registry entry. Its zero value represents an unregistered
// code point, so lookups need no presence check.
type codePointInfo struct {
	Description string
	Reference   Reference
}
