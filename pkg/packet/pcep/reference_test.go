// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package pcep

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

func TestRefKind_String(t *testing.T) {
	t.Parallel()

	const wantUnknown = "unknown"

	cases := map[RefKind]string{
		RefKindRFC:             "rfc",
		RefKindDraft:           "draft",
		RefKindVendor:          "vendor-specific",
		RefKindNotIANAAssigned: "not-iana-assigned",
		RefKindUnknown:         wantUnknown,
		RefKind(0xff):          wantUnknown,
	}

	for kind, want := range cases {
		assert.Equal(t, want, kind.String())
	}
}

func TestReference_Accessors(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		ref         Reference
		wantKind    RefKind
		wantName    string
		wantString  string
		wantURL     string
		wantRFC     uint16
		wantIsRFC   bool
		wantBase    string
		wantRev     uint16
		wantIsDraft bool
	}{
		"RFC": {
			ref:        rfc(8231),
			wantKind:   RefKindRFC,
			wantName:   "RFC8231",
			wantString: "RFC8231",
			wantURL:    "https://www.rfc-editor.org/rfc/rfc8231.html",
			wantRFC:    8231,
			wantIsRFC:  true,
		},
		"Draft": {
			ref:         refDraftPCEMultipath,
			wantKind:    RefKindDraft,
			wantName:    "draft-ietf-pce-multipath-07",
			wantString:  "draft-ietf-pce-multipath-07",
			wantURL:     "https://datatracker.ietf.org/doc/html/draft-ietf-pce-multipath-07",
			wantBase:    "draft-ietf-pce-multipath",
			wantRev:     7,
			wantIsDraft: true,
		},
		"NotIANAAssigned": {
			ref:        refNotIANAAssigned,
			wantKind:   RefKindNotIANAAssigned,
			wantString: "not IANA-assigned",
		},
		"Vendor": {
			ref:        Reference{kind: RefKindVendor},
			wantKind:   RefKindVendor,
			wantString: "vendor-specific",
		},
		"Zero": {
			ref:        Reference{},
			wantKind:   RefKindUnknown,
			wantString: "unknown",
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.wantKind, tt.ref.Kind())
			assert.Equal(t, tt.wantName, tt.ref.Name())
			assert.Equal(t, tt.wantString, tt.ref.String())
			assert.Equal(t, tt.wantURL, tt.ref.URL())
			assert.Equal(t, tt.wantIsRFC || tt.wantIsDraft, tt.ref.HasDocument())

			num, isRFC := tt.ref.RFCNumber()
			assert.Equal(t, tt.wantIsRFC, isRFC)
			assert.Equal(t, tt.wantRFC, num)

			base, rev, isDraft := tt.ref.Draft()
			assert.Equal(t, tt.wantIsDraft, isDraft)
			assert.Equal(t, tt.wantBase, base)
			assert.Equal(t, tt.wantRev, rev)
		})
	}
}

func TestReference_Comparable(t *testing.T) {
	t.Parallel()

	assert.Equal(t, rfc(5440), messageTypeDescriptions[MessageTypeOpen].Reference)
	assert.NotEqual(t, rfc(5440), rfc(8231))
	assert.NotEqual(t, refDraftPCEMultipath, draft("draft-ietf-pce-multipath", 8))
}

func TestDraft_RevisionPadding(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "draft-ietf-pce-multipath-07", draft("draft-ietf-pce-multipath", 7).Name())
	assert.Equal(t, "draft-ietf-pce-multipath-12", draft("draft-ietf-pce-multipath", 12).Name())
}

func TestReference_MarshalJSON(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		ref  Reference
		want string
	}{
		"RFC":             {rfc(8231), `{"kind":"rfc","name":"RFC8231","url":"https://www.rfc-editor.org/rfc/rfc8231.html"}`},
		"Draft":           {refDraftPCEMultipath, `{"kind":"draft","name":"draft-ietf-pce-multipath-07","url":"https://datatracker.ietf.org/doc/html/draft-ietf-pce-multipath-07"}`},
		"NotIANAAssigned": {refNotIANAAssigned, `{"kind":"not-iana-assigned"}`},
		"Zero":            {Reference{}, `{"kind":"unknown"}`},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := json.Marshal(tt.ref)
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestReference_MarshalLogObject(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		ref  Reference
		want map[string]any
	}{
		"RFC": {
			ref: rfc(8231),
			want: map[string]any{
				"kind": "rfc",
				"name": "RFC8231",
				"url":  "https://www.rfc-editor.org/rfc/rfc8231.html",
			},
		},
		"NotIANAAssigned": {
			ref:  refNotIANAAssigned,
			want: map[string]any{"kind": "not-iana-assigned"},
		},
	}

	for name, tt := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			enc := zapcore.NewMapObjectEncoder()
			require.NoError(t, tt.ref.MarshalLogObject(enc))
			assert.Equal(t, tt.want, enc.Fields)
		})
	}
}

func TestWithReference(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "Open (0x01) [RFC5440]", withReference("Open (0x01)", rfc(5440)))
	assert.Equal(t, "X [not IANA-assigned]", withReference("X", refNotIANAAssigned))
	// Unregistered code points have no reference.
	assert.Equal(t, "Unknown TLV (0xdead)", withReference("Unknown TLV (0xdead)", Reference{}))
}
