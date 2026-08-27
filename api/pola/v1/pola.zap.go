// Copyright (c) 2022 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package v1

import (
	"net/netip"

	"go.uber.org/zap/zapcore"
)

// MarshalLogObject implements zapcore.ObjectMarshaler for SRPolicy.
func (x *SRPolicy) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	// Convert IP address slices to netip.Addr
	peerAddr, _ := netip.AddrFromSlice(x.GetPeerAddr())
	enc.AddString("PeerAddr", peerAddr.String())
	srcAddr, _ := netip.AddrFromSlice(x.GetSrcAddr())
	enc.AddString("SrcAddr", srcAddr.String())
	dstAddr, _ := netip.AddrFromSlice(x.GetDstAddr())
	enc.AddString("DstAddr", dstAddr.String())
	if srcRouterID := x.GetSrcRouterId(); srcRouterID != "" {
		enc.AddString("SrcRouterID", srcRouterID)
	}
	if dstRouterID := x.DstRouterId; dstRouterID != "" {
		enc.AddString("DstRouterID", dstRouterID)
	}
	enc.AddUint32("Color", x.GetColor())
	enc.AddUint32("Preference", x.GetPreference())
	enc.AddString("PolicyName", x.GetPolicyName())
	enc.AddString("Type", x.GetType().String())

	if x.GetType() == SRPolicyType_SR_POLICY_TYPE_EXPLICIT {
		if err := enc.AddReflected("SegmentList", x.GetSegmentList()); err != nil {
			return err
		}
	} else if x.GetType() == SRPolicyType_SR_POLICY_TYPE_DYNAMIC {
		enc.AddString("Metric", x.Metric.String())
	}
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for Segment.
func (x *Segment) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("SID", x.GetSid())
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for Capability.
func (x *Capability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("Type", x.GetType().String())
	switch detail := x.GetDetail().(type) {
	case *Capability_Stateful:
		return enc.AddObject("Stateful", detail.Stateful)
	case *Capability_Sr:
		return enc.AddObject("Sr", detail.Sr)
	case *Capability_Srv6:
		return enc.AddObject("Srv6", detail.Srv6)
	case *Capability_PathSetupType:
		return enc.AddObject("PathSetupType", detail.PathSetupType)
	case *Capability_AssocTypeList:
		return enc.AddObject("AssocTypeList", detail.AssocTypeList)
	case *Capability_LspDbVersion:
		return enc.AddObject("LspDbVersion", detail.LspDbVersion)
	case *Capability_Multipath:
		return enc.AddObject("Multipath", detail.Multipath)
	case *Capability_VendorInformation:
		return enc.AddObject("VendorInformation", detail.VendorInformation)
	case *Capability_Unknown:
		return enc.AddObject("Unknown", detail.Unknown)
	}
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for StatefulCapability.
func (x *StatefulCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("LspUpdate", x.GetLspUpdate())
	enc.AddBool("IncludeDbVersion", x.GetIncludeDbVersion())
	enc.AddBool("LspInstantiation", x.GetLspInstantiation())
	enc.AddBool("TriggeredResync", x.GetTriggeredResync())
	enc.AddBool("DeltaLspSync", x.GetDeltaLspSync())
	enc.AddBool("TriggeredInitialSync", x.GetTriggeredInitialSync())
	enc.AddBool("Color", x.GetColor())
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for SrCapability.
func (x *SrCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("UnlimitedMsd", x.GetUnlimitedMsd())
	enc.AddBool("NaiSupported", x.GetNaiSupported())
	if x.Msd != nil {
		enc.AddUint32("Msd", x.GetMsd())
	}
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for Srv6Capability.
func (x *Srv6Capability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("NaiSupported", x.GetNaiSupported())
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for PathSetupTypeCapability.
func (x *PathSetupTypeCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if err := enc.AddReflected("PathSetupTypes", x.GetPathSetupTypes()); err != nil {
		return err
	}
	if subCapabilities := x.GetSubCapabilities(); len(subCapabilities) > 0 {
		return enc.AddArray("SubCapabilities", zapcore.ArrayMarshalerFunc(func(ae zapcore.ArrayEncoder) error {
			for _, subCapability := range subCapabilities {
				if err := ae.AppendObject(subCapability); err != nil {
					return err
				}
			}
			return nil
		}))
	}
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for AssocTypeListCapability.
func (x *AssocTypeListCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return enc.AddReflected("AssocTypes", x.GetAssocTypes())
}

// MarshalLogObject implements zapcore.ObjectMarshaler for LspDbVersionCapability.
func (x *LspDbVersionCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint64("VersionNumber", x.GetVersionNumber())
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for MultipathCapability.
func (x *MultipathCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint32("MaxMultipaths", x.GetMaxMultipaths())
	enc.AddBool("Weighted", x.GetWeighted())
	enc.AddBool("OppositeDir", x.GetOppositeDir())
	enc.AddBool("ForwardClass", x.GetForwardClass())
	enc.AddBool("CompositePath", x.GetCompositePath())
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for VendorInformationCapability.
func (x *VendorInformationCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint32("EnterpriseNumber", x.GetEnterpriseNumber())
	return nil
}

// MarshalLogObject implements zapcore.ObjectMarshaler for UnknownCapability.
func (x *UnknownCapability) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddUint32("TlvType", x.GetTlvType())
	return nil
}
