// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"bytes"
	"crypto/elliptic"

	"github.com/thelemail/go-crypto/openpgp/internal/encoding"
)

const Curve25519GenName = "Curve25519"

type CurveInfo struct {
	GenName string
	Oid     *encoding.OID
	Curve   Curve
}

var Curves = []CurveInfo{
	{
		// NIST P-256
		GenName: "P256",
		Oid:     encoding.NewOID([]byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}),
		Curve:   NewGenericCurve(elliptic.P256()),
	},
	{
		// NIST P-384
		GenName: "P384",
		Oid:     encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x22}),
		Curve:   NewGenericCurve(elliptic.P384()),
	},
	{
		// NIST P-521
		GenName: "P521",
		Oid:     encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x23}),
		Curve:   NewGenericCurve(elliptic.P521()),
	},
	{
		// Curve25519
		GenName: Curve25519GenName,
		Oid:     encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}),
		Curve:   NewCurve25519(),
	},
	{
		// x448
		GenName: "Curve448",
		Oid:     encoding.NewOID([]byte{0x2B, 0x65, 0x6F}),
		Curve:   NewX448(),
	},
	{
		// Ed25519
		GenName: Curve25519GenName,
		Oid:     encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}),
		Curve:   NewEd25519(),
	},
	{
		// Ed448
		GenName: "Curve448",
		Oid:     encoding.NewOID([]byte{0x2B, 0x65, 0x71}),
		Curve:   NewEd448(),
	},
}

func FindByCurve(curve Curve) *CurveInfo {
	for _, curveInfo := range Curves {
		if curveInfo.Curve.GetCurveName() == curve.GetCurveName() {
			return &curveInfo
		}
	}
	return nil
}

func FindByOid(oid encoding.Field) *CurveInfo {
	var rawBytes = oid.Bytes()
	for _, curveInfo := range Curves {
		if bytes.Equal(curveInfo.Oid.Bytes(), rawBytes) {
			return &curveInfo
		}
	}
	return nil
}

func FindEdDSAByGenName(curveGenName string) EdDSACurve {
	for _, curveInfo := range Curves {
		if curveInfo.GenName == curveGenName {
			curve, ok := curveInfo.Curve.(EdDSACurve)
			if ok {
				return curve
			}
		}
	}
	return nil
}

func FindECDSAByGenName(curveGenName string) ECDSACurve {
	for _, curveInfo := range Curves {
		if curveInfo.GenName == curveGenName {
			curve, ok := curveInfo.Curve.(ECDSACurve)
			if ok {
				return curve
			}
		}
	}
	return nil
}

func FindECDHByGenName(curveGenName string) ECDHCurve {
	for _, curveInfo := range Curves {
		if curveInfo.GenName == curveGenName {
			curve, ok := curveInfo.Curve.(ECDHCurve)
			if ok {
				return curve
			}
		}
	}
	return nil
}
