// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"io"
	"math/big"
)

type Curve interface {
	GetCurveName() string
}

type ECDSACurve interface {
	Curve
	MarshalBytePoint([]byte) []byte
	UnmarshalBytePoint([]byte) []byte
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	GenerateECDSA(rand io.Reader) ([]byte, []byte, error)
	Sign(rand io.Reader, secret, hash []byte) (*big.Int, *big.Int, error)
	Verify(point, hash []byte, r, s *big.Int) bool
	ValidatePoint(point []byte) error
	ValidateECDSA(point, secret []byte) error
}

type EdDSACurve interface {
	Curve
	MarshalBytePoint(x []byte) []byte
	UnmarshalBytePoint([]byte) (x []byte)
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	MarshalSignature(sig []byte) (r, s []byte)
	UnmarshalSignature(r, s []byte) (sig []byte)
	GenerateEdDSA(rand io.Reader) (pub, priv []byte, err error)
	Sign(publicKey, privateKey, message []byte) (sig []byte, err error)
	Verify(publicKey, message, sig []byte) bool
	ValidateEdDSA(publicKey, privateKey []byte) (err error)
}
type ECDHCurve interface {
	Curve
	MarshalBytePoint([]byte) (encoded []byte)
	UnmarshalBytePoint(encoded []byte) []byte
	MarshalByteSecret(d []byte) []byte
	UnmarshalByteSecret(d []byte) []byte
	GenerateECDH(rand io.Reader) (point []byte, secret []byte, err error)
	Encaps(rand io.Reader, point []byte) (ephemeral, sharedSecret []byte, err error)
	Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error)
	ValidateECDH(public []byte, secret []byte) error
}
