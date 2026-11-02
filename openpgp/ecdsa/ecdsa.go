// Package ecdsa implements ECDSA signature, suitable for OpenPGP,
// as specified in RFC 6637, section 5.
package ecdsa

import (
	"errors"
	"io"
	"math/big"

	"github.com/thelemail/go-crypto/openpgp/internal/ecc"
)

type PublicKey struct {
	Point []byte
	curve ecc.ECDSACurve
}

type PrivateKey struct {
	PublicKey
	D []byte
}

func NewPublicKey(curve ecc.ECDSACurve) *PublicKey {
	return &PublicKey{
		curve: curve,
	}
}

func NewPrivateKey(key PublicKey) *PrivateKey {
	return &PrivateKey{
		PublicKey: key,
	}
}

func (pk *PublicKey) GetCurve() ecc.ECDSACurve {
	return pk.curve
}

func (pk *PublicKey) MarshalPoint() []byte {
	return pk.curve.MarshalBytePoint(pk.Point)
}

func (pk *PublicKey) UnmarshalPoint(p []byte) error {
	if err := pk.curve.ValidatePoint(p); err != nil {
		return err
	}
	pk.Point = pk.curve.UnmarshalBytePoint(p)
	return nil
}

func (sk *PrivateKey) MarshalByteSecret() []byte {
	return sk.curve.MarshalByteSecret(sk.D)
}

func (sk *PrivateKey) UnmarshalByteSecret(d []byte) error {
	sk.D = sk.curve.UnmarshalByteSecret(d)

	if sk.D == nil {
		return errors.New("ecdsa: failed to parse scalar")
	}
	return nil
}

func GenerateKey(rand io.Reader, c ecc.ECDSACurve) (priv *PrivateKey, err error) {
	priv = new(PrivateKey)
	priv.PublicKey.curve = c
	priv.PublicKey.Point, priv.D, err = c.GenerateECDSA(rand)
	return
}

func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	return priv.PublicKey.curve.Sign(rand, priv.D, hash)
}

func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	return pub.curve.Verify(pub.Point, hash, r, s)
}

func Validate(priv *PrivateKey) error {
	return priv.curve.ValidateECDSA(priv.Point, priv.D)
}
