// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"

	"github.com/thelemail/go-crypto/openpgp/errors"
)

type genericCurve struct {
	Curve elliptic.Curve
	ecdh  ecdh.Curve
}

func NewGenericCurve(c elliptic.Curve) *genericCurve {
	return &genericCurve{
		Curve: c,
		ecdh:  ecdhCurve(c),
	}
}

func ecdhCurve(c elliptic.Curve) ecdh.Curve {
	switch c {
	case elliptic.P256():
		return ecdh.P256()
	case elliptic.P384():
		return ecdh.P384()
	case elliptic.P521():
		return ecdh.P521()
	}
	return nil
}

func (c *genericCurve) GetCurveName() string {
	return c.Curve.Params().Name
}

func (c *genericCurve) MarshalBytePoint(point []byte) []byte {
	return point
}

func (c *genericCurve) UnmarshalBytePoint(point []byte) []byte {
	return point
}

func (c *genericCurve) MarshalByteSecret(d []byte) []byte {
	return d
}

func (c *genericCurve) UnmarshalByteSecret(d []byte) []byte {
	return d
}

func (c *genericCurve) GenerateECDH(rand io.Reader) (point, secret []byte, err error) {
	priv, err := c.ecdh.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

func (c *genericCurve) GenerateECDSA(rand io.Reader) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(c.Curve, rand)
	if err != nil {
		return nil, nil, err
	}

	point, err := priv.PublicKey.Bytes()
	if err != nil {
		return nil, nil, err
	}

	secret, err := priv.Bytes()
	if err != nil {
		return nil, nil, err
	}

	return point, secret, nil
}

func (c *genericCurve) Encaps(rand io.Reader, point []byte) (ephemeral, sharedSecret []byte, err error) {
	pub, err := c.ecdh.NewPublicKey(point)
	if err != nil {
		return nil, nil, errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point",
			c.Curve.Params().Name))
	}

	eph, err := c.ecdh.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	zb, err := eph.ECDH(pub)
	if err != nil {
		return nil, nil, err
	}

	return eph.PublicKey().Bytes(), zb, nil
}

func (c *genericCurve) Decaps(ephemeral, secret []byte) (sharedSecret []byte, err error) {
	pub, err := c.ecdh.NewPublicKey(ephemeral)
	if err != nil {
		return nil, errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point",
			c.Curve.Params().Name))
	}

	d, err := c.fixedSecret(secret)
	if err != nil {
		return nil, err
	}

	priv, err := c.ecdh.NewPrivateKey(d)
	if err != nil {
		return nil, errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid secret",
			c.Curve.Params().Name))
	}

	return priv.ECDH(pub)
}

func (c *genericCurve) Sign(rand io.Reader, secret, hash []byte) (*big.Int, *big.Int, error) {
	priv, err := c.ecdsaPrivateKey(secret)
	if err != nil {
		return nil, nil, err
	}

	return ecdsa.Sign(rand, priv, hash)
}

func (c *genericCurve) Verify(point, hash []byte, r, s *big.Int) bool {
	pub, err := ecdsa.ParseUncompressedPublicKey(c.Curve, point)
	if err != nil {
		return false
	}

	return ecdsa.Verify(pub, hash, r, s)
}

func (c *genericCurve) ValidatePoint(point []byte) error {
	if _, err := ecdsa.ParseUncompressedPublicKey(c.Curve, point); err != nil {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point",
			c.Curve.Params().Name))
	}

	return nil
}

func (c *genericCurve) ValidateECDSA(point, secret []byte) error {
	priv, err := c.ecdsaPrivateKey(secret)
	if err != nil {
		return err
	}

	pub, err := priv.PublicKey.Bytes()
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(pub, point) != 1 {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point",
			c.Curve.Params().Name))
	}

	return nil
}

func (c *genericCurve) ValidateECDH(point []byte, secret []byte) error {
	d, err := c.fixedSecret(secret)
	if err != nil {
		return err
	}

	priv, err := c.ecdh.NewPrivateKey(d)
	if err != nil {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid secret",
			c.Curve.Params().Name))
	}

	if subtle.ConstantTimeCompare(priv.PublicKey().Bytes(), point) != 1 {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point",
			c.Curve.Params().Name))
	}

	return nil
}

func (c *genericCurve) fixedSecret(d []byte) ([]byte, error) {
	size := (c.Curve.Params().BitSize + 7) / 8
	if len(d) > size {
		return nil, errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid secret",
			c.GetCurveName()))
	}

	out := make([]byte, size)
	copy(out[size-len(d):], d)
	return out, nil
}

func (c *genericCurve) ecdsaPrivateKey(secret []byte) (*ecdsa.PrivateKey, error) {
	d, err := c.fixedSecret(secret)
	if err != nil {
		return nil, err
	}

	priv, err := ecdsa.ParseRawPrivateKey(c.Curve, d)
	if err != nil {
		return nil, errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid secret",
			c.Curve.Params().Name))
	}

	return priv, nil
}
