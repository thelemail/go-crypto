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

func (c *genericCurve) MarshalIntegerPoint(x, y *big.Int) []byte {
	return elliptic.Marshal(c.Curve, x, y)
}

func (c *genericCurve) UnmarshalIntegerPoint(point []byte) (x, y *big.Int) {
	return elliptic.Unmarshal(c.Curve, point)
}

func (c *genericCurve) MarshalByteSecret(d []byte) []byte {
	return d
}

func (c *genericCurve) UnmarshalByteSecret(d []byte) []byte {
	return d
}

func (c *genericCurve) MarshalIntegerSecret(d *big.Int) []byte {
	return d.Bytes()
}

func (c *genericCurve) UnmarshalIntegerSecret(d []byte) *big.Int {
	return new(big.Int).SetBytes(d)
}

func (c *genericCurve) MarshalFieldInteger(i *big.Int) (b []byte) {
	b = make([]byte, (c.Curve.Params().BitSize+7)/8)
	return i.FillBytes(b)
}

func (c *genericCurve) UnmarshalFieldInteger(d []byte) *big.Int {
	return new(big.Int).SetBytes(d)
}

func (c *genericCurve) GenerateECDH(rand io.Reader) (point, secret []byte, err error) {
	priv, err := c.ecdh.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}

	return priv.PublicKey().Bytes(), priv.Bytes(), nil
}

func (c *genericCurve) GenerateECDSA(rand io.Reader) (x, y, secret *big.Int, err error) {
	priv, err := ecdsa.GenerateKey(c.Curve, rand)
	if err != nil {
		return
	}

	return priv.X, priv.Y, priv.D, nil
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

func (c *genericCurve) Sign(rand io.Reader, x, y, d *big.Int, hash []byte) (r, s *big.Int, err error) {
	priv := &ecdsa.PrivateKey{D: d, PublicKey: ecdsa.PublicKey{X: x, Y: y, Curve: c.Curve}}
	return ecdsa.Sign(rand, priv, hash)
}

func (c *genericCurve) Verify(x, y *big.Int, hash []byte, r, s *big.Int) bool {
	pub := &ecdsa.PublicKey{X: x, Y: y, Curve: c.Curve}
	return ecdsa.Verify(pub, hash, r, s)
}

func (c *genericCurve) validate(xP, yP *big.Int, secret []byte) error {
	// the public point should not be at infinity (0,0)
	zero := new(big.Int)
	if xP.Cmp(zero) == 0 && yP.Cmp(zero) == 0 {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): infinity point", c.Curve.Params().Name))
	}

	// re-derive the public point Q' = (X,Y) = dG
	// to compare to declared Q in public key
	expectedX, expectedY := c.Curve.ScalarBaseMult(secret)
	if xP.Cmp(expectedX) != 0 || yP.Cmp(expectedY) != 0 {
		return errors.KeyInvalidError(fmt.Sprintf("ecc (%s): invalid point", c.Curve.Params().Name))
	}

	return nil
}

func (c *genericCurve) ValidateECDSA(xP, yP *big.Int, secret []byte) error {
	return c.validate(xP, yP, secret)
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
