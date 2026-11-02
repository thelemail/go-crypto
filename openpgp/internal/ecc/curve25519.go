// Package ecc implements a generic interface for ECDH, ECDSA, and EdDSA.
package ecc

import (
	"crypto/ecdh"
	"crypto/subtle"
	"io"

	"github.com/thelemail/go-crypto/openpgp/errors"
)

const curve25519Size = 32

type curve25519 struct{}

func NewCurve25519() *curve25519 {
	return &curve25519{}
}

func (c *curve25519) GetCurveName() string {
	return "curve25519"
}

// MarshalBytePoint encodes the public point from native format, adding the prefix.
// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-06#section-5.5.5.6
func (c *curve25519) MarshalBytePoint(point []byte) []byte {
	return append([]byte{0x40}, point...)
}

// UnmarshalBytePoint decodes the public point to native format, removing the prefix.
// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-06#section-5.5.5.6
func (c *curve25519) UnmarshalBytePoint(point []byte) []byte {
	if len(point) != curve25519Size+1 {
		return nil
	}

	// Remove prefix
	return point[1:]
}

// MarshalByteSecret encodes the secret scalar from native format.
// Note that the EC secret scalar differs from the definition of public keys in
// [Curve25519] in two ways: (1) the byte-ordering is big-endian, which is
// more uniform with how big integers are represented in OpenPGP, and (2) the
// leading zeros are truncated.
// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-06#section-5.5.5.6.1.1
// Note that leading zero bytes are stripped later when encoding as an MPI.
func (c *curve25519) MarshalByteSecret(secret []byte) []byte {
	d := make([]byte, curve25519Size)
	copyReversed(d, secret)

	// The following ensures that the private key is a number of the form
	// 2^{254} + 8 * [0, 2^{251}), in order to avoid the small subgroup of
	// the curve.
	//
	// This masking is done internally in the underlying lib and so is unnecessary
	// for security, but OpenPGP implementations require that private keys be
	// pre-masked.
	d[0] &= 127
	d[0] |= 64
	d[31] &= 248

	return d
}

// UnmarshalByteSecret decodes the secret scalar from native format.
// Note that the EC secret scalar differs from the definition of public keys in
// [Curve25519] in two ways: (1) the byte-ordering is big-endian, which is
// more uniform with how big integers are represented in OpenPGP, and (2) the
// leading zeros are truncated.
// See https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh-06#section-5.5.5.6.1.1
func (c *curve25519) UnmarshalByteSecret(d []byte) []byte {
	if len(d) > curve25519Size {
		return nil
	}

	// Ensure truncated leading bytes are re-added
	secret := make([]byte, curve25519Size)
	copyReversed(secret, d)

	return secret
}

// generateKeyPairBytes Generates a private-public key-pair.
// 'priv' is a private key; a little-endian scalar belonging to the set
// 2^{254} + 8 * [0, 2^{251}), in order to avoid the small subgroup of the
// curve. 'pub' is simply 'priv' * G where G is the base point.
// See https://cr.yp.to/ecdh.html and RFC7748, sec 5.
func (c *curve25519) generateKeyPairBytes(rand io.Reader) ([]byte, []byte, error) {
	priv := make([]byte, curve25519Size)
	if _, err := io.ReadFull(rand, priv); err != nil {
		return nil, nil, err
	}

	key, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	return priv, key.PublicKey().Bytes(), nil
}

func (c *curve25519) GenerateECDH(rand io.Reader) ([]byte, []byte, error) {
	priv, pub, err := c.generateKeyPairBytes(rand)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, nil
}

func (c *genericCurve) MaskSecret(secret []byte) []byte {
	return secret
}

func x25519Shared(secret, point []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		return nil, err
	}

	pub, err := ecdh.X25519().NewPublicKey(point)
	if err != nil {
		return nil, err
	}

	return priv.ECDH(pub)
}

func (c *curve25519) Encaps(rand io.Reader, point []byte) ([]byte, []byte, error) {
	// RFC6637 §8: "Generate an ephemeral key pair {v, V=vG}"
	// ephemeralPrivate corresponds to `v`.
	// ephemeralPublic corresponds to `V`.
	ephemeralPrivate, ephemeralPublic, err := c.generateKeyPairBytes(rand)
	if err != nil {
		return nil, nil, err
	}

	// RFC6637 §8: "Compute the shared point S = vR"
	//	"VB = convert point V to the octet string"
	// sharedPoint corresponds to `VB`.
	sharedPoint, err := x25519Shared(ephemeralPrivate, point)
	if err != nil {
		return nil, nil, errors.KeyInvalidError("ecc: the public key is a low order point")
	}

	return ephemeralPublic, sharedPoint, nil
}

func (c *curve25519) Decaps(vsG, secret []byte) ([]byte, error) {
	// RFC6637 §8: "Note that the recipient obtains the shared secret by calculating
	//   S = rV = rvG, where (r,R) is the recipient's key pair."
	// sharedPoint corresponds to `S`.
	sharedPoint, err := x25519Shared(secret, vsG)
	if err != nil {
		return nil, errors.KeyInvalidError("ecc: the public key is a low order point")
	}

	return sharedPoint, nil
}

func (c *curve25519) ValidateECDH(point []byte, secret []byte) error {
	sk, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		return errors.KeyInvalidError("ecc: invalid curve25519 secret")
	}

	if subtle.ConstantTimeCompare(point, sk.PublicKey().Bytes()) == 0 {
		return errors.KeyInvalidError("ecc: invalid curve25519 public point")
	}

	return nil
}

func copyReversed(out []byte, in []byte) {
	l := len(in)
	for i := 0; i < l; i++ {
		out[i] = in[l-i-1]
	}
}
