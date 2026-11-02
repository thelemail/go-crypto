// Package ecdsa implements ECDSA signature, suitable for OpenPGP,
// as specified in RFC 6637, section 5.
package ecdsa

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/thelemail/go-crypto/openpgp/internal/ecc"
)

func TestCurves(t *testing.T) {
	for _, curve := range ecc.Curves {
		ECDSACurve, ok := curve.Curve.(ecc.ECDSACurve)
		if !ok {
			continue
		}

		t.Run(ECDSACurve.GetCurveName(), func(t *testing.T) {
			testFingerprint := make([]byte, 20)
			_, err := io.ReadFull(rand.Reader, testFingerprint[:])
			if err != nil {
				t.Fatal(err)
			}

			priv := testGenerate(t, ECDSACurve)
			testSignVerify(t, priv)
			testValidation(t, priv)

			// Needs fresh key
			priv = testGenerate(t, ECDSACurve)
			testMarshalUnmarshal(t, priv)
		})
	}
}

func testGenerate(t *testing.T, curve ecc.ECDSACurve) *PrivateKey {
	priv, err := GenerateKey(rand.Reader, curve)
	if err != nil {
		t.Fatal(err)
	}

	return priv
}

func testSignVerify(t *testing.T, priv *PrivateKey) {
	digest := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	r, s, err := Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Errorf("error signing: %s", err)
	}

	result := Verify(&priv.PublicKey, digest, r, s)

	if !result {
		t.Error("unable to verify message")
	}
}

func testValidation(t *testing.T, priv *PrivateKey) {
	if err := Validate(priv); err != nil {
		t.Fatalf("valid key marked as invalid: %s", err)
	}

	priv.Point[5] ^= 1
	if err := Validate(priv); err == nil {
		t.Fatal("failed to detect invalid key")
	}
}

func testMarshalUnmarshal(t *testing.T, priv *PrivateKey) {
	p := priv.MarshalPoint()
	d := priv.MarshalByteSecret()

	parsed := NewPrivateKey(*NewPublicKey(priv.GetCurve()))

	if err := parsed.UnmarshalPoint(p); err != nil {
		t.Fatalf("unable to unmarshal point: %s", err)
	}

	if err := parsed.UnmarshalByteSecret(d); err != nil {
		t.Fatalf("unable to unmarshal integer: %s", err)
	}

	if !bytes.Equal(priv.Point, parsed.Point) || !bytes.Equal(priv.D, parsed.D) {
		t.Fatal("failed to marshal/unmarshal correctly")
	}
}

func TestShortSecretNIST(t *testing.T) {
	for _, curve := range ecc.Curves {
		ecdsaCurve, ok := curve.Curve.(ecc.ECDSACurve)
		if !ok {
			continue
		}

		t.Run(ecdsaCurve.GetCurveName(), func(t *testing.T) {
			var priv *PrivateKey
			for i := 0; i < 4096; i++ {
				priv = testGenerate(t, ecdsaCurve)
				if priv.D[0] == 0 {
					break
				}
			}
			if priv.D[0] != 0 {
				t.Fatal("no key with a leading zero byte found")
			}

			full := priv.D
			priv.D = full[1:]
			if err := Validate(priv); err != nil {
				t.Fatalf("short secret rejected: %s", err)
			}
			testSignVerify(t, priv)

			priv.D = append([]byte{0}, full...)
			if err := Validate(priv); err == nil {
				t.Fatal("oversized secret accepted")
			}
		})
	}
}
