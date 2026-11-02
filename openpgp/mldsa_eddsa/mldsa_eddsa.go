// Package mldsa_eddsa implements hybrid ML-DSA + EdDSA encryption for OpenPGP,
// according to https://www.rfc-editor.org/rfc/rfc9980.html#name-composite-signature-schemes.
package mldsa_eddsa

import (
	"crypto/mldsa"
	goerrors "errors"
	"io"

	"github.com/thelemail/go-crypto/openpgp/errors"
	"github.com/thelemail/go-crypto/openpgp/internal/ecc"
)

const (
	MlDsaSeedLen = mldsa.PrivateKeySize
)

type PublicKey struct {
	AlgId       uint8
	Curve       ecc.EdDSACurve
	PublicPoint []byte
	PublicMldsa *mldsa.PublicKey
}

type PrivateKey struct {
	PublicKey
	SecretEc        []byte
	SecretMldsa     *mldsa.PrivateKey
	SecretMldsaSeed []byte
}

// GenerateKey generates a ML-DSA + EdDSA composite key as specified in
// https://www.rfc-editor.org/rfc/rfc9980.html#name-key-generation-procedure-2
func GenerateKey(rand io.Reader, algId uint8, c ecc.EdDSACurve) (*PrivateKey, error) {
	priv := new(PrivateKey)

	priv.PublicKey.AlgId = algId
	priv.PublicKey.Curve = c

	var err error
	priv.PublicKey.PublicPoint, priv.SecretEc, err = c.GenerateEdDSA(rand)
	if err != nil {
		return nil, err
	}

	keySeed := make([]byte, MlDsaSeedLen)
	if _, err = rand.Read(keySeed); err != nil {
		return nil, err
	}

	if err := priv.DeriveMlDsaKeys(keySeed, true); err != nil {
		return nil, err
	}
	return priv, nil
}

// DeriveMlDsaKeys derives the ML-DSA keys from the provided seed and stores them inside priv.
func (priv *PrivateKey) DeriveMlDsaKeys(seed []byte, overridePublicKey bool) error {
	if len(seed) != MlDsaSeedLen {
		return goerrors.New("mldsa_eddsa: ml-dsa secret seed has the wrong length")
	}

	privateKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return err
	}

	priv.SecretMldsaSeed = seed
	if overridePublicKey {
		priv.PublicKey.PublicMldsa = privateKey.PublicKey()
	}

	priv.SecretMldsa = privateKey

	return nil
}

// Sign generates a ML-DSA + EdDSA composite signature as specified in
// https://www.rfc-editor.org/rfc/rfc9980.html#name-signature-generation
func Sign(priv *PrivateKey, message []byte) ([]byte, []byte, error) {
	ecSig, err := priv.PublicKey.Curve.Sign(priv.PublicKey.PublicPoint, priv.SecretEc, message)
	if err != nil {
		return nil, nil, err
	}

	mldsaSig, err := priv.SecretMldsa.Sign(nil, message, nil)
	if err != nil {
		return nil, nil, err
	}

	return mldsaSig, ecSig, nil
}

// Verify verifies a ML-DSA + EdDSA composite signature as specified in
// https://www.rfc-editor.org/rfc/rfc9980.html#name-signature-verification
func Verify(pub *PublicKey, message, dSig, ecSig []byte) bool {
	return pub.Curve.Verify(pub.PublicPoint, message, ecSig) &&
		mldsa.Verify(pub.PublicMldsa, message, dSig, nil) == nil
}

// Validate checks that the public key corresponds to the private key
func Validate(priv *PrivateKey) (err error) {
	if err = priv.PublicKey.Curve.ValidateEdDSA(priv.PublicKey.PublicPoint, priv.SecretEc); err != nil {
		return err
	}

	if !priv.PublicMldsa.Equal(priv.SecretMldsa.PublicKey()) {
		return errors.KeyInvalidError("mldsa_eddsa: invalid public key")
	}

	return nil
}
