// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/thelemail/go-crypto/openpgp/ecdsa"
	"github.com/thelemail/go-crypto/openpgp/eddsa"
	"github.com/thelemail/go-crypto/openpgp/errors"
	"github.com/thelemail/go-crypto/openpgp/internal/ecc"
	"github.com/thelemail/go-crypto/openpgp/internal/encoding"
	"github.com/thelemail/go-crypto/openpgp/s2k"
)

const maxMessageLength = 1 << 10

var privateKeyTests = []struct {
	privateKeyHex string
	creationTime  time.Time
}{
	{
		privKeyRSAHex,
		time.Unix(0x4cc349a8, 0),
	},
}

func TestExternalPrivateKeyRead(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		err = privKey.Decrypt([]byte("wrong password"))
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect key", i)
			continue
		}

		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

// En/decryption of private keys provided externally, with random passwords
func TestExternalPrivateKeyEncryptDecryptRandomizeSlow(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		// Decrypt with the correct password
		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		// Encrypt with another (possibly empty) password
		randomPassword := make([]byte, mathrand.Intn(30))
		rand.Read(randomPassword)
		err = privKey.Encrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to encrypt: %s", i, err)
			continue
		}

		// Try to decrypt with incorrect password
		incorrect := make([]byte, 1+mathrand.Intn(30))
		for rand.Read(incorrect); bytes.Equal(incorrect, randomPassword); {
			rand.Read(incorrect)
		}
		err = privKey.Decrypt(incorrect)
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect password\nPassword is:%vDecrypted with:%v", i, randomPassword, incorrect)
			continue
		}

		// Try to decrypt with old password
		err = privKey.Decrypt([]byte("testing"))
		if err == nil {
			t.Errorf("#%d: decrypted with old password", i)
			continue
		}

		// Decrypt with correct password
		err = privKey.Decrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

func TestExternalPrivateKeyEncryptDecryptS2KModes(t *testing.T) {
	sk2Modes := []s2k.Mode{s2k.IteratedSaltedS2K, s2k.Argon2S2K}
	sk2KeyTypes := []S2KType{S2KAEAD, S2KSHA1}
	for _, s2kMode := range sk2Modes {
		for _, sk2KeyType := range sk2KeyTypes {
			if s2kMode == s2k.Argon2S2K && sk2KeyType == S2KSHA1 {
				continue
			}
			t.Run(fmt.Sprintf("s2kMode:%d-s2kType:%d", s2kMode, sk2KeyType), func(t *testing.T) {
				var configAEAD *AEADConfig
				if sk2KeyType == S2KAEAD {
					configAEAD = &AEADConfig{}
				}
				config := &Config{
					S2KConfig:  &s2k.Config{S2KMode: s2kMode},
					AEADConfig: configAEAD,
				}
				for i, test := range privateKeyTests {
					packet, err := Read(readerFromHex(test.privateKeyHex))
					if err != nil {
						t.Errorf("#%d: failed to parse: %s", i, err)
						continue
					}

					privKey := packet.(*PrivateKey)

					if !privKey.Encrypted {
						t.Errorf("#%d: private key isn't encrypted", i)
						continue
					}

					// Decrypt with the correct password
					err = privKey.Decrypt([]byte("testing"))
					if err != nil {
						t.Errorf("#%d: failed to decrypt: %s", i, err)
						continue
					}

					// Encrypt with another (possibly empty) password
					randomPassword := make([]byte, mathrand.Intn(30))
					rand.Read(randomPassword)
					err = privKey.EncryptWithConfig(randomPassword, config)
					if err != nil {
						t.Errorf("#%d: failed to encrypt: %s", i, err)
						continue
					}

					// Try to decrypt with incorrect password
					incorrect := make([]byte, 1+mathrand.Intn(30))
					for rand.Read(incorrect); bytes.Equal(incorrect, randomPassword); {
						rand.Read(incorrect)
					}
					err = privKey.Decrypt(incorrect)
					if err == nil {
						t.Errorf("#%d: decrypted with incorrect password\nPassword is:%vDecrypted with:%v", i, randomPassword, incorrect)
						continue
					}

					// Try to decrypt with old password
					err = privKey.Decrypt([]byte("testing"))
					if err == nil {
						t.Errorf("#%d: decrypted with old password", i)
						continue
					}

					// Decrypt with correct password
					err = privKey.Decrypt(randomPassword)
					if err != nil {
						t.Errorf("#%d: failed to decrypt: %s", i, err)
						continue
					}

					if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
						t.Errorf("#%d: bad result, got: %#v", i, privKey)
					}
				}
			})
		}
	}
}

func populateHash(hashFunc crypto.Hash, msg []byte) (hash.Hash, error) {
	h := hashFunc.New()
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return h, nil
}

func TestExternalRSAPrivateKey(t *testing.T) {
	privKeyDER, _ := hex.DecodeString(pkcs1PrivKeyHex)
	rsaPriv, err := x509.ParsePKCS1PrivateKey(privKeyDER)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	xrsaPriv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: rsaPriv.PublicKey.E,
			N: rsaPriv.PublicKey.N,
		},
		D:      rsaPriv.D,
		Primes: rsaPriv.Primes,
	}
	xrsaPriv.Precompute()
	if err := NewRSAPrivateKey(time.Now(), xrsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}
	for j := 0; j < 256; j++ {
		msg := make([]byte, maxMessageLength)
		rand.Read(msg)

		h, err := populateHash(sig.Hash, msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Sign(h, priv, nil); err != nil {
			t.Fatal(err)
		}

		if h, err = populateHash(sig.Hash, msg); err != nil {
			t.Fatal(err)
		}
		if err := priv.VerifySignature(h, sig); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSerializeRSAPrivateKeyPrimeOrder(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Primes[1] is serialized as p and Primes[0] as q.
	if rsaPriv.Primes[0].Cmp(rsaPriv.Primes[1]) < 0 {
		rsaPriv.Primes[0], rsaPriv.Primes[1] = rsaPriv.Primes[1], rsaPriv.Primes[0]
		rsaPriv.Precomputed = rsa.PrecomputedValues{}
		rsaPriv.Precompute()
	}

	var buf bytes.Buffer
	if err := serializeRSAPrivateKey(&buf, rsaPriv); err != nil {
		t.Fatal(err)
	}

	parsed := &PrivateKey{PublicKey: *NewRSAPublicKey(time.Now(), &rsaPriv.PublicKey)}
	if err := parsed.parseRSAPrivateKey(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	parsedRSA := parsed.PrivateKey.(*rsa.PrivateKey)
	if parsedRSA.Primes[0].Cmp(rsaPriv.Primes[0]) != 0 || parsedRSA.Primes[1].Cmp(rsaPriv.Primes[1]) != 0 {
		t.Fatal("prime order not preserved across serialize/parse")
	}

	// RFC 9580 section 5.5.5.1: d, p, q (p < q), u = p^-1 mod q.
	mpis := make([]*big.Int, 4)
	for i := range mpis {
		mpi := new(encoding.MPI)
		if _, err := mpi.ReadFrom(&buf); err != nil {
			t.Fatal(err)
		}
		mpis[i] = new(big.Int).SetBytes(mpi.Bytes())
	}
	p, q, u := mpis[1], mpis[2], mpis[3]
	if p.Cmp(q) >= 0 {
		t.Fatal("expected p < q")
	}
	if new(big.Int).Mod(new(big.Int).Mul(p, u), q).Cmp(big.NewInt(1)) != 0 {
		t.Fatal("expected u = p^-1 mod q")
	}
}

func TestECDSAPrivateKeysRandomizeFast(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(rand.Reader, ecc.NewGenericCurve(elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewECDSAPrivateKey(time.Now(), ecdsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

func TestRSASignerPrivateKeysRandomizeSlow(t *testing.T) {
	// Generate random key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), rsaPriv)

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}

	// Sign random message
	msg := make([]byte, maxMessageLength)
	h, err := populateHash(sig.Hash, msg)

	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}

	// Try to verify signature with wrong key
	incorrectRsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	incorrectPriv := NewSignerPrivateKey(time.Now(), incorrectRsaPriv)
	if err = incorrectPriv.VerifySignature(h, sig); err == nil {
		t.Fatalf(
			"Verified signature with incorrect key.\nCorrect key:  \n%v\nIncorrect key:\n%v\nSignature:%v",
			priv, incorrectPriv, sig)
	}
}

func TestECDSASignerPrivateKeysRandomizeFast(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(rand.Reader, ecc.NewGenericCurve(elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), ecdsaPriv)

	if priv.PubKeyAlgo != PubKeyAlgoECDSA {
		t.Fatal("NewSignerPrivateKey should have made an ECSDA private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

func TestEdDSASignerPrivateKeyRandomizeFast(t *testing.T) {
	eddsaPriv, err := eddsa.GenerateKey(rand.Reader, ecc.NewEd25519())
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), eddsaPriv)

	if priv.PubKeyAlgo != PubKeyAlgoEdDSA {
		t.Fatal("NewSignerPrivateKey should have made a EdDSA private key")
	}

	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoEdDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, maxMessageLength)
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}
	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

// Tests correctness when encrypting an EdDSA private key with a password.
func TestEncryptDecryptEdDSAPrivateKeyRandomizeFast(t *testing.T) {
	password := make([]byte, 20)
	_, err := rand.Read(password)
	if err != nil {
		panic(err)
	}
	primaryKey, err := eddsa.GenerateKey(rand.Reader, ecc.NewEd25519())
	if err != nil {
		panic(err)
	}
	privKey := *NewEdDSAPrivateKey(time.Now(), primaryKey)

	copiedSecret := make([]byte, len(primaryKey.D))
	copy(copiedSecret, privKey.PrivateKey.(*eddsa.PrivateKey).D)

	// Encrypt private key with random passphrase
	if err := privKey.Encrypt(password); err != nil {
		t.Fatal(err)
	}
	// Decrypt and check correctness
	if err := privKey.Decrypt(password); err != nil {
		t.Fatal(err)
	}

	decryptedSecret := privKey.PrivateKey.(*eddsa.PrivateKey).D
	if !bytes.Equal(decryptedSecret, copiedSecret) {
		t.Fatalf("Private key was not correctly decrypted:\ngot:\n%v\nwant:\n%v", decryptedSecret, copiedSecret)
	}
}

func TestIssue11505(t *testing.T) {
	// parsing a rsa private key with p or q == 1 used to panic due to a divide by zero
	_, _ = Read(readerFromHex("9c3004303030300100000011303030000000000000010130303030303030303030303030303030303030303030303030303030303030303030303030303030303030"))
}

func TestECDSASignerRandomizedNotation(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(rand.Reader, ecc.NewGenericCurve(elliptic.P256()))
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), ecdsaPriv)
	sig := &Signature{
		Version:    4,
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		NonDeterministicSignaturesViaNotation: BoolPointer(true),
	}
	if err := sig.Sign(h, priv, &config); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
	if len(sig.Notations) == 0 {
		t.Fatalf("failed to find randomized notation")
	}
	if sig.Notations[0].Name != SaltNotationName {
		t.Fatalf("failed to find randomized notation")
	}
}

func privateKeyWithS2KUsage(t *testing.T, tail []byte) []byte {
	raw, err := hex.DecodeString(privKeyRSAHex)
	if err != nil {
		t.Fatal(err)
	}
	body := append(append([]byte{}, raw[3:144]...), tail...)
	var out bytes.Buffer
	if err := serializeHeader(&out, packetTypePrivateKey, len(body)); err != nil {
		t.Fatal(err)
	}
	out.Write(body)
	return out.Bytes()
}

func TestMalleableCFBPrivateKeyRejected(t *testing.T) {
	raw, err := hex.DecodeString(privKeyRSAHex)
	if err != nil {
		t.Fatal(err)
	}
	tail := append([]byte{0xff}, raw[145:]...)
	_, err = Read(bytes.NewReader(privateKeyWithS2KUsage(t, tail)))
	if _, ok := err.(errors.UnsupportedError); !ok {
		t.Fatalf("want unsupported error for s2k usage 255, got %v", err)
	}
}

func TestDummyPrivateKeyMalleableCFBUsage(t *testing.T) {
	stub := []byte{0xff, 0x00, 0x65, 0x02, 'G', 'N', 'U', 0x01}
	p, err := Read(bytes.NewReader(privateKeyWithS2KUsage(t, stub)))
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := p.(*PrivateKey)
	if !ok || !pk.Dummy() {
		t.Fatalf("want dummy private key, got %#v", p)
	}
	var out bytes.Buffer
	if err := pk.Serialize(&out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), privateKeyWithS2KUsage(t, stub)) {
		t.Fatalf("dummy key did not round-trip: %x", out.Bytes())
	}
}
