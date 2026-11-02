```
go get github.com/thelemail/go-crypto
```

short version:  
ProtonMail/go-crypto fork that drops legacy algorithms and uses Go stdlib cryptography.

long version:  
An OpenPGP library for Go (RFC 9580, RFC 9980), forked from [ProtonMail/go-crypto v1.5.2](https://github.com/ProtonMail/go-crypto/releases/tag/v1.5.2). It uses the Go standard library for cryptography, with `golang.org/x/crypto/argon2` as the only external dependency.

This is not a drop-in replacement for `golang.org/x/crypto/openpgp` or ProtonMail's `openpgp`: legacy algorithms and unauthenticated messages are removed.

What's supported:
- v4 and v6 keys
- RSA, ECDSA (P-256, P-384, P-521), EdDSA (legacy), Ed25519
- ECDH (P-256, P-384, P-521, Curve25519 legacy), X25519
- ML-KEM-768 + X25519, ML-DSA-65 + Ed25519
- AES-128, AES-192, AES-256
- SEIPD v2 (OCB, EAX, GCM) and SEIPD v1
- Argon2, iterated and salted, salted S2K
- SHA-2, SHA3-256, SHA3-512

BSD-3-Clause, same as upstream. See LICENSE.