// Copyright (c) 2026 Quantova Inc
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

// Package attestation produces a post quantum attestation over a byte payload
// such as an exported controller state or a policy manifest. It uses FIPS 204
// ML-DSA so a reader can confirm the payload is authentic and has not been
// altered, with a signature scheme that stays safe once large quantum
// computers exist.
package attestation

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Scheme is the FIPS 204 signature scheme used for attestations.
const Scheme = "ML-DSA-65"

// Issuer names the party that builds the attestation.
const Issuer = "Quantova"

// Attestation is a self contained post quantum attestation over a payload. It
// carries the public key and the signature, so a verifier needs only the
// attestation and the payload.
type Attestation struct {
	Scheme        string `json:"scheme"`
	Issuer        string `json:"issuer"`
	PayloadSHA256 string `json:"payload_sha256"`
	PublicKey     string `json:"public_key"`
	Signature     string `json:"signature"`
}

// GenerateKeypair returns a fresh (publicKey, secretKey) pair.
func GenerateKeypair() (publicKey, secretKey []byte, err error) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ML-DSA-65 key: %w", err)
	}

	var packedPublic [mldsa65.PublicKeySize]byte

	pk.Pack(&packedPublic)

	var packedSecret [mldsa65.PrivateKeySize]byte

	sk.Pack(&packedSecret)

	return bytes.Clone(packedPublic[:]), bytes.Clone(packedSecret[:]), nil
}

// Build returns a self contained attestation over payload.
func Build(payload, publicKey, secretKey []byte) (*Attestation, error) {
	var sk mldsa65.PrivateKey

	if err := sk.UnmarshalBinary(secretKey); err != nil {
		return nil, fmt.Errorf("parse secret key: %w", err)
	}

	signature := make([]byte, mldsa65.SignatureSize)

	if err := mldsa65.SignTo(&sk, payload, nil, false, signature); err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}

	digest := sha256.Sum256(payload)

	return &Attestation{
		Scheme:        Scheme,
		Issuer:        Issuer,
		PayloadSHA256: hex.EncodeToString(digest[:]),
		PublicKey:     base64.StdEncoding.EncodeToString(publicKey),
		Signature:     base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// Verify reports whether a matches payload. When expectedPublicKey is not nil
// the signer is pinned too, so a valid signature made under a different key is
// rejected.
func Verify(payload []byte, a *Attestation, expectedPublicKey []byte) bool {
	digest := sha256.Sum256(payload)
	if a.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return false
	}

	publicKey, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil {
		return false
	}

	signature, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return false
	}

	if expectedPublicKey != nil && !bytes.Equal(publicKey, expectedPublicKey) {
		return false
	}

	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(publicKey); err != nil {
		return false
	}

	return mldsa65.Verify(&pk, payload, nil, signature)
}

type signerFile struct {
	Scheme    string `json:"scheme"`
	PublicKey string `json:"public_key"`
	SecretKey string `json:"secret_key"`
}

// SaveSigner writes a signer key file that LoadSigner reads back.
func SaveSigner(path string, publicKey, secretKey []byte) error {
	data, err := json.Marshal(signerFile{
		Scheme:    Scheme,
		PublicKey: base64.StdEncoding.EncodeToString(publicKey),
		SecretKey: base64.StdEncoding.EncodeToString(secretKey),
	})
	if err != nil {
		return fmt.Errorf("encode signer: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write signer: %w", err)
	}

	return nil
}

// LoadSigner reads (publicKey, secretKey) from a signer key file.
func LoadSigner(path string) (publicKey, secretKey []byte, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is provided by the operator.
	if err != nil {
		return nil, nil, fmt.Errorf("read signer: %w", err)
	}

	var f signerFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, nil, fmt.Errorf("decode signer: %w", err)
	}

	publicKey, err = base64.StdEncoding.DecodeString(f.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode public key: %w", err)
	}

	secretKey, err = base64.StdEncoding.DecodeString(f.SecretKey)
	if err != nil {
		return nil, nil, fmt.Errorf("decode secret key: %w", err)
	}

	return publicKey, secretKey, nil
}
