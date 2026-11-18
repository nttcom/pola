// Copyright (c) 2026 Quantova Inc
//
// This software is released under the MIT License.
// see https://github.com/nttcom/pola/blob/main/LICENSE

package attestation_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/nttcom/pola/pkg/attestation"
)

var payload = []byte(`{"policy":"sr-001","color":100,"preference":10}`)

func mustKeypair(t *testing.T) (publicKey, secretKey []byte) {
	t.Helper()

	publicKey, secretKey, err := attestation.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	return publicKey, secretKey
}

func TestBuildAndVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)

	a, err := attestation.Build(payload, publicKey, secretKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if a.Scheme != attestation.Scheme || a.Issuer != attestation.Issuer {
		t.Fatalf("header mismatch: %+v", a)
	}

	if !attestation.Verify(payload, a, nil) {
		t.Fatal("Verify returned false for a valid attestation")
	}

	if !attestation.Verify(payload, a, publicKey) {
		t.Fatal("Verify with a pinned public key returned false")
	}
}

func TestTamperedPayloadIsRejected(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)

	a, err := attestation.Build(payload, publicKey, secretKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if attestation.Verify([]byte(`{"policy":"sr-002"}`), a, nil) {
		t.Fatal("Verify accepted a tampered payload")
	}
}

func TestWrongSignerIsRejectedWhenPinned(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)
	otherPublicKey, _ := mustKeypair(t)

	a, err := attestation.Build(payload, publicKey, secretKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if attestation.Verify(payload, a, otherPublicKey) {
		t.Fatal("Verify accepted an attestation under a different pinned key")
	}
}

func TestForgedSignatureIsRejected(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)

	a, err := attestation.Build(payload, publicKey, secretKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	a.Signature = base64.StdEncoding.EncodeToString(make([]byte, mldsa65.SignatureSize))
	if attestation.Verify(payload, a, nil) {
		t.Fatal("Verify accepted a forged signature")
	}
}

func TestVerifyRejectsMalformedFields(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)

	a, err := attestation.Build(payload, publicKey, secretKey)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	bad := *a
	bad.PublicKey = "!!!not base64!!!"

	if attestation.Verify(payload, &bad, nil) {
		t.Fatal("Verify accepted a non base64 public key")
	}

	bad = *a
	bad.Signature = "!!!not base64!!!"

	if attestation.Verify(payload, &bad, nil) {
		t.Fatal("Verify accepted a non base64 signature")
	}

	bad = *a
	bad.PublicKey = base64.StdEncoding.EncodeToString([]byte("short"))

	if attestation.Verify(payload, &bad, nil) {
		t.Fatal("Verify accepted a public key of the wrong length")
	}
}

func TestBuildRejectsBadSecretKey(t *testing.T) {
	t.Parallel()

	publicKey, _ := mustKeypair(t)

	if _, err := attestation.Build(payload, publicKey, []byte("short")); err == nil {
		t.Fatal("Build accepted a malformed secret key")
	}
}

func TestSignerFileRoundtrip(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)
	path := filepath.Join(t.TempDir(), "signer.json")

	if err := attestation.SaveSigner(path, publicKey, secretKey); err != nil {
		t.Fatalf("SaveSigner: %v", err)
	}

	loadedPublic, loadedSecret, err := attestation.LoadSigner(path)
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}

	a, err := attestation.Build(payload, loadedPublic, loadedSecret)
	if err != nil {
		t.Fatalf("Build with loaded signer: %v", err)
	}

	if !attestation.Verify(payload, a, publicKey) {
		t.Fatal("attestation from a loaded signer did not verify")
	}
}

func TestSaveSignerBadPath(t *testing.T) {
	t.Parallel()

	publicKey, secretKey := mustKeypair(t)
	path := filepath.Join(t.TempDir(), "no-such-dir", "signer.json")

	if err := attestation.SaveSigner(path, publicKey, secretKey); err == nil {
		t.Fatal("SaveSigner accepted an unwritable path")
	}
}

func TestLoadSignerErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if _, _, err := attestation.LoadSigner(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("LoadSigner accepted a missing file")
	}

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := attestation.LoadSigner(badJSON); err == nil {
		t.Fatal("LoadSigner accepted invalid json")
	}

	badB64 := filepath.Join(dir, "badb64.json")
	if err := os.WriteFile(badB64, []byte(`{"public_key":"!!!","secret_key":"!!!"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := attestation.LoadSigner(badB64); err == nil {
		t.Fatal("LoadSigner accepted a non base64 key")
	}
}
