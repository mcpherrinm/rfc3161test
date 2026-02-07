package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tsa.key")
	certPath := filepath.Join(dir, "tsa.crt")

	err := generate(keyPath, certPath, defaultKeySize)
	if err != nil {
		t.Fatal(err)
	}

	key := loadTestKey(t, keyPath)
	cert := loadTestCert(t, certPath)

	if cert.Subject.CommonName != "RFC 3161 Test TSA" {
		t.Fatalf("subject CN = %q, want %q", cert.Subject.CommonName, "RFC 3161 Test TSA")
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("certificate should have digital signature key usage")
	}

	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("key and certificate public key mismatch")
	}
}

func TestGenerateKeySize(t *testing.T) {
	t.Parallel()

	// CSBR §6.1.5.2 requires at least 3072-bit RSA keys for Timestamp Authority certificates.
	if defaultKeySize < 3072 {
		t.Fatalf("default key size = %d, want >= 3072 per CSBR §6.1.5.2", defaultKeySize)
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tsa.key")
	certPath := filepath.Join(dir, "tsa.crt")

	err := generate(keyPath, certPath, defaultKeySize)
	if err != nil {
		t.Fatal(err)
	}

	key := loadTestKey(t, keyPath)
	if key.N.BitLen() < 3072 {
		t.Fatalf("key size = %d bits, want >= 3072 per CSBR §6.1.5.2", key.N.BitLen())
	}
}

func TestGenerateTimestampEKU(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tsa.key")
	certPath := filepath.Join(dir, "tsa.crt")

	err := generate(keyPath, certPath, defaultKeySize)
	if err != nil {
		t.Fatal(err)
	}

	cert := loadTestCert(t, certPath)

	// CSBR §7.1.2.3(f) requires id-kp-timeStamping EKU marked critical.
	if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageTimeStamping) {
		t.Fatal("certificate should have id-kp-timeStamping EKU per CSBR §7.1.2.3(f)")
	}
}

func TestGenerateValidity(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tsa.key")
	certPath := filepath.Join(dir, "tsa.crt")

	err := generate(keyPath, certPath, defaultKeySize)
	if err != nil {
		t.Fatal(err)
	}

	cert := loadTestCert(t, certPath)

	// CSBR §6.3.2 requires timestamp certificate validity <= 135 months.
	validity := cert.NotAfter.Sub(cert.NotBefore)
	maxValidity := 135 * 30 * 24 * time.Hour

	if validity > maxValidity+24*time.Hour {
		t.Fatalf("certificate validity = %v, want <= ~135 months per CSBR §6.3.2", validity)
	}
}

func loadTestKey(t *testing.T, path string) *rsa.PrivateKey {
	t.Helper()

	keyPEM, err := os.ReadFile(path) //nolint:gosec // test helper with test-controlled path
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("expected RSA PRIVATE KEY PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func loadTestCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	certPEM, err := os.ReadFile(path) //nolint:gosec // test helper with test-controlled path
	if err != nil {
		t.Fatal(err)
	}

	cBlock, _ := pem.Decode(certPEM)
	if cBlock == nil || cBlock.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM block")
	}

	cert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func TestGenerateExistingFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "tsa.key")
	certPath := filepath.Join(dir, "tsa.crt")

	err := os.WriteFile(keyPath, []byte("existing"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	err = generate(keyPath, certPath, defaultKeySize)
	if err == nil {
		t.Fatal("expected error when key file already exists")
	}
}
