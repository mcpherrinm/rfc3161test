// Command tsakeygen generates an RSA private key and self-signed certificate for use with tsserver.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	defaultKeySize = 2048
	serialBitLen   = 128
	certDuration   = 365 * 24 * time.Hour
	keyFileMode    = 0o600
	certFileMode   = 0o644
)

func main() {
	keyFile := flag.String("key", "tsa.key", "output path for PEM-encoded RSA private key")
	certFile := flag.String("cert", "tsa.crt", "output path for PEM-encoded certificate")
	keySize := flag.Int("bits", defaultKeySize, "RSA key size in bits")

	flag.Parse()

	err := generate(*keyFile, *certFile, *keySize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tsakeygen: %v\n", err)
		os.Exit(1)
	}
}

func generate(keyPath, certPath string, bits int) error {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), serialBitLen)

	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()

	tmpl := &x509.Certificate{ //nolint:exhaustruct // only setting relevant fields
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "RFC 3161 Test TSA"}, //nolint:exhaustruct // only CN needed
		NotBefore:             now,
		NotAfter:              now.Add(certDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	err = writeKey(keyPath, key)
	if err != nil {
		return err
	}

	err = writeCert(certPath, certDER)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %s and %s\n", keyPath, certPath)

	return nil
}

func writeKey(path string, key *rsa.PrivateKey) error {
	//nolint:gosec // user-provided path is expected
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, keyFileMode)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer file.Close() //nolint:errcheck // best-effort close after write

	err = pem.Encode(file, &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
}

func writeCert(path string, certDER []byte) error {
	//nolint:gosec // user-provided path; cert is not secret
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, certFileMode)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer file.Close() //nolint:errcheck // best-effort close after write

	err = pem.Encode(file, &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   certDER,
	})
	if err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	return nil
}
