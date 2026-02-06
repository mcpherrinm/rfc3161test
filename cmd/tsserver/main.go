// Command tsserver is the RFC 3161 Time-Stamp Authority server.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/mcpherrinm/rfc3161test/server"
	"github.com/mcpherrinm/rfc3161test/tsp"
)

var errNoPEMBlock = errors.New("no PEM block found")

func main() {
	addr := flag.String("addr", ":3161", "listen address")
	keyFile := flag.String("key", "", "path to PEM-encoded RSA private key")
	certFile := flag.String("cert", "", "path to PEM-encoded certificate")

	flag.Parse()

	if *keyFile == "" || *certFile == "" {
		fmt.Fprintln(os.Stderr, "both -key and -cert flags are required")
		os.Exit(1)
	}

	key, err := loadKey(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load key: %v\n", err)
		os.Exit(1)
	}

	cert, err := loadCert(*certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load cert: %v\n", err)
		os.Exit(1)
	}

	signer := &tsp.Signer{Key: key, Certificate: cert}

	fmt.Fprintf(os.Stderr, "listening on %s\n", *addr)

	err = http.ListenAndServe(*addr, server.Handler(signer)) //nolint:gosec // test server
	if err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

func loadKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is expected
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key %s: %w", path, errNoPEMBlock)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return key, nil
}

func loadCert(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-provided path is expected
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("cert %s: %w", path, errNoPEMBlock)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}
