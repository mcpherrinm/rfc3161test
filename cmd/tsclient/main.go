// Command tsclient is a CLI tool for requesting RFC 3161 timestamps.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"flag"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/mcpherrinm/rfc3161test/tsp"
)

const nonceBytes = 16

var (
	errUnsupportedAlg     = errors.New("unsupported hash algorithm")
	errUnexpectedStatus   = errors.New("unexpected HTTP status")
	errUnexpectedContent  = errors.New("unexpected content type")
)

func main() {
	serverURL := flag.String("server", "http://localhost:3161", "timestamp server URL")
	filePath := flag.String("file", "", "file to timestamp")
	hashAlg := flag.String("hash", "sha256", "hash algorithm (sha256, sha384, sha512)")

	flag.Parse()

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "-file flag is required")
		os.Exit(1)
	}

	digest, oid, err := hashFile(*filePath, *hashAlg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash file: %v\n", err)
		os.Exit(1)
	}

	reqDER, nonce, err := buildRequest(digest, oid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request: %v\n", err)
		os.Exit(1)
	}

	respDER, err := postRequest(*serverURL, reqDER)
	if err != nil {
		fmt.Fprintf(os.Stderr, "post request: %v\n", err)
		os.Exit(1)
	}

	err = printResponse(os.Stdout, respDER, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse response: %v\n", err)
		os.Exit(1)
	}
}

func hashFile(path, algorithm string) ([]byte, asn1.ObjectIdentifier, error) {
	file, err := os.Open(path) //nolint:gosec // user-provided path is expected
	if err != nil {
		return nil, nil, fmt.Errorf("open file: %w", err)
	}
	defer file.Close() //nolint:errcheck // best-effort close on read-only file

	var hasher hash.Hash

	var oid asn1.ObjectIdentifier

	switch algorithm {
	case "sha256":
		hasher = sha256.New()
		oid = tsp.OIDSHA256
	case "sha384":
		hasher = sha512.New384()
		oid = tsp.OIDSHA384
	case "sha512":
		hasher = sha512.New()
		oid = tsp.OIDSHA512
	default:
		return nil, nil, fmt.Errorf("%w: %s", errUnsupportedAlg, algorithm)
	}

	_, err = io.Copy(hasher, file)
	if err != nil {
		return nil, nil, fmt.Errorf("hash file: %w", err)
	}

	return hasher.Sum(nil), oid, nil
}

func buildRequest(
	digest []byte, oid asn1.ObjectIdentifier,
) ([]byte, *big.Int, error) {
	nonceValue := make([]byte, nonceBytes)

	_, err := rand.Read(nonceValue)
	if err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	nonce := new(big.Int).SetBytes(nonceValue)

	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm: oid,
			},
			HashedMessage: digest,
		},
		ReqPolicy:  nil,
		Nonce:      nonce,
		CertReq:    true,
		Extensions: nil,
	}

	der, err := tsp.MarshalRequest(&req)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	return der, nonce, nil
}

func postRequest(serverURL string, reqDER []byte) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		serverURL,
		bytes.NewReader(reqDER),
	)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("post request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"%w: %d", errUnexpectedStatus, resp.StatusCode,
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return body, nil
}

func printResponse(
	writer io.Writer, respDER []byte, nonce *big.Int,
) error {
	resp, err := tsp.ParseResponse(respDER)
	if err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	_, err = fmt.Fprintf(writer, "Status: %d\n", resp.Status.Status)
	if err != nil {
		return fmt.Errorf("write status: %w", err)
	}

	if resp.Status.Status != tsp.StatusGranted {
		_, err = fmt.Fprintln(writer, "Timestamp request was not granted")

		return err //nolint:wrapcheck // pass-through write error
	}

	if resp.TimeStampToken == nil || !resp.TimeStampToken.ContentType.Equal(tsp.OIDSignedData) {
		return fmt.Errorf(
			"%w", errUnexpectedContent,
		)
	}

	_, err = fmt.Fprintf(writer, "Nonce sent: %v\n", nonce)
	if err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}

	_, err = fmt.Fprintln(writer, "Timestamp token received successfully")

	return err //nolint:wrapcheck // pass-through write error
}
