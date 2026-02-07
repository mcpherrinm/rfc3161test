package tsp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
)

func mustMarshalRequest(t *testing.T, req TimeStampReq) []byte {
	t.Helper()

	der, err := MarshalRequest(&req)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func validRequest(t *testing.T) TimeStampReq {
	t.Helper()

	hash := sha256.Sum256([]byte("test data"))

	return TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: OIDSHA256,
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}
}

func TestParseValidRequest(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	der := mustMarshalRequest(t, req)

	parsed, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Version != 1 {
		t.Fatalf("version = %d, want 1", parsed.Version)
	}

	if !parsed.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDSHA256) {
		t.Fatal("wrong hash algorithm")
	}
}

func TestParseRequestWithNonce(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.Nonce = big.NewInt(12345)

	der := mustMarshalRequest(t, req)

	parsed, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Nonce == nil {
		t.Fatal("nonce should be present")
	}

	if parsed.Nonce.Cmp(big.NewInt(12345)) != 0 {
		t.Fatalf("nonce = %v, want 12345", parsed.Nonce)
	}
}

func TestParseRequestWithPolicy(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.ReqPolicy = OIDDefaultPolicy

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestWithCertReq(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.CertReq = true

	der := mustMarshalRequest(t, req)

	parsed, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if !parsed.CertReq {
		t.Fatal("certReq should be true")
	}
}

func TestParseRequestSHA384(t *testing.T) {
	t.Parallel()

	hash := sha512.Sum384([]byte("test data"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: OIDSHA384,
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestSHA512(t *testing.T) {
	t.Parallel()

	hash := sha512.Sum512([]byte("test data"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: OIDSHA512,
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestWrongVersion(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.Version = 2

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureBadDataFormat)
	}
}

func TestParseRequestBadAlg(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("test"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureBadAlg {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureBadAlg)
	}
}

func TestParseRequestHashLengthMismatch(t *testing.T) {
	t.Parallel()

	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: OIDSHA256,
			},
			HashedMessage: []byte("short"),
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for hash length mismatch")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureBadDataFormat)
	}
}

func TestParseRequestUnacceptedPolicy(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.ReqPolicy = asn1.ObjectIdentifier{1, 2, 3, 4, 99}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unaccepted policy")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureUnacceptedPolicy {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureUnacceptedPolicy)
	}
}

func TestParseRequestUnacceptedExtension(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.Extensions = []Extension{{
		ID:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		Critical: false,
		Value:    []byte{0x01},
	}}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unaccepted extension")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureUnacceptedExtension {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureUnacceptedExtension)
	}
}

func TestParseRequestTrailingData(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	der := mustMarshalRequest(t, req)
	der = append(der, 0x00)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestParseRequestInvalidDER(t *testing.T) {
	t.Parallel()

	_, err := ParseRequest([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureBadDataFormat)
	}
}

func TestParseRequestSHA1Rejected(t *testing.T) {
	t.Parallel()

	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm: OIDSHA1,
			},
			HashedMessage: make([]byte, 20), // SHA-1 produces 20 bytes
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for SHA-1 algorithm")
	}

	var reqErr *RequestError
	if !errors.As(err, &reqErr) {
		t.Fatal("expected RequestError")
	}

	if reqErr.FailureInfo != FailureBadAlg {
		t.Fatalf("failureInfo = %d, want %d", reqErr.FailureInfo, FailureBadAlg)
	}
}

func TestParseRequestEmpty(t *testing.T) {
	t.Parallel()

	_, err := ParseRequest(nil)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
