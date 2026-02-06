package tsp_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/mcpherrinm/rfc3161test/tsp"
)

func mustMarshalRequest(t *testing.T, req tsp.TimeStampReq) []byte {
	t.Helper()

	der, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func validRequest(t *testing.T) tsp.TimeStampReq {
	t.Helper()

	hash := sha256.Sum256([]byte("test data"))

	return tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm:  tsp.OIDSHA256,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
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

	parsed, err := tsp.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Version != 1 {
		t.Fatalf("version = %d, want 1", parsed.Version)
	}

	if !parsed.MessageImprint.HashAlgorithm.Algorithm.Equal(tsp.OIDSHA256) {
		t.Fatal("wrong hash algorithm")
	}
}

func TestParseRequestWithNonce(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.Nonce = big.NewInt(12345)

	der := mustMarshalRequest(t, req)

	parsed, err := tsp.ParseRequest(der)
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
	req.ReqPolicy = tsp.OIDDefaultPolicy

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestWithCertReq(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.CertReq = true

	der := mustMarshalRequest(t, req)

	parsed, err := tsp.ParseRequest(der)
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
	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm:  tsp.OIDSHA384,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestSHA512(t *testing.T) {
	t.Parallel()

	hash := sha512.Sum512([]byte("test data"))
	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm:  tsp.OIDSHA512,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestWrongVersion(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.Version = 2

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}

	var re *tsp.RequestError
	if !errors.As(err, &re) {
		t.Fatal("expected RequestError")
	}

	if re.FailureInfo != tsp.FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, tsp.FailureBadDataFormat)
	}
}

func TestParseRequestBadAlg(t *testing.T) {
	t.Parallel()

	hash := sha256.Sum256([]byte("test"))
	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 3, 4, 5},
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}

	var re *tsp.RequestError
	if !errors.As(err, &re) {
		t.Fatal("expected RequestError")
	}

	if re.FailureInfo != tsp.FailureBadAlg {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, tsp.FailureBadAlg)
	}
}

func TestParseRequestHashLengthMismatch(t *testing.T) {
	t.Parallel()

	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm:  tsp.OIDSHA256,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: []byte("short"),
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for hash length mismatch")
	}

	var re *tsp.RequestError
	if !errors.As(err, &re) {
		t.Fatal("expected RequestError")
	}

	if re.FailureInfo != tsp.FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, tsp.FailureBadDataFormat)
	}
}

func TestParseRequestUnacceptedPolicy(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.ReqPolicy = asn1.ObjectIdentifier{1, 2, 3, 4, 99}

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unaccepted policy")
	}

	var re *tsp.RequestError
	if !errors.As(err, &re) {
		t.Fatal("expected RequestError")
	}

	if re.FailureInfo != tsp.FailureUnacceptedPolicy {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, tsp.FailureUnacceptedPolicy)
	}
}

func TestParseRequestUnacceptedExtension(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	req.Extensions = []tsp.Extension{{
		ID:       asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		Critical: false,
		Value:    []byte{0x01},
	}}

	der := mustMarshalRequest(t, req)

	_, err := tsp.ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unaccepted extension")
	}

	var re *tsp.RequestError
	if !errors.As(err, &re) {
		t.Fatal("expected RequestError")
	}

	if re.FailureInfo != tsp.FailureUnacceptedExtension {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, tsp.FailureUnacceptedExtension)
	}
}

func TestParseRequestTrailingData(t *testing.T) {
	t.Parallel()

	req := validRequest(t)
	der := mustMarshalRequest(t, req)
	der = append(der, 0x00)

	_, err := tsp.ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestParseRequestInvalidDER(t *testing.T) {
	t.Parallel()

	_, err := tsp.ParseRequest([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}

	var re *tsp.RequestError
	if !errors.As(err, &re) {
		t.Fatal("expected RequestError")
	}

	if re.FailureInfo != tsp.FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, tsp.FailureBadDataFormat)
	}
}

func TestParseRequestEmpty(t *testing.T) {
	t.Parallel()

	_, err := tsp.ParseRequest(nil)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
