package tsp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"math/big"
	"testing"
)

func mustMarshalRequest(t *testing.T, req TimeStampReq) []byte {
	t.Helper()
	der, err := asn1.Marshal(req)
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
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256},
			HashedMessage: hash[:],
		},
	}
}

func TestParseValidRequest(t *testing.T) {
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
	req := validRequest(t)
	req.ReqPolicy = OIDDefaultPolicy
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestWithCertReq(t *testing.T) {
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
	hash := sha512.Sum384([]byte("test data"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA384},
			HashedMessage: hash[:],
		},
	}
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestSHA512(t *testing.T) {
	hash := sha512.Sum512([]byte("test data"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA512},
			HashedMessage: hash[:],
		},
	}
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRequestWrongVersion(t *testing.T) {
	req := validRequest(t)
	req.Version = 2
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
	re, ok := err.(*RequestError)
	if !ok {
		t.Fatal("expected RequestError")
	}
	if re.FailureInfo != FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, FailureBadDataFormat)
	}
}

func TestParseRequestBadAlg(t *testing.T) {
	hash := sha256.Sum256([]byte("test"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5}},
			HashedMessage: hash[:],
		},
	}
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
	re, ok := err.(*RequestError)
	if !ok {
		t.Fatal("expected RequestError")
	}
	if re.FailureInfo != FailureBadAlg {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, FailureBadAlg)
	}
}

func TestParseRequestHashLengthMismatch(t *testing.T) {
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256},
			HashedMessage: []byte("short"),
		},
	}
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for hash length mismatch")
	}
	re, ok := err.(*RequestError)
	if !ok {
		t.Fatal("expected RequestError")
	}
	if re.FailureInfo != FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, FailureBadDataFormat)
	}
}

func TestParseRequestUnacceptedPolicy(t *testing.T) {
	req := validRequest(t)
	req.ReqPolicy = asn1.ObjectIdentifier{1, 2, 3, 4, 99}
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unaccepted policy")
	}
	re, ok := err.(*RequestError)
	if !ok {
		t.Fatal("expected RequestError")
	}
	if re.FailureInfo != FailureUnacceptedPolicy {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, FailureUnacceptedPolicy)
	}
}

func TestParseRequestUnacceptedExtension(t *testing.T) {
	req := validRequest(t)
	req.Extensions = []Extension{{
		ID:    asn1.ObjectIdentifier{1, 2, 3, 4, 5},
		Value: []byte{0x01},
	}}
	der := mustMarshalRequest(t, req)
	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for unaccepted extension")
	}
	re, ok := err.(*RequestError)
	if !ok {
		t.Fatal("expected RequestError")
	}
	if re.FailureInfo != FailureUnacceptedExtension {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, FailureUnacceptedExtension)
	}
}

func TestParseRequestTrailingData(t *testing.T) {
	req := validRequest(t)
	der := mustMarshalRequest(t, req)
	der = append(der, 0x00)
	_, err := ParseRequest(der)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
}

func TestParseRequestInvalidDER(t *testing.T) {
	_, err := ParseRequest([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for invalid DER")
	}
	re, ok := err.(*RequestError)
	if !ok {
		t.Fatal("expected RequestError")
	}
	if re.FailureInfo != FailureBadDataFormat {
		t.Fatalf("failureInfo = %d, want %d", re.FailureInfo, FailureBadDataFormat)
	}
}

func TestParseRequestEmpty(t *testing.T) {
	_, err := ParseRequest(nil)
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
