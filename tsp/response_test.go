package tsp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

func TestFailureInfoBitString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		bit  PKIFailureInfo
	}{
		{"badAlg", FailureBadAlg},
		{"badRequest", FailureBadRequest},
		{"badDataFormat", FailureBadDataFormat},
		{"timeNotAvailable", FailureTimeNotAvailable},
		{"unacceptedPolicy", FailureUnacceptedPolicy},
		{"unacceptedExtension", FailureUnacceptedExtension},
		{"addInfoNotAvailable", FailureAddInfoNotAvailable},
		{"systemFailure", FailureSystemFailure},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			bs := FailureInfoBitString(testCase.bit)
			if bs.BitLength != int(testCase.bit)+1 {
				t.Fatalf("BitLength = %d, want %d", bs.BitLength, int(testCase.bit)+1)
			}

			if bs.At(int(testCase.bit)) != 1 {
				t.Fatal("expected bit to be set")
			}
		})
	}
}

func testSigner(t *testing.T) *Signer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{ //nolint:exhaustruct // test cert: only fields relevant for TSA
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"}, //nolint:exhaustruct // test cert
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return &Signer{Key: key, Certificate: cert}
}

func TestCreateResponseGranted(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status.Status != StatusGranted {
		t.Fatalf("status = %d, want %d", resp.Status.Status, StatusGranted)
	}

	if !resp.TimeStampToken.ContentType.Equal(OIDSignedData) {
		t.Fatal("token content type should be signedData")
	}
}

func TestCreateResponseNonceEcho(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	nonce := big.NewInt(99999)
	req.Nonce = nonce

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	tstInfo := extractTSTInfo(t, resp)
	if tstInfo.Nonce == nil || tstInfo.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce = %v, want %v", tstInfo.Nonce, nonce)
	}
}

func TestCreateResponseSerial128Bit(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	before := time.Since(signer.Certificate.NotBefore)

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	after := time.Since(signer.Certificate.NotBefore)

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	tstInfo := extractTSTInfo(t, resp)

	// Serial should be at most 16 bytes (128 bits).
	serialBytes := tstInfo.SerialNumber.Bytes()
	if len(serialBytes) > 16 {
		t.Fatalf("serial number too large: %d bytes, want at most 16", len(serialBytes))
	}

	if len(serialBytes) < 13 {
		t.Fatalf("serial number too small: %d bytes, want at least 13", len(serialBytes))
	}

	// Verify the upper 4 bytes encode seconds since NotBefore.
	var padded [16]byte
	copy(padded[16-len(serialBytes):], serialBytes)
	seconds := binary.BigEndian.Uint32(padded[:4])

	if seconds < uint32(before.Seconds())-1 || seconds > uint32(after.Seconds())+1 {
		t.Fatalf("serial timestamp %d not in expected range [%d, %d]",
			seconds, uint32(before.Seconds())-1, uint32(after.Seconds())+1)
	}
}

func TestCreateResponseSerialUnique(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	resp1DER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp2DER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp1, err := ParseResponse(resp1DER)
	if err != nil {
		t.Fatal(err)
	}

	resp2, err := ParseResponse(resp2DER)
	if err != nil {
		t.Fatal(err)
	}

	tst1 := extractTSTInfo(t, resp1)
	tst2 := extractTSTInfo(t, resp2)

	if tst1.SerialNumber.Cmp(tst2.SerialNumber) == 0 {
		t.Fatalf("serial numbers should be unique, both are %v", tst1.SerialNumber)
	}
}

func TestCreateResponseCertReqTrue(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)
	req.CertReq = true

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	parsedSD := extractSignedData(t, resp)
	if len(parsedSD.Certificates.Bytes) == 0 {
		t.Fatal("certificates should be present when certReq is true")
	}
}

func TestCreateResponseCertReqFalse(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)
	req.CertReq = false

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	parsedSD := extractSignedData(t, resp)
	if len(parsedSD.Certificates.Bytes) != 0 {
		t.Fatal("certificates should be absent when certReq is false")
	}
}

func TestCreateResponseTSTInfoFields(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	before := time.Now().UTC().Add(-time.Second)

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	after := time.Now().UTC().Add(time.Second)

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	tstInfo := extractTSTInfo(t, resp)

	if tstInfo.Version != 1 {
		t.Fatalf("TSTInfo version = %d, want 1", tstInfo.Version)
	}

	if !tstInfo.Policy.Equal(OIDDefaultPolicy) {
		t.Fatal("TSTInfo policy mismatch")
	}

	if !tstInfo.MessageImprint.HashAlgorithm.Algorithm.Equal(req.MessageImprint.HashAlgorithm.Algorithm) {
		t.Fatal("TSTInfo messageImprint algorithm mismatch")
	}

	if string(tstInfo.MessageImprint.HashedMessage) != string(req.MessageImprint.HashedMessage) {
		t.Fatal("TSTInfo messageImprint hash mismatch")
	}

	if tstInfo.GenTime.Before(before) || tstInfo.GenTime.After(after) {
		t.Fatalf("genTime %v not in expected range [%v, %v]", tstInfo.GenTime, before, after)
	}
}

func TestCreateResponseSignatureVerifies(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)
	req.CertReq = true

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	parsedSD := extractSignedData(t, resp)
	parsedSI := extractSignerInfo(t, parsedSD)

	// Rebuild signed attributes with SET tag for verification.
	attrBytes := parsedSI.SignedAttrs.FullBytes
	setBuf := make([]byte, len(attrBytes))
	copy(setBuf, attrBytes)
	setBuf[0] = 0x31

	digest := sha256.Sum256(setBuf)

	err = rsa.VerifyPKCS1v15(&signer.Key.PublicKey, crypto.SHA256, digest[:], parsedSI.Signature)
	if err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
}

func TestCreateResponseEContentType(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	parsedSD := extractSignedData(t, resp)
	if !parsedSD.EncapContentInfo.EContentType.Equal(OIDTSTInfo) {
		t.Fatal("eContentType should be id-ct-TSTInfo")
	}
}

func TestCreateResponseSigningCertificateV2(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)
	req := validRequest(t)

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	parsedSD := extractSignedData(t, resp)
	parsedSI := extractSignerInfo(t, parsedSD)

	// Parse signed attributes to find SigningCertificateV2.
	attrs := extractSignedAttrs(t, parsedSI)

	found := false

	for _, attr := range attrs {
		if attr.Type.Equal(OIDSigningCertificateV2) {
			found = true

			var sigCertV2 signingCertificateV2

			_, err := asn1.Unmarshal(attr.Values.Bytes, &sigCertV2)
			if err != nil {
				t.Fatalf("unmarshal SigningCertificateV2: %v", err)
			}

			if len(sigCertV2.Certs) != 1 {
				t.Fatalf("expected 1 ESSCertIDv2, got %d", len(sigCertV2.Certs))
			}

			certHash := sha256.Sum256(signer.Certificate.Raw)
			if !bytes.Equal(sigCertV2.Certs[0].CertHash, certHash[:]) {
				t.Fatal("ESSCertIDv2 certHash does not match certificate")
			}
		}
	}

	if !found {
		t.Fatal("SigningCertificateV2 attribute not found in signed attributes")
	}
}

func TestCreateErrorResponse(t *testing.T) {
	t.Parallel()

	respDER, err := CreateErrorResponse(FailureBadAlg)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status.Status != StatusRejection {
		t.Fatalf("status = %d, want %d", resp.Status.Status, StatusRejection)
	}

	if resp.Status.FailInfo.At(int(FailureBadAlg)) != 1 {
		t.Fatal("badAlg bit should be set")
	}
}

func TestCreateErrorResponseBadDataFormat(t *testing.T) {
	t.Parallel()

	respDER, err := CreateErrorResponse(FailureBadDataFormat)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status.Status != StatusRejection {
		t.Fatalf("status = %d, want %d", resp.Status.Status, StatusRejection)
	}

	if resp.Status.FailInfo.At(int(FailureBadDataFormat)) != 1 {
		t.Fatal("badDataFormat bit should be set")
	}
}

func extractSignedData(t *testing.T, resp *TimeStampResp) signedData {
	t.Helper()

	var parsed signedData

	_, err := asn1.Unmarshal(resp.TimeStampToken.Content.Bytes, &parsed)
	if err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	return parsed
}

func extractSignerInfo(t *testing.T, parsed signedData) signerInfo {
	t.Helper()

	var info signerInfo

	_, err := asn1.Unmarshal(parsed.SignerInfos.Bytes, &info)
	if err != nil {
		t.Fatalf("unmarshal SignerInfo: %v", err)
	}

	return info
}

func extractSignedAttrs(t *testing.T, info signerInfo) []attribute {
	t.Helper()

	var attrs []attribute

	rest := info.SignedAttrs.Bytes

	for len(rest) > 0 {
		var attr attribute

		var err error

		rest, err = asn1.Unmarshal(rest, &attr)
		if err != nil {
			t.Fatalf("unmarshal attribute: %v", err)
		}

		attrs = append(attrs, attr)
	}

	return attrs
}

func extractTSTInfo(t *testing.T, resp *TimeStampResp) TSTInfo {
	t.Helper()

	parsedSD := extractSignedData(t, resp)

	var eContentOctet []byte

	_, err := asn1.Unmarshal(parsedSD.EncapContentInfo.EContent.Bytes, &eContentOctet)
	if err != nil {
		t.Fatalf("unmarshal eContent OCTET STRING: %v", err)
	}

	var tstInfo TSTInfo

	_, err = asn1.Unmarshal(eContentOctet, &tstInfo)
	if err != nil {
		t.Fatalf("unmarshal TSTInfo: %v", err)
	}

	return tstInfo
}
