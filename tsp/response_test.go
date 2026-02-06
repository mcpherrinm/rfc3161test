package tsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
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

	key, err := rsa.GenerateKey(rand.Reader, 2048) //nolint:mnd // test key size
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"},      //nolint:exhaustruct // test cert
		NotBefore:             time.Now().Add(-time.Hour),              //nolint:mnd // test cert validity
		NotAfter:              time.Now().Add(time.Hour),               //nolint:mnd // test cert validity
		KeyUsage:              x509.KeyUsageDigitalSignature,           //nolint:exhaustruct // test cert
		BasicConstraintsValid: true,                                    //nolint:exhaustruct // test cert
	} //nolint:exhaustruct // test cert

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
	req.Nonce = big.NewInt(99999) //nolint:mnd // test nonce value

	respDER, err := signer.CreateResponse(&req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := ParseResponse(respDER)
	if err != nil {
		t.Fatal(err)
	}

	tstInfo := extractTSTInfo(t, resp)
	if tstInfo.Nonce == nil || tstInfo.Nonce.Cmp(big.NewInt(99999)) != 0 { //nolint:mnd // test nonce value
		t.Fatalf("nonce = %v, want 99999", tstInfo.Nonce)
	}
}

func TestCreateResponseSerialIncrements(t *testing.T) {
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

	if tst1.SerialNumber.Cmp(tst2.SerialNumber) >= 0 {
		t.Fatalf("serial %v should be less than %v", tst1.SerialNumber, tst2.SerialNumber)
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

	sd := extractSignedData(t, resp)
	if len(sd.Certificates.Bytes) == 0 {
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

	sd := extractSignedData(t, resp)
	if len(sd.Certificates.Bytes) != 0 {
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

	sd := extractSignedData(t, resp)
	si := extractSignerInfo(t, sd)

	// Rebuild signed attributes with SET tag for verification.
	attrBytes := si.SignedAttrs.FullBytes
	setBuf := make([]byte, len(attrBytes))
	copy(setBuf, attrBytes)
	setBuf[0] = 0x31

	h := sha256.Sum256(setBuf)

	err = rsa.VerifyPKCS1v15(&signer.Key.PublicKey, crypto.SHA256, h[:], si.Signature)
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

	sd := extractSignedData(t, resp)
	if !sd.EncapContentInfo.EContentType.Equal(OIDTSTInfo) {
		t.Fatal("eContentType should be id-ct-TSTInfo")
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

	var sd signedData

	_, err := asn1.Unmarshal(resp.TimeStampToken.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	return sd
}

func extractSignerInfo(t *testing.T, sd signedData) signerInfo {
	t.Helper()

	var si signerInfo

	_, err := asn1.Unmarshal(sd.SignerInfos.Bytes, &si)
	if err != nil {
		t.Fatalf("unmarshal SignerInfo: %v", err)
	}

	return si
}

func extractTSTInfo(t *testing.T, resp *TimeStampResp) TSTInfo {
	t.Helper()

	sd := extractSignedData(t, resp)

	var eContentOctet []byte

	_, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &eContentOctet)
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
