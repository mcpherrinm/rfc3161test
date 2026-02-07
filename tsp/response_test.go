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

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
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

	if resp.TimeStampToken == nil {
		t.Fatal("token should be present")
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

	hasCerts := extractHasCertificates(t, resp)
	if !hasCerts {
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

	hasCerts := extractHasCertificates(t, resp)
	if hasCerts {
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

	signedAttrsDER, signature := extractSignerInfoParts(t, resp)

	// Rebuild signed attributes with SET tag for verification.
	setBuf := make([]byte, len(signedAttrsDER))
	copy(setBuf, signedAttrsDER)
	setBuf[0] = 0x31

	digest := sha256.Sum256(setBuf)

	err = rsa.VerifyPKCS1v15(&signer.Key.PublicKey, crypto.SHA256, digest[:], signature)
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

	eContentType := extractEContentType(t, resp)
	if !eContentType.Equal(OIDTSTInfo) {
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

	signedAttrsDER, _ := extractSignerInfoParts(t, resp)

	// Parse signed attributes to find SigningCertificateV2
	found := false
	input := cryptobyte.String(signedAttrsDER)

	// The signedAttrs is tagged [0] IMPLICIT - read inner elements
	var attrsContent cryptobyte.String
	if !input.ReadASN1(&attrsContent, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		// Try as raw SET
		input = cryptobyte.String(signedAttrsDER)
		attrsContent = input
	}

	for !attrsContent.Empty() {
		var attrSeq cryptobyte.String
		if !attrsContent.ReadASN1(&attrSeq, cbasn1.SEQUENCE) {
			t.Fatal("failed to read attribute SEQUENCE")
		}

		var attrOID asn1.ObjectIdentifier
		if !attrSeq.ReadASN1ObjectIdentifier(&attrOID) {
			t.Fatal("failed to read attribute OID")
		}

		if attrOID.Equal(OIDSigningCertificateV2) {
			found = true

			var setContent cryptobyte.String
			if !attrSeq.ReadASN1(&setContent, cbasn1.SET) {
				t.Fatal("failed to read attribute SET")
			}

			// Parse SigningCertificateV2
			var scv2Seq cryptobyte.String
			if !setContent.ReadASN1(&scv2Seq, cbasn1.SEQUENCE) {
				t.Fatal("failed to read SigningCertificateV2 SEQUENCE")
			}

			// Parse ESSCertIDv2
			var certIDSeq cryptobyte.String
			if !scv2Seq.ReadASN1(&certIDSeq, cbasn1.SEQUENCE) {
				t.Fatal("failed to read ESSCertIDv2 SEQUENCE")
			}

			// certHash OCTET STRING
			var certHash []byte
			if !certIDSeq.ReadASN1Bytes(&certHash, cbasn1.OCTET_STRING) {
				t.Fatal("failed to read certHash")
			}

			expectedHash := sha256.Sum256(signer.Certificate.Raw)
			if !bytes.Equal(certHash, expectedHash[:]) {
				t.Fatal("ESSCertIDv2 certHash does not match certificate")
			}
		}
	}

	if !found {
		t.Fatal("SigningCertificateV2 attribute not found in signed attributes")
	}
}

func TestCreateResponseCSBRPolicyOID(t *testing.T) {
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

	tstInfo := extractTSTInfo(t, resp)

	// CSBR §1.2.2 requires the TSA policy OID 2.23.140.1.4.2.
	expectedOID := asn1.ObjectIdentifier{2, 23, 140, 1, 4, 2}
	if !tstInfo.Policy.Equal(expectedOID) {
		t.Fatalf("TSTInfo policy = %v, want %v (CSBR TSA policy)", tstInfo.Policy, expectedOID)
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

// extractSignedDataContent returns the raw bytes inside the SignedData content.
func extractSignedDataContent(t *testing.T, resp *TimeStampResp) cryptobyte.String {
	t.Helper()

	return cryptobyte.String(resp.TimeStampToken.Content)
}

// extractHasCertificates checks if the SignedData contains certificates.
func extractHasCertificates(t *testing.T, resp *TimeStampResp) bool {
	t.Helper()

	sdContent := extractSignedDataContent(t, resp)

	var sdSeq cryptobyte.String
	if !sdContent.ReadASN1(&sdSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read SignedData SEQUENCE")
	}

	// version
	var version int
	if !sdSeq.ReadASN1Integer(&version) {
		t.Fatal("failed to read version")
	}

	// digestAlgorithms SET
	if !sdSeq.SkipASN1(cbasn1.SET) {
		t.Fatal("failed to skip digestAlgorithms")
	}

	// encapContentInfo SEQUENCE
	if !sdSeq.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("failed to skip encapContentInfo")
	}

	// certificates [0] IMPLICIT (optional)
	return sdSeq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed())
}

// extractSignerInfoParts returns the raw signed attributes DER and signature.
func extractSignerInfoParts(t *testing.T, resp *TimeStampResp) ([]byte, []byte) {
	t.Helper()

	sdContent := extractSignedDataContent(t, resp)

	var sdSeq cryptobyte.String
	if !sdContent.ReadASN1(&sdSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read SignedData SEQUENCE")
	}

	// version
	if !sdSeq.SkipASN1(cbasn1.INTEGER) {
		t.Fatal("failed to skip version")
	}

	// digestAlgorithms SET
	if !sdSeq.SkipASN1(cbasn1.SET) {
		t.Fatal("failed to skip digestAlgorithms")
	}

	// encapContentInfo SEQUENCE
	if !sdSeq.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("failed to skip encapContentInfo")
	}

	// certificates [0] IMPLICIT (optional)
	sdSeq.SkipOptionalASN1(cbasn1.Tag(0).ContextSpecific().Constructed())

	// signerInfos SET
	var siSet cryptobyte.String
	if !sdSeq.ReadASN1(&siSet, cbasn1.SET) {
		t.Fatal("failed to read signerInfos SET")
	}

	// SignerInfo SEQUENCE
	var siSeq cryptobyte.String
	if !siSet.ReadASN1(&siSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read SignerInfo SEQUENCE")
	}

	// version
	if !siSeq.SkipASN1(cbasn1.INTEGER) {
		t.Fatal("failed to skip SI version")
	}

	// SID SEQUENCE
	if !siSeq.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("failed to skip SID")
	}

	// digestAlgorithm SEQUENCE
	if !siSeq.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("failed to skip digestAlgorithm")
	}

	// signedAttrs [0] IMPLICIT - read as element (with tag)
	var rawAttrs cryptobyte.String
	if !siSeq.ReadASN1Element(&rawAttrs, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		t.Fatal("failed to read signedAttrs element")
	}

	// signatureAlgorithm SEQUENCE
	if !siSeq.SkipASN1(cbasn1.SEQUENCE) {
		t.Fatal("failed to skip signatureAlgorithm")
	}

	// signature OCTET STRING
	var sig []byte
	if !siSeq.ReadASN1Bytes(&sig, cbasn1.OCTET_STRING) {
		t.Fatal("failed to read signature")
	}

	return []byte(rawAttrs), sig
}

// extractEContentType returns the eContentType OID from the SignedData.
func extractEContentType(t *testing.T, resp *TimeStampResp) asn1.ObjectIdentifier {
	t.Helper()

	sdContent := extractSignedDataContent(t, resp)

	var sdSeq cryptobyte.String
	if !sdContent.ReadASN1(&sdSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read SignedData SEQUENCE")
	}

	// version
	if !sdSeq.SkipASN1(cbasn1.INTEGER) {
		t.Fatal("failed to skip version")
	}

	// digestAlgorithms SET
	if !sdSeq.SkipASN1(cbasn1.SET) {
		t.Fatal("failed to skip digestAlgorithms")
	}

	// encapContentInfo SEQUENCE
	var eciSeq cryptobyte.String
	if !sdSeq.ReadASN1(&eciSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read encapContentInfo")
	}

	var eContentType asn1.ObjectIdentifier
	if !eciSeq.ReadASN1ObjectIdentifier(&eContentType) {
		t.Fatal("failed to read eContentType")
	}

	return eContentType
}

func extractTSTInfo(t *testing.T, resp *TimeStampResp) TSTInfo {
	t.Helper()

	sdContent := extractSignedDataContent(t, resp)

	var sdSeq cryptobyte.String
	if !sdContent.ReadASN1(&sdSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read SignedData SEQUENCE")
	}

	// version
	if !sdSeq.SkipASN1(cbasn1.INTEGER) {
		t.Fatal("failed to skip version")
	}

	// digestAlgorithms SET
	if !sdSeq.SkipASN1(cbasn1.SET) {
		t.Fatal("failed to skip digestAlgorithms")
	}

	// encapContentInfo SEQUENCE
	var eciSeq cryptobyte.String
	if !sdSeq.ReadASN1(&eciSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read encapContentInfo")
	}

	// eContentType OID
	if !eciSeq.SkipASN1(cbasn1.OBJECT_IDENTIFIER) {
		t.Fatal("failed to skip eContentType")
	}

	// eContent [0] EXPLICIT
	var eContentExplicit cryptobyte.String
	if !eciSeq.ReadASN1(&eContentExplicit, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		t.Fatal("failed to read eContent [0]")
	}

	// OCTET STRING
	var tstInfoDER []byte
	if !eContentExplicit.ReadASN1Bytes(&tstInfoDER, cbasn1.OCTET_STRING) {
		t.Fatal("failed to read eContent OCTET STRING")
	}

	return parseTSTInfoDER(t, tstInfoDER)
}

func parseTSTInfoDER(t *testing.T, der []byte) TSTInfo {
	t.Helper()

	input := cryptobyte.String(der)

	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read TSTInfo SEQUENCE")
	}

	var info TSTInfo

	if !seq.ReadASN1Integer(&info.Version) {
		t.Fatal("failed to read TSTInfo version")
	}

	if !seq.ReadASN1ObjectIdentifier(&info.Policy) {
		t.Fatal("failed to read TSTInfo policy")
	}

	// messageImprint SEQUENCE
	var miSeq cryptobyte.String
	if !seq.ReadASN1(&miSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read TSTInfo messageImprint")
	}

	var algSeq cryptobyte.String
	if !miSeq.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read hashAlgorithm")
	}

	if !algSeq.ReadASN1ObjectIdentifier(&info.MessageImprint.HashAlgorithm.Algorithm) {
		t.Fatal("failed to read algorithm OID")
	}

	if !miSeq.ReadASN1Bytes(&info.MessageImprint.HashedMessage, cbasn1.OCTET_STRING) {
		t.Fatal("failed to read hashedMessage")
	}

	info.SerialNumber = new(big.Int)
	if !seq.ReadASN1Integer(info.SerialNumber) {
		t.Fatal("failed to read serialNumber")
	}

	if !seq.ReadASN1GeneralizedTime(&info.GenTime) {
		t.Fatal("failed to read genTime")
	}

	// Optional fields: accuracy, ordering, nonce, tsa, extensions
	// Skip accuracy if present (SEQUENCE)
	seq.SkipOptionalASN1(cbasn1.SEQUENCE)

	// Skip ordering if present (BOOLEAN)
	if seq.PeekASN1Tag(cbasn1.BOOLEAN) {
		var ordering bool
		if !seq.ReadASN1Boolean(&ordering) {
			t.Fatal("failed to read ordering")
		}
	}

	// nonce (optional INTEGER)
	if seq.PeekASN1Tag(cbasn1.INTEGER) {
		info.Nonce = new(big.Int)
		if !seq.ReadASN1Integer(info.Nonce) {
			t.Fatal("failed to read nonce")
		}
	}

	return info
}
