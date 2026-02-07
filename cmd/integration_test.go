package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/mcpherrinm/rfc3161test/server"
	"github.com/mcpherrinm/rfc3161test/tsp"
)

func e2eTestSigner(t *testing.T) *tsp.Signer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{ //nolint:exhaustruct // test cert
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test TSA"}, //nolint:exhaustruct // test cert
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(
		rand.Reader, tmpl, tmpl, &key.PublicKey, key,
	)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	return &tsp.Signer{Key: key, Certificate: cert}
}

func TestEndToEnd(t *testing.T) {
	t.Parallel()

	signer := e2eTestSigner(t)

	srv := httptest.NewServer(server.Handler(signer))
	defer srv.Close()

	testData := []byte("end-to-end test file contents")
	hash := sha256.Sum256(testData)
	nonce := big.NewInt(123456789)

	reqDER := marshalE2EReq(t, hash[:], nonce)
	body := postE2ERequest(t, srv.URL, reqDER)

	tsResp, err := tsp.ParseResponse(body)
	if err != nil {
		t.Fatal(err)
	}

	if tsResp.Status.Status != tsp.StatusGranted {
		t.Fatalf(
			"status = %d, want %d",
			tsResp.Status.Status,
			tsp.StatusGranted,
		)
	}

	if tsResp.TimeStampToken == nil || !tsResp.TimeStampToken.ContentType.Equal(tsp.OIDSignedData) {
		t.Fatal("token content type should be signedData")
	}

	verifyE2ETSTInfo(t, tsResp, hash[:], nonce)
}

func marshalE2EReq(t *testing.T, hash []byte, nonce *big.Int) []byte {
	t.Helper()

	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm: tsp.OIDSHA256,
			},
			HashedMessage: hash,
		},
		ReqPolicy:  nil,
		Nonce:      nonce,
		CertReq:    true,
		Extensions: nil,
	}

	der, err := tsp.MarshalRequest(&req)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func postE2ERequest(t *testing.T, url string, reqDER []byte) []byte {
	t.Helper()

	httpReq, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		url,
		bytes.NewReader(reqDER),
	)
	if err != nil {
		t.Fatal(err)
	}

	httpReq.Header.Set("Content-Type", "application/timestamp-query")

	httpResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close() //nolint:errcheck // test cleanup

	if httpResp.StatusCode != http.StatusOK {
		t.Fatalf(
			"status = %d, want %d",
			httpResp.StatusCode,
			http.StatusOK,
		)
	}

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		t.Fatal(err)
	}

	return body
}

func verifyE2ETSTInfo(
	t *testing.T,
	tsResp *tsp.TimeStampResp,
	hash []byte,
	nonce *big.Int,
) {
	t.Helper()

	sdContent := cryptobyte.String(tsResp.TimeStampToken.Content)

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

	var eContentExplicit cryptobyte.String
	if !eciSeq.ReadASN1(&eContentExplicit, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		t.Fatal("failed to read eContent [0]")
	}

	var tstInfoDER []byte
	if !eContentExplicit.ReadASN1Bytes(&tstInfoDER, cbasn1.OCTET_STRING) {
		t.Fatal("failed to read eContent OCTET STRING")
	}

	tstInfo := parseTSTInfoDER(t, tstInfoDER)

	if tstInfo.Nonce == nil || tstInfo.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce = %v, want %v", tstInfo.Nonce, nonce)
	}

	if !tstInfo.Policy.Equal(tsp.OIDDefaultPolicy) {
		t.Fatal("policy mismatch")
	}

	if !tstInfo.MessageImprint.HashAlgorithm.Algorithm.Equal(tsp.OIDSHA256) {
		t.Fatal("messageImprint algorithm mismatch")
	}

	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, hash) {
		t.Fatal("messageImprint hash mismatch")
	}

	// certificates [0] IMPLICIT (optional)
	hasCerts := sdSeq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed())
	if !hasCerts {
		t.Fatal("certificates should be present when certReq is true")
	}
}

func parseTSTInfoDER(t *testing.T, der []byte) tsp.TSTInfo {
	t.Helper()

	input := cryptobyte.String(der)

	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) {
		t.Fatal("failed to read TSTInfo SEQUENCE")
	}

	var info tsp.TSTInfo

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

	// Optional: skip accuracy, ordering
	seq.SkipOptionalASN1(cbasn1.SEQUENCE)

	if seq.PeekASN1Tag(cbasn1.BOOLEAN) {
		var ordering bool
		if !seq.ReadASN1Boolean(&ordering) {
			t.Fatal("failed to read ordering")
		}
	}

	// nonce
	if seq.PeekASN1Tag(cbasn1.INTEGER) {
		info.Nonce = new(big.Int)
		if !seq.ReadASN1Integer(info.Nonce) {
			t.Fatal("failed to read nonce")
		}
	}

	return info
}
