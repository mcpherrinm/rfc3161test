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

	if !tsResp.TimeStampToken.ContentType.Equal(tsp.OIDSignedData) {
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
				Algorithm:  tsp.OIDSHA256,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: hash,
		},
		ReqPolicy:  nil,
		Nonce:      nonce,
		CertReq:    true,
		Extensions: nil,
	}

	der, err := asn1.Marshal(req)
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

	parsedSD := unmarshalSignedData(t, tsResp)
	tstInfo := unmarshalTSTInfo(t, parsedSD)

	if tstInfo.Nonce == nil || tstInfo.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce = %v, want %v", tstInfo.Nonce, nonce)
	}

	if !tstInfo.Policy.Equal(tsp.OIDDefaultPolicy) {
		t.Fatal("policy mismatch")
	}

	if !tstInfo.MessageImprint.HashAlgorithm.Algorithm.Equal(tsp.OIDSHA256) {
		t.Fatal("messageImprint algorithm mismatch")
	}

	if string(tstInfo.MessageImprint.HashedMessage) != string(hash) {
		t.Fatal("messageImprint hash mismatch")
	}

	if len(parsedSD.Certificates.Bytes) == 0 {
		t.Fatal("certificates should be present when certReq is true")
	}
}

type e2eSignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo struct {
		EContentType asn1.ObjectIdentifier
		EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
	}
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos  asn1.RawValue `asn1:"set"`
}

func unmarshalSignedData(
	t *testing.T, tsResp *tsp.TimeStampResp,
) e2eSignedData {
	t.Helper()

	var parsedSD e2eSignedData

	_, err := asn1.Unmarshal(
		tsResp.TimeStampToken.Content.Bytes,
		&parsedSD,
	)
	if err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	return parsedSD
}

func unmarshalTSTInfo(t *testing.T, parsedSD e2eSignedData) tsp.TSTInfo {
	t.Helper()

	var eContentOctet []byte

	_, err := asn1.Unmarshal(
		parsedSD.EncapContentInfo.EContent.Bytes,
		&eContentOctet,
	)
	if err != nil {
		t.Fatalf("unmarshal eContent: %v", err)
	}

	var tstInfo tsp.TSTInfo

	_, err = asn1.Unmarshal(eContentOctet, &tstInfo)
	if err != nil {
		t.Fatalf("unmarshal TSTInfo: %v", err)
	}

	return tstInfo
}
