package server

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

	"github.com/mcpherrinm/rfc3161test/tsp"
)

func createTestSigner(tb testing.TB) *tsp.Signer {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}

	tmpl := &x509.Certificate{ //nolint:exhaustruct // test cert: only fields relevant for TSA
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
		tb.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		tb.Fatal(err)
	}

	return &tsp.Signer{Key: key, Certificate: cert}
}

func testSigner(t *testing.T) *tsp.Signer {
	t.Helper()

	return createTestSigner(t)
}

func validRequestDER(t *testing.T) []byte {
	t.Helper()

	hash := sha256.Sum256([]byte("test data"))

	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm:  tsp.OIDSHA256,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      big.NewInt(42),
		CertReq:    true,
		Extensions: nil,
	}

	der, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func postTimestamp(
	t *testing.T, url, contentType string, body []byte,
) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func getRequest(t *testing.T, url string) *http.Response {
	t.Helper()

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		url,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func TestHandlerValidRequest(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)

	srv := httptest.NewServer(Handler(signer))
	defer srv.Close()

	reqDER := validRequestDER(t)

	resp := postTimestamp(t, srv.URL, contentTypeQuery, reqDER)
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	if resp.Header.Get("Content-Type") != contentTypeReply {
		t.Fatalf(
			"content-type = %s, want %s",
			resp.Header.Get("Content-Type"),
			contentTypeReply,
		)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tsResp, err := tsp.ParseResponse(body)
	if err != nil {
		t.Fatal(err)
	}

	if tsResp.Status.Status != tsp.StatusGranted {
		t.Fatalf("status = %d, want %d", tsResp.Status.Status, tsp.StatusGranted)
	}

	if !tsResp.TimeStampToken.ContentType.Equal(tsp.OIDSignedData) {
		t.Fatal("token content type should be signedData")
	}
}

func TestHandlerWrongMethod(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)

	srv := httptest.NewServer(Handler(signer))
	defer srv.Close()

	resp := getRequest(t, srv.URL)
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf(
			"status = %d, want %d",
			resp.StatusCode,
			http.StatusMethodNotAllowed,
		)
	}
}

func TestHandlerWrongContentType(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)

	srv := httptest.NewServer(Handler(signer))
	defer srv.Close()

	resp := postTimestamp(t, srv.URL, "text/plain", []byte("hello"))
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf(
			"status = %d, want %d",
			resp.StatusCode,
			http.StatusBadRequest,
		)
	}
}

func TestHandlerGarbageBody(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)

	srv := httptest.NewServer(Handler(signer))
	defer srv.Close()

	resp := postTimestamp(
		t, srv.URL, contentTypeQuery, []byte{0x00, 0x01, 0x02},
	)
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tsResp, err := tsp.ParseResponse(body)
	if err != nil {
		t.Fatal(err)
	}

	if tsResp.Status.Status != tsp.StatusRejection {
		t.Fatalf(
			"status = %d, want %d",
			tsResp.Status.Status,
			tsp.StatusRejection,
		)
	}

	if tsResp.Status.FailInfo.At(int(tsp.FailureBadDataFormat)) != 1 {
		t.Fatal("badDataFormat bit should be set")
	}
}

func TestHandlerUnsupportedHash(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)

	srv := httptest.NewServer(Handler(signer))
	defer srv.Close()

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

	der, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	resp := postTimestamp(t, srv.URL, contentTypeQuery, der)
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tsResp, err := tsp.ParseResponse(body)
	if err != nil {
		t.Fatal(err)
	}

	if tsResp.Status.Status != tsp.StatusRejection {
		t.Fatalf(
			"status = %d, want %d",
			tsResp.Status.Status,
			tsp.StatusRejection,
		)
	}

	if tsResp.Status.FailInfo.At(int(tsp.FailureBadAlg)) != 1 {
		t.Fatal("badAlg bit should be set")
	}
}

func TestHandlerIntegrationNonce(t *testing.T) {
	t.Parallel()

	signer := testSigner(t)

	srv := httptest.NewServer(Handler(signer))
	defer srv.Close()

	hash := sha256.Sum256([]byte("integration test data"))
	nonce := big.NewInt(77777)

	reqDER := marshalTestReq(t, hash[:], nonce)

	resp := postTimestamp(t, srv.URL, contentTypeQuery, reqDER)
	defer resp.Body.Close() //nolint:errcheck // test cleanup

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	tsResp, err := tsp.ParseResponse(body)
	if err != nil {
		t.Fatal(err)
	}

	if tsResp.Status.Status != tsp.StatusGranted {
		t.Fatalf("status = %d, want %d", tsResp.Status.Status, tsp.StatusGranted)
	}

	tstInfo := extractTSTInfo(t, tsResp)

	verifyTSTInfo(t, tstInfo, hash[:], nonce)
}

func marshalTestReq(t *testing.T, hash []byte, nonce *big.Int) []byte {
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

func extractTSTInfo(t *testing.T, resp *tsp.TimeStampResp) tsp.TSTInfo {
	t.Helper()

	var parsedSD struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		EncapContentInfo struct {
			EContentType asn1.ObjectIdentifier
			EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
		}
		Certificates asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos  asn1.RawValue `asn1:"set"`
	}

	_, err := asn1.Unmarshal(resp.TimeStampToken.Content.Bytes, &parsedSD)
	if err != nil {
		t.Fatalf("unmarshal SignedData: %v", err)
	}

	if !parsedSD.EncapContentInfo.EContentType.Equal(tsp.OIDTSTInfo) {
		t.Fatal("eContentType should be id-ct-TSTInfo")
	}

	var eContentOctet []byte

	_, err = asn1.Unmarshal(
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

func verifyTSTInfo(
	t *testing.T, tstInfo tsp.TSTInfo, hash []byte, nonce *big.Int,
) {
	t.Helper()

	if !tstInfo.Policy.Equal(tsp.OIDDefaultPolicy) {
		t.Fatal("policy mismatch")
	}

	if tstInfo.Nonce == nil || tstInfo.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce = %v, want %v", tstInfo.Nonce, nonce)
	}

	if !tstInfo.MessageImprint.HashAlgorithm.Algorithm.Equal(tsp.OIDSHA256) {
		t.Fatal("messageImprint algorithm mismatch")
	}

	if !bytes.Equal(tstInfo.MessageImprint.HashedMessage, hash) {
		t.Fatal("messageImprint hash mismatch")
	}
}
