package server

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mcpherrinm/rfc3161test/tsp"
)

func FuzzHandleHTTP(f *testing.F) {
	hash := sha256.Sum256([]byte("test"))

	req := tsp.TimeStampReq{
		Version: 1,
		MessageImprint: tsp.MessageImprint{
			HashAlgorithm: tsp.AlgorithmIdentifier{
				Algorithm: tsp.OIDSHA256,
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	valid, err := tsp.MarshalRequest(&req)
	if err == nil {
		f.Add(valid)
	}

	f.Add([]byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	signer := createTestSigner(f)

	f.Fuzz(func(_ *testing.T, data []byte) {
		recorder := httptest.NewRecorder()
		httpReq := httptest.NewRequest(
			http.MethodPost,
			"/",
			bytes.NewReader(data),
		)
		httpReq.Header.Set("Content-Type", contentTypeQuery)

		Handler(signer).ServeHTTP(recorder, httpReq)

		if recorder.Code != http.StatusOK {
			return
		}

		_, _ = tsp.ParseResponse(recorder.Body.Bytes())
	})
}
