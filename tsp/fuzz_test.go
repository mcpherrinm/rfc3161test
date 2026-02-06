package tsp

import (
	"crypto/sha256"
	"encoding/asn1"
	"testing"
)

func FuzzParseRequest(f *testing.F) {
	hash := sha256.Sum256([]byte("test"))
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{
				Algorithm:  OIDSHA256,
				Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
			},
			HashedMessage: hash[:],
		},
		ReqPolicy:  nil,
		Nonce:      nil,
		CertReq:    false,
		Extensions: nil,
	}

	valid, err := asn1.Marshal(req)
	if err == nil {
		f.Add(valid)
	}

	f.Add([]byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseRequest(data)
	})
}
