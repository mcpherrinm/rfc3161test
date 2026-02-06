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
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDSHA256},
			HashedMessage: hash[:],
		},
	}
	if valid, err := asn1.Marshal(req); err == nil {
		f.Add(valid)
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic.
		_, _ = ParseRequest(data)
	})
}
