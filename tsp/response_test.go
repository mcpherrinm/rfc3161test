package tsp_test

import (
	"testing"

	"github.com/mcpherrinm/rfc3161test/tsp"
)

func TestFailureInfoBitString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		bit  tsp.PKIFailureInfo
	}{
		{"badAlg", tsp.FailureBadAlg},
		{"badRequest", tsp.FailureBadRequest},
		{"badDataFormat", tsp.FailureBadDataFormat},
		{"timeNotAvailable", tsp.FailureTimeNotAvailable},
		{"unacceptedPolicy", tsp.FailureUnacceptedPolicy},
		{"unacceptedExtension", tsp.FailureUnacceptedExtension},
		{"addInfoNotAvailable", tsp.FailureAddInfoNotAvailable},
		{"systemFailure", tsp.FailureSystemFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			bs := tsp.FailureInfoBitString(tt.bit)
			if bs.BitLength != int(tt.bit)+1 {
				t.Fatalf("BitLength = %d, want %d", bs.BitLength, int(tt.bit)+1)
			}

			if bs.At(int(tt.bit)) != 1 {
				t.Fatal("expected bit to be set")
			}
		})
	}
}
