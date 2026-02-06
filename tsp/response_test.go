package tsp

import (
	"testing"
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
