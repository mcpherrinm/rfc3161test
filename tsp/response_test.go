package tsp

import "testing"

func TestFailureInfoBitString(t *testing.T) {
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
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := FailureInfoBitString(tt.bit)
			if bs.BitLength != int(tt.bit)+1 {
				t.Fatalf("BitLength = %d, want %d", bs.BitLength, int(tt.bit)+1)
			}
			if bs.At(int(tt.bit)) != 1 {
				t.Fatal("expected bit to be set")
			}
		})
	}
}
