package tsp

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// AlgorithmIdentifier represents an X.509 AlgorithmIdentifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// MessageImprint contains a hash algorithm and the hash of the data to be timestamped.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// Extension represents an X.509 extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional,default:false"`
	Value    []byte
}

// TimeStampReq represents an RFC 3161 TimeStampReq.
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []Extension           `asn1:"optional,tag:0"`
}

// PKIFailureInfo represents an RFC 3161 PKIFailureInfo bit position.
type PKIFailureInfo int

// PKIFailureInfo constants per RFC 3161 §2.4.2.
const (
	FailureBadAlg              PKIFailureInfo = 0
	FailureBadRequest          PKIFailureInfo = 2
	FailureBadDataFormat       PKIFailureInfo = 5
	FailureTimeNotAvailable    PKIFailureInfo = 14
	FailureUnacceptedPolicy    PKIFailureInfo = 15
	FailureUnacceptedExtension PKIFailureInfo = 16
	FailureAddInfoNotAvailable PKIFailureInfo = 17
	FailureSystemFailure       PKIFailureInfo = 25
)

// RequestError is returned when a TimeStampReq is invalid.
type RequestError struct {
	FailureInfo PKIFailureInfo
	Detail      string
}

func (e *RequestError) Error() string { return e.Detail }

// ParseRequest parses and validates a DER-encoded TimeStampReq.
func ParseRequest(der []byte) (*TimeStampReq, error) {
	var req TimeStampReq

	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return nil, fmt.Errorf("invalid DER: %w", &RequestError{
			FailureInfo: FailureBadDataFormat,
			Detail:      err.Error(),
		})
	}

	if len(rest) > 0 {
		return nil, &RequestError{FailureInfo: FailureBadDataFormat, Detail: "trailing data"}
	}

	err = validateRequest(&req)
	if err != nil {
		return nil, err
	}

	return &req, nil
}

func validateRequest(req *TimeStampReq) error {
	if req.Version != 1 {
		return &RequestError{FailureInfo: FailureBadDataFormat, Detail: "unsupported version"}
	}

	if req.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDSHA1) {
		return &RequestError{FailureInfo: FailureBadAlg, Detail: "SHA-1 is not permitted per CSBR"}
	}

	expected, ok := hashLength(req.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return &RequestError{FailureInfo: FailureBadAlg, Detail: "unsupported hash algorithm"}
	}

	if len(req.MessageImprint.HashedMessage) != expected {
		return &RequestError{FailureInfo: FailureBadDataFormat, Detail: "hash length mismatch"}
	}

	if len(req.ReqPolicy) > 0 && !req.ReqPolicy.Equal(OIDDefaultPolicy) {
		return &RequestError{FailureInfo: FailureUnacceptedPolicy, Detail: "unsupported policy"}
	}

	if len(req.Extensions) > 0 {
		return &RequestError{FailureInfo: FailureUnacceptedExtension, Detail: "unsupported extension"}
	}

	return nil
}
