package tsp

import (
	"encoding/asn1"
	"math/big"
)

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional,default:false"`
	Value    []byte
}

type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []Extension           `asn1:"optional,tag:0"`
}

type PKIFailureInfo int

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

type RequestError struct {
	FailureInfo PKIFailureInfo
	Detail      string
}

func (e *RequestError) Error() string { return e.Detail }

func ParseRequest(der []byte) (*TimeStampReq, error) {
	var req TimeStampReq
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return nil, &RequestError{FailureBadDataFormat, "invalid DER: " + err.Error()}
	}
	if len(rest) > 0 {
		return nil, &RequestError{FailureBadDataFormat, "trailing data"}
	}
	if err := validateRequest(&req); err != nil {
		return nil, err
	}
	return &req, nil
}

func validateRequest(req *TimeStampReq) error {
	if req.Version != 1 {
		return &RequestError{FailureBadDataFormat, "unsupported version"}
	}
	expected, ok := hashLength(req.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return &RequestError{FailureBadAlg, "unsupported hash algorithm"}
	}
	if len(req.MessageImprint.HashedMessage) != expected {
		return &RequestError{FailureBadDataFormat, "hash length mismatch"}
	}
	if len(req.ReqPolicy) > 0 && !req.ReqPolicy.Equal(OIDDefaultPolicy) {
		return &RequestError{FailureUnacceptedPolicy, "unsupported policy"}
	}
	for range req.Extensions {
		return &RequestError{FailureUnacceptedExtension, "unsupported extension"}
	}
	return nil
}
