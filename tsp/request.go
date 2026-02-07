package tsp

import (
	"encoding/asn1"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// AlgorithmIdentifier represents an X.509 AlgorithmIdentifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters []byte // raw DER of optional parameters
}

// MessageImprint contains a hash algorithm and the hash of the data to be timestamped.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

// Extension represents an X.509 extension.
type Extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

// TimeStampReq represents an RFC 3161 TimeStampReq.
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier
	Nonce          *big.Int
	CertReq        bool
	Extensions     []Extension
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
	req, err := unmarshalRequest(der)
	if err != nil {
		return nil, fmt.Errorf("invalid DER: %w", &RequestError{
			FailureInfo: FailureBadDataFormat,
			Detail:      err.Error(),
		})
	}

	err = validateRequest(req)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func unmarshalRequest(der []byte) (*TimeStampReq, error) {
	input := cryptobyte.String(der)

	var req TimeStampReq
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read SEQUENCE")
	}

	if !input.Empty() {
		return nil, fmt.Errorf("trailing data")
	}

	// version INTEGER
	var version int
	if !seq.ReadASN1Integer(&version) {
		return nil, fmt.Errorf("failed to read version")
	}

	req.Version = version

	// messageImprint SEQUENCE
	var miSeq cryptobyte.String
	if !seq.ReadASN1(&miSeq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read messageImprint")
	}

	// hashAlgorithm AlgorithmIdentifier (SEQUENCE)
	var algSeq cryptobyte.String
	if !miSeq.ReadASN1(&algSeq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read hashAlgorithm")
	}

	if !algSeq.ReadASN1ObjectIdentifier(&req.MessageImprint.HashAlgorithm.Algorithm) {
		return nil, fmt.Errorf("failed to read algorithm OID")
	}

	if !algSeq.Empty() {
		// Read optional parameters as raw bytes
		var params cryptobyte.String
		var tag cbasn1.Tag

		if !algSeq.ReadAnyASN1Element(&params, &tag) {
			return nil, fmt.Errorf("failed to read algorithm parameters")
		}

		req.MessageImprint.HashAlgorithm.Parameters = []byte(params)
	}

	// hashedMessage OCTET STRING
	if !miSeq.ReadASN1Bytes(&req.MessageImprint.HashedMessage, cbasn1.OCTET_STRING) {
		return nil, fmt.Errorf("failed to read hashedMessage")
	}

	// reqPolicy [OPTIONAL] OBJECT IDENTIFIER
	if seq.PeekASN1Tag(cbasn1.OBJECT_IDENTIFIER) {
		if !seq.ReadASN1ObjectIdentifier(&req.ReqPolicy) {
			return nil, fmt.Errorf("failed to read reqPolicy")
		}
	}

	// nonce [OPTIONAL] INTEGER
	if seq.PeekASN1Tag(cbasn1.INTEGER) {
		req.Nonce = new(big.Int)
		if !seq.ReadASN1Integer(req.Nonce) {
			return nil, fmt.Errorf("failed to read nonce")
		}
	}

	// certReq [OPTIONAL] BOOLEAN DEFAULT FALSE
	if seq.PeekASN1Tag(cbasn1.BOOLEAN) {
		if !seq.ReadASN1Boolean(&req.CertReq) {
			return nil, fmt.Errorf("failed to read certReq")
		}
	}

	// extensions [0] IMPLICIT SEQUENCE OF Extension OPTIONAL
	if seq.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()) {
		var extsRaw cryptobyte.String
		if !seq.ReadASN1(&extsRaw, cbasn1.Tag(0).ContextSpecific().Constructed()) {
			return nil, fmt.Errorf("failed to read extensions")
		}

		for !extsRaw.Empty() {
			var extSeq cryptobyte.String
			if !extsRaw.ReadASN1(&extSeq, cbasn1.SEQUENCE) {
				return nil, fmt.Errorf("failed to read extension SEQUENCE")
			}

			var ext Extension
			if !extSeq.ReadASN1ObjectIdentifier(&ext.ID) {
				return nil, fmt.Errorf("failed to read extension OID")
			}

			// critical BOOLEAN DEFAULT FALSE
			if extSeq.PeekASN1Tag(cbasn1.BOOLEAN) {
				if !extSeq.ReadASN1Boolean(&ext.Critical) {
					return nil, fmt.Errorf("failed to read extension critical")
				}
			}

			// value OCTET STRING
			if !extSeq.ReadASN1Bytes(&ext.Value, cbasn1.OCTET_STRING) {
				return nil, fmt.Errorf("failed to read extension value")
			}

			req.Extensions = append(req.Extensions, ext)
		}
	}

	if !seq.Empty() {
		return nil, fmt.Errorf("trailing data in SEQUENCE")
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

// MarshalRequest encodes a TimeStampReq as DER.
func MarshalRequest(req *TimeStampReq) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(req.Version))

		// messageImprint
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addAlgorithmIdentifier(b, req.MessageImprint.HashAlgorithm)
			b.AddASN1OctetString(req.MessageImprint.HashedMessage)
		})

		// reqPolicy
		if len(req.ReqPolicy) > 0 {
			b.AddASN1ObjectIdentifier(req.ReqPolicy)
		}

		// nonce
		if req.Nonce != nil {
			b.AddASN1BigInt(req.Nonce)
		}

		// certReq
		if req.CertReq {
			b.AddASN1Boolean(true)
		}

		// extensions
		if len(req.Extensions) > 0 {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				for _, ext := range req.Extensions {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(ext.ID)
						if ext.Critical {
							b.AddASN1Boolean(true)
						}
						b.AddASN1OctetString(ext.Value)
					})
				}
			})
		}
	})

	return b.Bytes()
}

func addAlgorithmIdentifier(b *cryptobyte.Builder, alg AlgorithmIdentifier) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(alg.Algorithm)
		if len(alg.Parameters) > 0 {
			b.AddBytes(alg.Parameters)
		}
	})
}
