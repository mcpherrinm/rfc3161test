package tsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// PKIStatus represents the status of a PKI response per RFC 3161.
type PKIStatus int

// PKIStatus constants per RFC 3161 §2.4.2.
const (
	StatusGranted                PKIStatus = 0
	StatusGrantedWithMods        PKIStatus = 1
	StatusRejection              PKIStatus = 2
	StatusWaiting                PKIStatus = 3
	StatusRevocationWarning      PKIStatus = 4
	StatusRevocationNotification PKIStatus = 5
)

// PKIStatusInfo represents an RFC 3161 PKIStatusInfo.
type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString [][]byte // raw DER elements
	FailInfo     asn1.BitString
}

// ContentInfo represents a CMS ContentInfo structure.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte // raw DER of the content value (inside [0] EXPLICIT)
}

// TimeStampResp represents an RFC 3161 TimeStampResp.
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken *ContentInfo
}

// TSTInfo represents an RFC 3161 TSTInfo.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Nonce          *big.Int
}

// Signer holds the TSA's signing key and certificate.
type Signer struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
}

// ErrTrailingData is returned when a TimeStampResp has trailing bytes.
var ErrTrailingData = errors.New("trailing data in TimeStampResp")

// FailureInfoBitString encodes a PKIFailureInfo bit position as an ASN.1 BIT STRING.
func FailureInfoBitString(bit PKIFailureInfo) asn1.BitString {
	bitLen := int(bit) + 1
	byteLen := (bitLen + 7) / 8
	bytes := make([]byte, byteLen)
	bytes[int(bit)/8] |= 0x80 >> (uint(bit) % 8) //nolint:gosec // bit indexing

	return asn1.BitString{Bytes: bytes, BitLength: bitLen}
}

func addASN1BitStringRaw(b *cryptobyte.Builder, bs asn1.BitString) {
	// BIT STRING: first byte is number of unused bits in last byte
	padding := byte(0)
	if bs.BitLength%8 != 0 {
		padding = byte(8 - bs.BitLength%8)
	}

	b.AddASN1(cbasn1.BIT_STRING, func(b *cryptobyte.Builder) {
		b.AddUint8(padding)
		b.AddBytes(bs.Bytes)
	})
}

// CreateErrorResponse builds a TimeStampResp indicating failure.
func CreateErrorResponse(failure PKIFailureInfo) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// PKIStatusInfo
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(int64(StatusRejection))
			// FailInfo BIT STRING - use raw encoding since BitLength may not be a multiple of 8
			bs := FailureInfoBitString(failure)
			addASN1BitStringRaw(b, bs)
		})
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal error response: %w", err)
	}

	return der, nil
}

// CreateResponse builds a granted TimeStampResp for the given request.
func (signer *Signer) CreateResponse(req *TimeStampReq) ([]byte, error) {
	serial, err := signer.generateSerial()
	if err != nil {
		return nil, err
	}

	tstInfoDER, err := marshalTSTInfo(req, serial)
	if err != nil {
		return nil, err
	}

	token, err := signer.signCMS(tstInfoDER, req.CertReq)
	if err != nil {
		return nil, err
	}

	tokenCI, err := marshalContentInfoBytes(OIDSignedData, token)
	if err != nil {
		return nil, err
	}

	statusDER, err := marshalPKIStatusInfo(StatusGranted, asn1.BitString{}) //nolint:exhaustruct // no FailInfo on success
	if err != nil {
		return nil, err
	}

	// Build response SEQUENCE manually
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(statusDER)
		b.AddBytes(tokenCI)
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	return der, nil
}

func marshalPKIStatusInfo(status PKIStatus, failInfo asn1.BitString) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(status))

		if len(failInfo.Bytes) > 0 {
			addASN1BitStringRaw(b, failInfo)
		}
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal status: %w", err)
	}

	return der, nil
}

func marshalTSTInfo(req *TimeStampReq, serial *big.Int) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1) // version

		b.AddASN1ObjectIdentifier(OIDDefaultPolicy) // policy

		// messageImprint
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addAlgorithmIdentifier(b, req.MessageImprint.HashAlgorithm)
			b.AddASN1OctetString(req.MessageImprint.HashedMessage)
		})

		b.AddASN1BigInt(serial) // serialNumber

		b.AddASN1GeneralizedTime(time.Now().UTC()) // genTime

		// nonce (optional)
		if req.Nonce != nil {
			b.AddASN1BigInt(req.Nonce)
		}
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal TSTInfo: %w", err)
	}

	return der, nil
}

// generateSerial produces a 128-bit serial number. The upper 4 bytes encode the
// number of seconds elapsed since the signing certificate's NotBefore, and the
// lower 12 bytes are cryptographically random.
func (signer *Signer) generateSerial() (*big.Int, error) {
	elapsed := time.Since(signer.Certificate.NotBefore)
	seconds := uint32(elapsed.Seconds())

	var buf [16]byte
	binary.BigEndian.PutUint32(buf[:4], seconds)

	_, err := rand.Read(buf[4:])
	if err != nil {
		return nil, fmt.Errorf("generate serial random bytes: %w", err)
	}

	return new(big.Int).SetBytes(buf[:]), nil
}

func marshalContentInfoBytes(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(contentType)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddBytes(content)
		})
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal content info: %w", err)
	}

	return der, nil
}

func (signer *Signer) signCMS(tstInfoDER []byte, includeCert bool) ([]byte, error) {
	digest := sha256.Sum256(tstInfoDER)

	signedAttrsDER, err := buildSignedAttrsDER(digest[:], signer.Certificate)
	if err != nil {
		return nil, err
	}

	// For signing, the IMPLICIT [0] tag must be replaced with SET (0x31).
	setBytes := make([]byte, len(signedAttrsDER))
	copy(setBytes, signedAttrsDER)
	setBytes[0] = 0x31

	attrDigest := sha256.Sum256(setBytes)

	signature, err := rsa.SignPKCS1v15(rand.Reader, signer.Key, crypto.SHA256, attrDigest[:])
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	siDER, err := marshalSignerInfo(signer, signedAttrsDER, signature)
	if err != nil {
		return nil, err
	}

	return marshalSignedData(tstInfoDER, siDER, signer.Certificate, includeCert)
}

func marshalSignerInfo(signer *Signer, signedAttrsDER, signature []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1) // version

		// SID: issuerAndSerialNumber
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(signer.Certificate.RawIssuer) // issuer (pre-encoded)
			b.AddASN1BigInt(signer.Certificate.SerialNumber)
		})

		// digestAlgorithm
		addAlgorithmIdentifier(b, AlgorithmIdentifier{Algorithm: OIDSHA256})

		// signedAttrs [0] IMPLICIT
		b.AddBytes(signedAttrsDER)

		// signatureAlgorithm
		addAlgorithmIdentifier(b, AlgorithmIdentifier{Algorithm: OIDRSASHA256})

		// signature OCTET STRING
		b.AddASN1OctetString(signature)
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal signer info: %w", err)
	}

	return der, nil
}

func marshalSignedData(tstInfoDER, siDER []byte, cert *x509.Certificate, includeCert bool) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3) // version

		// digestAlgorithms SET
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			addAlgorithmIdentifier(b, AlgorithmIdentifier{Algorithm: OIDSHA256})
		})

		// encapContentInfo
		addEncapContentInfo(b, tstInfoDER)

		// certificates [0] IMPLICIT (optional)
		if includeCert {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddBytes(cert.Raw)
			})
		}

		// signerInfos SET
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddBytes(siDER)
		})
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}

	return der, nil
}

func addEncapContentInfo(b *cryptobyte.Builder, tstInfoDER []byte) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDTSTInfo)
		b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(tstInfoDER)
		})
	})
}

func buildSignedAttrsDER(digest []byte, cert *x509.Certificate) ([]byte, error) {
	// Build individual attribute SEQUENCEs
	contentTypeAttr, err := marshalAttrBytes(OIDAttributeContentType, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDTSTInfo)
	})
	if err != nil {
		return nil, err
	}

	digestAttr, err := marshalAttrBytes(OIDAttributeMessageDigest, func(b *cryptobyte.Builder) {
		b.AddASN1OctetString(digest)
	})
	if err != nil {
		return nil, err
	}

	sigCertV2Attr, err := buildSigningCertificateV2Attr(cert)
	if err != nil {
		return nil, err
	}

	// Wrap in [0] IMPLICIT (context-specific constructed, tag 0)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
		b.AddBytes(contentTypeAttr)
		b.AddBytes(digestAttr)
		b.AddBytes(sigCertV2Attr)
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal signed attrs: %w", err)
	}

	return der, nil
}

// buildSigningCertificateV2Attr builds the SigningCertificateV2 signed attribute per RFC 5816.
func buildSigningCertificateV2Attr(cert *x509.Certificate) ([]byte, error) {
	certHash := sha256.Sum256(cert.Raw)

	return marshalAttrBytes(OIDSigningCertificateV2, func(b *cryptobyte.Builder) {
		// SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2 }
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			// SEQUENCE OF ESSCertIDv2 (one entry)
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				// ESSCertIDv2 ::= SEQUENCE {
				//   hashAlgorithm  AlgorithmIdentifier DEFAULT {sha-256},
				//   certHash       OCTET STRING,
				//   issuerSerial   IssuerSerial OPTIONAL }

				// hashAlgorithm omitted (default SHA-256)
				b.AddASN1OctetString(certHash[:])

				// issuerSerial SEQUENCE
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					// issuer GeneralNames (SEQUENCE OF GeneralName)
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						// directoryName [4] EXPLICIT
						b.AddASN1(cbasn1.Tag(4).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
							b.AddBytes(cert.RawIssuer)
						})
					})
					// serialNumber INTEGER
					b.AddASN1BigInt(cert.SerialNumber)
				})
			})
		})
	})
}

func marshalAttrBytes(oid asn1.ObjectIdentifier, valueFn func(b *cryptobyte.Builder)) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			valueFn(b)
		})
	})

	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("marshal attribute: %w", err)
	}

	return der, nil
}

// ParseResponse parses a DER-encoded TimeStampResp.
func ParseResponse(der []byte) (*TimeStampResp, error) {
	input := cryptobyte.String(der)

	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("unmarshal TimeStampResp: failed to read SEQUENCE")
	}

	if !input.Empty() {
		return nil, ErrTrailingData
	}

	var resp TimeStampResp

	// Parse PKIStatusInfo
	var statusSeq cryptobyte.String
	if !seq.ReadASN1(&statusSeq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("unmarshal TimeStampResp: failed to read PKIStatusInfo")
	}

	var statusVal int
	if !statusSeq.ReadASN1Integer(&statusVal) {
		return nil, fmt.Errorf("unmarshal TimeStampResp: failed to read status")
	}

	resp.Status.Status = PKIStatus(statusVal)

	// Optional: statusString (SEQUENCE OF UTF8String) - skip if present
	if statusSeq.PeekASN1Tag(cbasn1.SEQUENCE) {
		var statusStrSeq cryptobyte.String
		if !statusSeq.ReadASN1(&statusStrSeq, cbasn1.SEQUENCE) {
			return nil, fmt.Errorf("unmarshal TimeStampResp: failed to read statusString")
		}
	}

	// Optional: failInfo BIT STRING
	if statusSeq.PeekASN1Tag(cbasn1.BIT_STRING) {
		if !statusSeq.ReadASN1BitString(&resp.Status.FailInfo) {
			return nil, fmt.Errorf("unmarshal TimeStampResp: failed to read failInfo")
		}
	}

	// Optional: TimeStampToken (ContentInfo SEQUENCE)
	if seq.PeekASN1Tag(cbasn1.SEQUENCE) {
		ci, err := parseContentInfo(&seq)
		if err != nil {
			return nil, fmt.Errorf("unmarshal TimeStampResp: %w", err)
		}

		resp.TimeStampToken = ci
	}

	return &resp, nil
}

func parseContentInfo(s *cryptobyte.String) (*ContentInfo, error) {
	var ciSeq cryptobyte.String
	if !s.ReadASN1(&ciSeq, cbasn1.SEQUENCE) {
		return nil, fmt.Errorf("failed to read ContentInfo SEQUENCE")
	}

	var ci ContentInfo
	if !ciSeq.ReadASN1ObjectIdentifier(&ci.ContentType) {
		return nil, fmt.Errorf("failed to read ContentInfo OID")
	}

	// [0] EXPLICIT content
	var content cryptobyte.String
	if !ciSeq.ReadASN1(&content, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, fmt.Errorf("failed to read ContentInfo content")
	}

	ci.Content = []byte(content)

	return &ci, nil
}
