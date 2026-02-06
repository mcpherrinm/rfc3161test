package tsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"
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
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

// ContentInfo represents a CMS ContentInfo structure.
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// TimeStampResp represents an RFC 3161 TimeStampResp.
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken ContentInfo `asn1:"optional"`
}

// TSTInfo represents an RFC 3161 TSTInfo.
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Accuracy       Accuracy      `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     []Extension   `asn1:"optional,tag:1"`
}

// Accuracy represents the accuracy of a TSTInfo genTime.
type Accuracy struct {
	Seconds *int `asn1:"optional"`
	Millis  *int `asn1:"optional,tag:0"`
	Micros  *int `asn1:"optional,tag:1"`
}

// issuerAndSerialNumber identifies a certificate by issuer DN and serial number.
type issuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// attribute represents a CMS attribute (SET OF values keyed by OID).
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// signerInfo represents a CMS SignerInfo.
type signerInfo struct {
	Version            int
	SID                issuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue       `asn1:"optional,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
}

// signedData represents a CMS SignedData structure.
type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

// encapContentInfo represents a CMS EncapsulatedContentInfo.
type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// Signer holds the TSA's signing key and certificate.
type Signer struct {
	Key         *rsa.PrivateKey
	Certificate *x509.Certificate
	serial      atomic.Int64
}

// ErrTrailingData is returned when a TimeStampResp has trailing bytes.
var ErrTrailingData = errors.New("trailing data in TimeStampResp")

//nolint:gochecknoglobals // reusable algorithm identifiers
var algSHA256 = AlgorithmIdentifier{
	Algorithm:  OIDSHA256,
	Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
}

//nolint:gochecknoglobals // reusable algorithm identifiers
var algRSASHA256 = AlgorithmIdentifier{
	Algorithm:  OIDRSASHA256,
	Parameters: asn1.RawValue{}, //nolint:exhaustruct // optional ASN.1 field
}

// FailureInfoBitString encodes a PKIFailureInfo bit position as an ASN.1 BIT STRING.
func FailureInfoBitString(bit PKIFailureInfo) asn1.BitString {
	bitLen := int(bit) + 1
	byteLen := (bitLen + 7) / 8 //nolint:mnd // bit-to-byte conversion
	bytes := make([]byte, byteLen)
	bytes[int(bit)/8] |= 0x80 >> (uint(bit) % 8) //nolint:mnd,gosec // bit indexing

	return asn1.BitString{Bytes: bytes, BitLength: bitLen}
}

// CreateErrorResponse builds a TimeStampResp indicating failure.
func CreateErrorResponse(failure PKIFailureInfo) ([]byte, error) {
	resp := TimeStampResp{ //nolint:exhaustruct // no token on failure
		Status: PKIStatusInfo{
			Status:       StatusRejection,
			StatusString: nil,
			FailInfo:     FailureInfoBitString(failure),
		},
	}

	der, err := asn1.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal error response: %w", err)
	}

	return der, nil
}

// CreateResponse builds a granted TimeStampResp for the given request.
func (signer *Signer) CreateResponse(req *TimeStampReq) ([]byte, error) {
	serial := signer.serial.Add(1)

	tstInfo := TSTInfo{ //nolint:exhaustruct // optional fields left zero
		Version:        1,
		Policy:         OIDDefaultPolicy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   big.NewInt(serial),
		GenTime:        time.Now().UTC(),
		Nonce:          req.Nonce,
	}

	tstInfoDER, err := asn1.Marshal(tstInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal TSTInfo: %w", err)
	}

	token, err := signer.signCMS(tstInfoDER, req.CertReq)
	if err != nil {
		return nil, err
	}

	tokenCI, err := marshalContentInfo(OIDSignedData, token)
	if err != nil {
		return nil, err
	}

	statusDER, err := asn1.Marshal(PKIStatusInfo{ //nolint:exhaustruct // success has no FailInfo
		Status:       StatusGranted,
		StatusString: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal status: %w", err)
	}

	respBytes := concat(statusDER, tokenCI)

	der, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SEQUENCE
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      respBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	return der, nil
}

func marshalContentInfo(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, fmt.Errorf("marshal content type OID: %w", err)
	}

	explicitDER, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER [0] EXPLICIT
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal explicit tag: %w", err)
	}

	inner := concat(oidDER, explicitDER)

	der, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SEQUENCE
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      inner,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal content info: %w", err)
	}

	return der, nil
}

func (signer *Signer) signCMS(tstInfoDER []byte, includeCert bool) ([]byte, error) {
	digest := sha256.Sum256(tstInfoDER)

	signedAttrsDER, err := buildSignedAttrsDER(digest[:])
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
	versionDER, err := asn1.Marshal(1)
	if err != nil {
		return nil, fmt.Errorf("marshal version: %w", err)
	}

	sidDER, err := asn1.Marshal(issuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: signer.Certificate.RawIssuer}, //nolint:exhaustruct // raw DER
		SerialNumber: signer.Certificate.SerialNumber,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal SID: %w", err)
	}

	digestAlgDER, err := asn1.Marshal(algSHA256)
	if err != nil {
		return nil, fmt.Errorf("marshal digest algorithm: %w", err)
	}

	sigAlgDER, err := asn1.Marshal(algRSASHA256)
	if err != nil {
		return nil, fmt.Errorf("marshal signature algorithm: %w", err)
	}

	sigDER, err := asn1.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("marshal signature: %w", err)
	}

	inner := concat(versionDER, sidDER, digestAlgDER, signedAttrsDER, sigAlgDER, sigDER)

	der, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SEQUENCE
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signer info: %w", err)
	}

	return der, nil
}

func marshalSignedData(tstInfoDER, siDER []byte, cert *x509.Certificate, includeCert bool) ([]byte, error) {
	versionDER, err := asn1.Marshal(3) //nolint:mnd // CMS SignedData version
	if err != nil {
		return nil, fmt.Errorf("marshal version: %w", err)
	}

	digestAlgDER, err := asn1.Marshal(algSHA256)
	if err != nil {
		return nil, fmt.Errorf("marshal digest algorithm: %w", err)
	}

	digestAlgSetDER, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SET
		Tag: asn1.TagSet, IsCompound: true, Bytes: digestAlgDER,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal digest algorithm set: %w", err)
	}

	eciDER, err := marshalEncapContentInfo(tstInfoDER)
	if err != nil {
		return nil, err
	}

	siSetDER, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SET
		Tag: asn1.TagSet, IsCompound: true, Bytes: siDER,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signer info set: %w", err)
	}

	inner := concat(versionDER, digestAlgSetDER, eciDER)

	if includeCert {
		certsDER, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER IMPLICIT [0]
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal certificates: %w", err)
		}

		inner = append(inner, certsDER...)
	}

	inner = append(inner, siSetDER...)

	der, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SEQUENCE
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signed data: %w", err)
	}

	return der, nil
}

func marshalEncapContentInfo(tstInfoDER []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(OIDTSTInfo)
	if err != nil {
		return nil, fmt.Errorf("marshal OID: %w", err)
	}

	octetDER, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER OCTET STRING
		Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: tstInfoDER,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal octet string: %w", err)
	}

	explicitDER, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER [0] EXPLICIT
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octetDER,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal explicit tag: %w", err)
	}

	inner := concat(oidDER, explicitDER)

	der, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER SEQUENCE
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal encap content info: %w", err)
	}

	return der, nil
}

func buildSignedAttrsDER(digest []byte) ([]byte, error) {
	contentTypeAttr, err := marshalAttr(OIDAttributeContentType, OIDTSTInfo)
	if err != nil {
		return nil, err
	}

	digestOctet := asn1.RawValue{ //nolint:exhaustruct // manual DER OCTET STRING
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagOctetString,
		Bytes: digest,
	}

	digestAttr, err := marshalAttr(OIDAttributeMessageDigest, digestOctet)
	if err != nil {
		return nil, err
	}

	combined := concat(contentTypeAttr, digestAttr)

	der, err := asn1.Marshal(asn1.RawValue{ //nolint:exhaustruct // manual DER IMPLICIT [0]
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: combined,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal signed attrs: %w", err)
	}

	return der, nil
}

func marshalAttr(oid asn1.ObjectIdentifier, value any) ([]byte, error) {
	valDER, err := asn1.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal attr value: %w", err)
	}

	attr := attribute{
		Type: oid,
		Values: asn1.RawValue{ //nolint:exhaustruct // manual DER SET
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      valDER,
		},
	}

	der, err := asn1.Marshal(attr)
	if err != nil {
		return nil, fmt.Errorf("marshal attribute: %w", err)
	}

	return der, nil
}

func concat(slices ...[]byte) []byte {
	total := 0
	for _, slice := range slices {
		total += len(slice)
	}

	out := make([]byte, 0, total)
	for _, slice := range slices {
		out = append(out, slice...)
	}

	return out
}

// ParseResponse parses a DER-encoded TimeStampResp.
func ParseResponse(der []byte) (*TimeStampResp, error) {
	var resp TimeStampResp

	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TimeStampResp: %w", err)
	}

	if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return &resp, nil
}
