package tsp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
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
	resp := TimeStampResp{
		Status: PKIStatusInfo{
			Status:   StatusRejection,
			FailInfo: FailureInfoBitString(failure),
		},
	}

	return asn1.Marshal(resp)
}

// CreateResponse builds a granted TimeStampResp for the given request.
func (s *Signer) CreateResponse(req *TimeStampReq) ([]byte, error) {
	serial := s.serial.Add(1)

	tstInfo := TSTInfo{
		Version:        1,
		Policy:         OIDDefaultPolicy,
		MessageImprint: req.MessageImprint,
		SerialNumber:   big.NewInt(serial),
		GenTime:        time.Now().UTC(),
		Nonce:          req.Nonce,
	}

	tstInfoDER, err := asn1.Marshal(tstInfo)
	if err != nil {
		return nil, err
	}

	token, err := s.signCMS(tstInfoDER, req.CertReq)
	if err != nil {
		return nil, err
	}

	tokenCI, err := marshalContentInfo(OIDSignedData, token)
	if err != nil {
		return nil, err
	}

	statusDER, err := asn1.Marshal(PKIStatusInfo{Status: StatusGranted})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      append(statusDER, tokenCI...),
	})
}

func marshalContentInfo(contentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(contentType)
	if err != nil {
		return nil, err
	}

	explicitDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      content,
	})
	if err != nil {
		return nil, err
	}

	inner := append(oidDER, explicitDER...)

	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      inner,
	})
}

func (s *Signer) signCMS(tstInfoDER []byte, includeCert bool) ([]byte, error) {
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

	sig, err := rsa.SignPKCS1v15(rand.Reader, s.Key, crypto.SHA256, attrDigest[:])
	if err != nil {
		return nil, err
	}

	siDER, err := marshalSignerInfo(s, signedAttrsDER, sig)
	if err != nil {
		return nil, err
	}

	return marshalSignedData(tstInfoDER, siDER, s.Certificate, includeCert)
}

func marshalSignerInfo(s *Signer, signedAttrsDER, sig []byte) ([]byte, error) {
	versionDER, err := asn1.Marshal(1)
	if err != nil {
		return nil, err
	}

	sidDER, err := asn1.Marshal(issuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: s.Certificate.RawIssuer}, //nolint:exhaustruct // raw DER
		SerialNumber: s.Certificate.SerialNumber,
	})
	if err != nil {
		return nil, err
	}

	digestAlgDER, err := asn1.Marshal(AlgorithmIdentifier{Algorithm: OIDSHA256})
	if err != nil {
		return nil, err
	}

	sigAlgDER, err := asn1.Marshal(AlgorithmIdentifier{Algorithm: OIDRSASHA256})
	if err != nil {
		return nil, err
	}

	sigDER, err := asn1.Marshal(sig)
	if err != nil {
		return nil, err
	}

	inner := concat(versionDER, sidDER, digestAlgDER, signedAttrsDER, sigAlgDER, sigDER)

	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	}) //nolint:exhaustruct // raw SEQUENCE
}

func marshalSignedData(tstInfoDER, siDER []byte, cert *x509.Certificate, includeCert bool) ([]byte, error) {
	versionDER, err := asn1.Marshal(3) //nolint:mnd // CMS SignedData version
	if err != nil {
		return nil, err
	}

	digestAlgDER, err := asn1.Marshal(AlgorithmIdentifier{Algorithm: OIDSHA256})
	if err != nil {
		return nil, err
	}

	digestAlgSetDER, err := asn1.Marshal(asn1.RawValue{
		Tag: asn1.TagSet, IsCompound: true, Bytes: digestAlgDER,
	}) //nolint:exhaustruct // raw SET
	if err != nil {
		return nil, err
	}

	eciDER, err := marshalEncapContentInfo(tstInfoDER)
	if err != nil {
		return nil, err
	}

	siSetDER, err := asn1.Marshal(asn1.RawValue{
		Tag: asn1.TagSet, IsCompound: true, Bytes: siDER,
	}) //nolint:exhaustruct // raw SET
	if err != nil {
		return nil, err
	}

	inner := concat(versionDER, digestAlgSetDER, eciDER)

	if includeCert {
		certsDER, err := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert.Raw,
		}) //nolint:exhaustruct // IMPLICIT [0]
		if err != nil {
			return nil, err
		}

		inner = append(inner, certsDER...)
	}

	inner = append(inner, siSetDER...)

	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	}) //nolint:exhaustruct // raw SEQUENCE
}

func marshalEncapContentInfo(tstInfoDER []byte) ([]byte, error) {
	oidDER, err := asn1.Marshal(OIDTSTInfo)
	if err != nil {
		return nil, err
	}

	octetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: tstInfoDER,
	}) //nolint:exhaustruct // OCTET STRING
	if err != nil {
		return nil, err
	}

	explicitDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: octetDER,
	}) //nolint:exhaustruct // [0] EXPLICIT
	if err != nil {
		return nil, err
	}

	inner := append(oidDER, explicitDER...)

	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner,
	}) //nolint:exhaustruct // SEQUENCE
}

func buildSignedAttrsDER(digest []byte) ([]byte, error) {
	contentTypeAttr, err := marshalAttr(OIDAttributeContentType, OIDTSTInfo)
	if err != nil {
		return nil, err
	}

	digestAttr, err := marshalAttr(OIDAttributeMessageDigest, asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: digest,
	}) //nolint:exhaustruct // OCTET STRING
	if err != nil {
		return nil, err
	}

	combined := append(contentTypeAttr, digestAttr...)

	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: combined,
	}) //nolint:exhaustruct // IMPLICIT [0]
}

func marshalAttr(oid asn1.ObjectIdentifier, value interface{}) ([]byte, error) {
	valDER, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}

	attr := attribute{
		Type: oid,
		Values: asn1.RawValue{
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      valDER,
		}, //nolint:exhaustruct // raw SET
	}

	return asn1.Marshal(attr)
}

func concat(slices ...[]byte) []byte {
	var out []byte
	for _, s := range slices {
		out = append(out, s...)
	}

	return out
}

// ParseResponse parses a DER-encoded TimeStampResp.
func ParseResponse(der []byte) (*TimeStampResp, error) {
	var resp TimeStampResp

	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return nil, err
	}

	if len(rest) > 0 {
		return nil, errors.New("trailing data in TimeStampResp")
	}

	return &resp, nil
}
