// Package tsp implements RFC 3161 Time-Stamp Protocol types and logic.
package tsp

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
)

//nolint:gochecknoglobals // OIDs are effectively constants; Go lacks const support for slices.
var (
	// OIDSignedData is the OID for CMS SignedData (1.2.840.113549.1.7.2).
	OIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// OIDTSTInfo is the OID for id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
	OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	// OIDSHA256 is the OID for SHA-256.
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	// OIDSHA384 is the OID for SHA-384.
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	// OIDSHA512 is the OID for SHA-512.
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	// OIDSHA1 is the OID for SHA-1, which is rejected per CSBR §6.8.
	OIDSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	// OIDDefaultPolicy is the CA/Browser Forum Timestamp policy OID per CSBR §1.2.2.
	OIDDefaultPolicy = asn1.ObjectIdentifier{2, 23, 140, 1, 4, 2}
	// OIDExtKeyUsageTimeStamping is the id-kp-timeStamping OID per RFC 5280.
	OIDExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	// OIDAttributeContentType is the OID for the content-type attribute.
	OIDAttributeContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	// OIDAttributeMessageDigest is the OID for the message-digest attribute.
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	// OIDRSASHA256 is the OID for sha256WithRSAEncryption.
	OIDRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	// OIDSigningCertificateV2 is the OID for id-aa-signingCertificateV2 (RFC 5816 / RFC 5035).
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
)

//nolint:gochecknoglobals // lookup table for hash digest sizes
var hashLengths = map[string]int{
	OIDSHA256.String(): sha256.Size,
	OIDSHA384.String(): sha512.Size384,
	OIDSHA512.String(): sha512.Size,
}

func hashLength(oid asn1.ObjectIdentifier) (int, bool) {
	l, ok := hashLengths[oid.String()]

	return l, ok
}
