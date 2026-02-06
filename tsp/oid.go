// Package tsp implements RFC 3161 Time-Stamp Protocol types and logic.
package tsp

import "encoding/asn1"

var (
	OIDSignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDTSTInfo     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	OIDSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDefaultPolicy = asn1.ObjectIdentifier{1, 2, 3, 4, 1}
)

var hashLengths = map[string]int{
	OIDSHA256.String(): 32,
	OIDSHA384.String(): 48,
	OIDSHA512.String(): 64,
}

func hashLength(oid asn1.ObjectIdentifier) (int, bool) {
	l, ok := hashLengths[oid.String()]
	return l, ok
}
