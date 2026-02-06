package tsp

import (
	"encoding/asn1"
	"math/big"
	"time"
)

type PKIStatus int

const (
	StatusGranted                PKIStatus = 0
	StatusGrantedWithMods        PKIStatus = 1
	StatusRejection              PKIStatus = 2
	StatusWaiting                PKIStatus = 3
	StatusRevocationWarning      PKIStatus = 4
	StatusRevocationNotification PKIStatus = 5
)

type PKIStatusInfo struct {
	Status       PKIStatus
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken ContentInfo `asn1:"optional"`
}

type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Accuracy       Accuracy  `asn1:"optional"`
	Ordering       bool      `asn1:"optional,default:false"`
	Nonce          *big.Int  `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     []Extension   `asn1:"optional,tag:1"`
}

type Accuracy struct {
	Seconds *int `asn1:"optional"`
	Millis  *int `asn1:"optional,tag:0"`
	Micros  *int `asn1:"optional,tag:1"`
}

func FailureInfoBitString(bit PKIFailureInfo) asn1.BitString {
	bitLen := int(bit) + 1
	byteLen := (bitLen + 7) / 8
	bytes := make([]byte, byteLen)
	bytes[int(bit)/8] |= 0x80 >> (uint(bit) % 8)
	return asn1.BitString{Bytes: bytes, BitLength: bitLen}
}
