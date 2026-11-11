package pki

import "encoding/asn1"

// RingNumberOid is the custom ASN.1 ObjectIdentifier used to embed
// the ring count in X.509 certificates.
var RingNumberOid asn1.ObjectIdentifier = []int{2, 5, 13, 37}
