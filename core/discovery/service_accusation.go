package discovery

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const serviceAccusationWireVersion byte = 1

var (
	ErrMalformedServiceAccusation = errors.New("malformed service accusation binary payload")
	ErrNilServiceAccusation       = errors.New("service accusation is nil")
	ErrServiceAccAlreadyExists    = errors.New("service accusation already exists")
	ErrInvalidServiceVersion      = errors.New("service accusation version does not match active service version")
	ErrInvalidServiceAccuser      = errors.New("accuser is not predecessor of accused on given service super-overlay ring")
	ErrServiceNotHosted           = errors.New("peer does not host the specified service")
)

// ServiceAccusation is a signed accusation targeting a specific third-party service instance
// (accused, serviceID, serviceVersion) on ringNum of that service's RingSuperOverlay.
// Targeting the per-service Version inside ServiceNote's VersionVectorImmutable
// ensures unrelated services changing on accused never cancel an active accusation.
type ServiceAccusation struct {
	ringNum        uint32
	serviceVersion uint64
	serviceID      string
	accuser        string
	accused        string
	*signature
}

// NewSignedServiceAccusation creates and ECDSA-signs a ServiceAccusation.
func NewSignedServiceAccusation(
	accused, accuser, serviceID string,
	serviceVersion uint64,
	ringNum uint32,
	s signer,
) (*ServiceAccusation, error) {
	if err := ValidateServiceID(serviceID); err != nil {
		return nil, err
	}
	if accused == "" || accuser == "" {
		return nil, errAccusedId
	}
	if s == nil {
		return nil, errNoPrivKey
	}

	acc := &ServiceAccusation{
		ringNum:        ringNum,
		serviceVersion: serviceVersion,
		serviceID:      serviceID,
		accuser:        accuser,
		accused:        accused,
	}
	r, sigS, err := s.Sign(acc.UnsignedBytes())
	if err != nil {
		return nil, fmt.Errorf("sign service accusation: %w", err)
	}
	acc.signature = &signature{r: r, s: sigS}
	return acc, nil
}

func (a *ServiceAccusation) RingNum() uint32 {
	if a == nil {
		return 0
	}
	return a.ringNum
}

func (a *ServiceAccusation) ServiceVersion() uint64 {
	if a == nil {
		return 0
	}
	return a.serviceVersion
}

func (a *ServiceAccusation) ServiceID() string {
	if a == nil {
		return ""
	}
	return a.serviceID
}

func (a *ServiceAccusation) Accuser() string {
	if a == nil {
		return ""
	}
	return a.accuser
}

func (a *ServiceAccusation) Accused() string {
	if a == nil {
		return ""
	}
	return a.accused
}

func (a *ServiceAccusation) Signature() (r, s []byte) {
	if a == nil || a.signature == nil {
		return nil, nil
	}
	return a.signature.r, a.signature.s
}

// UnsignedBytes returns the canonical deterministic binary representation signed by ECDSA
// and hashed by CryptographicIdentity.
func (a *ServiceAccusation) UnsignedBytes() []byte {
	if a == nil {
		return nil
	}
	out := make([]byte, 0, 1+4+8+12+len(a.serviceID)+len(a.accuser)+len(a.accused))
	out = append(out, serviceAccusationWireVersion)
	out = binary.BigEndian.AppendUint32(out, a.ringNum)
	out = binary.BigEndian.AppendUint64(out, a.serviceVersion)
	out = appendUint32Bytes(out, []byte(a.serviceID))
	out = appendUint32Bytes(out, []byte(a.accuser))
	out = appendUint32Bytes(out, []byte(a.accused))
	return out
}

func (a *ServiceAccusation) CryptographicIdentity() []byte {
	return a.UnsignedBytes()
}

// MarshalBinary encodes the signed ServiceAccusation for reconcile.ItemCodec transfer.
func (a *ServiceAccusation) MarshalBinary() ([]byte, error) {
	if a == nil {
		return nil, ErrNilServiceAccusation
	}
	unsigned := a.UnsignedBytes()
	r, s := a.Signature()
	out := make([]byte, 0, len(unsigned)+8+len(r)+len(s))
	out = append(out, unsigned...)
	out = appendUint32Bytes(out, r)
	out = appendUint32Bytes(out, s)
	return out, nil
}

// UnmarshalServiceAccusation decodes a binary ServiceAccusation.
func UnmarshalServiceAccusation(data []byte) (*ServiceAccusation, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("%w: payload too short", ErrMalformedServiceAccusation)
	}
	if data[0] != serviceAccusationWireVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrMalformedServiceAccusation, data[0])
	}
	ringNum := binary.BigEndian.Uint32(data[1:5])
	serviceVersion := binary.BigEndian.Uint64(data[5:13])
	rest := data[13:]

	svcBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: service id: %v", ErrMalformedServiceAccusation, err)
	}
	serviceID := string(svcBytes)
	if err := ValidateServiceID(serviceID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedServiceAccusation, err)
	}
	accuserBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: accuser: %v", ErrMalformedServiceAccusation, err)
	}
	accusedBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: accused: %v", ErrMalformedServiceAccusation, err)
	}
	rBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: signature r: %v", ErrMalformedServiceAccusation, err)
	}
	sBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: signature s: %v", ErrMalformedServiceAccusation, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformedServiceAccusation, len(rest))
	}

	var sig *signature
	if len(rBytes) > 0 || len(sBytes) > 0 {
		sig = &signature{r: rBytes, s: sBytes}
	}
	return &ServiceAccusation{
		ringNum:        ringNum,
		serviceVersion: serviceVersion,
		serviceID:      serviceID,
		accuser:        string(accuserBytes),
		accused:        string(accusedBytes),
		signature:      sig,
	}, nil
}
