package discovery

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/eika123/ifrit/digestmaps"
)

const (
	// MaxServiceIDLength is the maximum permitted byte length of a service identifier.
	MaxServiceIDLength = 64

	// MaxServicesPerNote caps the number of hosted services in a single ServiceNote
	// to bound wire payloads and memory consumption against Byzantine peers.
	MaxServicesPerNote = 128

	serviceNoteWireVersion byte = 1
)

var (
	ErrInvalidServiceID     = errors.New("invalid service id: must match [a-z0-9._-]{1,64}")
	ErrTooManyServices      = errors.New("service note exceeds maximum service count")
	ErrMalformedServiceNote = errors.New("malformed service note binary payload")
	ErrNilServiceNote       = errors.New("service note is nil")
)

// ValidateServiceID checks that serviceID is non-empty, at most 64 bytes, and contains
// only lowercase ASCII letters, digits, '.', '_', or '-'.
func ValidateServiceID(serviceID string) error {
	if len(serviceID) == 0 || len(serviceID) > MaxServiceIDLength {
		return fmt.Errorf("%w: %q", ErrInvalidServiceID, serviceID)
	}
	for i := range len(serviceID) {
		c := serviceID[i]
		valid := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
		if !valid {
			return fmt.Errorf("%w: %q", ErrInvalidServiceID, serviceID)
		}
	}
	return nil
}

func serviceKeyExtractor(serviceID string) string {
	return serviceID
}

func serviceEntryHasher(vi digestmaps.VersionedItem[string]) digestmaps.DigestSymbol {
	h := sha256.New()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(len(vi.Item)))
	h.Write(buf[:])
	h.Write([]byte(vi.Item))
	binary.BigEndian.PutUint64(buf[:], vi.Version)
	h.Write(buf[:])
	sum := h.Sum(nil)
	return digestmaps.DigestSymbol(binary.BigEndian.Uint64(sum[:8]))
}

// NewServiceVector returns an empty immutable version vector for a node's hosted services.
func NewServiceVector() digestmaps.VersionVectorImmutable[string, string, digestmaps.DigestSymbol] {
	return digestmaps.NewVersionVectorImmutable[string, string, digestmaps.DigestSymbol](
		serviceKeyExtractor,
		serviceEntryHasher,
	)
}

// ServiceNote is a signed, epoch-versioned snapshot of all third-party services
// hosted by a peer, wrapping a VersionVectorImmutable mapping serviceID -> serviceVersion.
// It is the Service Discovery counterpart to Fireflies' host Note.
type ServiceNote struct {
	id        string
	services  digestmaps.VersionVectorImmutable[string, string, digestmaps.DigestSymbol]
	signature *signature
}

// NewSignedServiceNote creates and ECDSA-signs a ServiceNote for peer id.
func NewSignedServiceNote(
	id string,
	services digestmaps.VersionVectorImmutable[string, string, digestmaps.DigestSymbol],
	s signer,
) (*ServiceNote, error) {
	if id == "" {
		return nil, errPeerId
	}
	if services == nil {
		services = NewServiceVector()
	}
	if services.Size() > MaxServicesPerNote {
		return nil, ErrTooManyServices
	}
	if s == nil {
		return nil, errNoPrivKey
	}

	note := &ServiceNote{
		id:       id,
		services: services,
	}
	r, sigS, err := s.Sign(note.UnsignedBytes())
	if err != nil {
		return nil, fmt.Errorf("sign service note: %w", err)
	}
	note.signature = &signature{r: r, s: sigS}
	return note, nil
}

func (n *ServiceNote) Id() string {
	if n == nil {
		return ""
	}
	return n.id
}

func (n *ServiceNote) Epoch() uint64 {
	if n == nil || n.services == nil {
		return 0
	}
	return n.services.Epoch()
}

func (n *ServiceNote) HasService(serviceID string) bool {
	if n == nil || n.services == nil {
		return false
	}
	return n.services.ContainsKey(serviceID)
}

func (n *ServiceNote) ServiceVersion(serviceID string) (uint64, bool) {
	if n == nil || n.services == nil {
		return 0, false
	}
	entry, ok := n.services.GetOne(serviceID)
	if !ok {
		return 0, false
	}
	return entry.Version, true
}

func (n *ServiceNote) Services() map[string]uint64 {
	if n == nil || n.services == nil {
		return nil
	}
	return n.services.Versions()
}

func (n *ServiceNote) Vector() digestmaps.VersionVectorImmutable[string, string, digestmaps.DigestSymbol] {
	if n == nil {
		return nil
	}
	return n.services
}

func (n *ServiceNote) VectorFingerprint() digestmaps.DigestSymbol {
	if n == nil || n.services == nil {
		return 0
	}
	return n.services.Fingerprint()
}

func (n *ServiceNote) Signature() (r, s []byte) {
	if n == nil || n.signature == nil {
		return nil, nil
	}
	return n.signature.r, n.signature.s
}

// UnsignedBytes returns the canonical deterministic binary representation of
// (version, id, epoch, sorted (serviceID, serviceVersion) entries) used for both
// ECDSA signing and CryptographicIdentity SHA-256 hashing.
func (n *ServiceNote) UnsignedBytes() []byte {
	if n == nil {
		return nil
	}
	ordered := digestmaps.OrderedElements[string, string, digestmaps.DigestSymbol](n.services, serviceKeyExtractor)
	out := make([]byte, 0, 1+4+len(n.id)+8+4+len(ordered)*24)
	out = append(out, serviceNoteWireVersion)
	out = appendUint32Bytes(out, []byte(n.id))
	out = binary.BigEndian.AppendUint64(out, n.Epoch())
	out = binary.BigEndian.AppendUint32(out, uint32(len(ordered)))
	for _, entry := range ordered {
		out = appendUint32Bytes(out, []byte(entry.Item))
		out = binary.BigEndian.AppendUint64(out, entry.Version)
	}
	return out
}

// CryptographicIdentity returns the canonical unsigned payload bytes so
// digestmaps.DefaultHasher hashes (id, epoch, canonical entries) with SHA-256
// rather than relying on the linear 64-bit XOR vector fingerprint.
func (n *ServiceNote) CryptographicIdentity() []byte {
	return n.UnsignedBytes()
}

// MarshalBinary encodes the signed ServiceNote for reconcile.ItemCodec transfer.
func (n *ServiceNote) MarshalBinary() ([]byte, error) {
	if n == nil {
		return nil, ErrNilServiceNote
	}
	unsigned := n.UnsignedBytes()
	r, s := n.Signature()
	out := make([]byte, 0, len(unsigned)+8+len(r)+len(s))
	out = append(out, unsigned...)
	out = appendUint32Bytes(out, r)
	out = appendUint32Bytes(out, s)
	return out, nil
}

// UnmarshalServiceNote decodes a binary ServiceNote and reconstructs
// its underlying VersionVectorImmutable with exact wire epoch and fingerprint.
func UnmarshalServiceNote(data []byte) (*ServiceNote, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("%w: empty payload", ErrMalformedServiceNote)
	}
	if data[0] != serviceNoteWireVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrMalformedServiceNote, data[0])
	}
	rest := data[1:]

	idBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: peer id: %v", ErrMalformedServiceNote, err)
	}
	if len(rest) < 12 {
		return nil, fmt.Errorf("%w: truncated epoch/count", ErrMalformedServiceNote)
	}
	epoch := binary.BigEndian.Uint64(rest[:8])
	count := binary.BigEndian.Uint32(rest[8:12])
	rest = rest[12:]
	if count > MaxServicesPerNote {
		return nil, fmt.Errorf("%w: count %d > %d", ErrTooManyServices, count, MaxServicesPerNote)
	}

	items := make([]digestmaps.VersionedItem[string], 0, count)
	for range count {
		svcBytes, next, err := readUint32Bytes(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: service id: %v", ErrMalformedServiceNote, err)
		}
		if len(next) < 8 {
			return nil, fmt.Errorf("%w: truncated service version", ErrMalformedServiceNote)
		}
		svcID := string(svcBytes)
		if err := ValidateServiceID(svcID); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedServiceNote, err)
		}
		ver := binary.BigEndian.Uint64(next[:8])
		rest = next[8:]
		items = append(items, digestmaps.VersionedItem[string]{
			Item:    svcID,
			Version: ver,
		})
	}

	rBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: signature r: %v", ErrMalformedServiceNote, err)
	}
	sBytes, rest, err := readUint32Bytes(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: signature s: %v", ErrMalformedServiceNote, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrMalformedServiceNote, len(rest))
	}

	vv := digestmaps.NewVersionVectorImmutableSnapshot[string, string, digestmaps.DigestSymbol](
		epoch,
		serviceKeyExtractor,
		serviceEntryHasher,
		items...,
	)
	var sig *signature
	if len(rBytes) > 0 || len(sBytes) > 0 {
		sig = &signature{r: rBytes, s: sBytes}
	}
	return &ServiceNote{
		id:        string(idBytes),
		services:  vv,
		signature: sig,
	}, nil
}

func appendUint32Bytes(dst, b []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(b)))
	return append(dst, b...)
}

func readUint32Bytes(src []byte) ([]byte, []byte, error) {
	if len(src) < 4 {
		return nil, nil, errors.New("truncated length prefix")
	}
	n := int(binary.BigEndian.Uint32(src[:4]))
	src = src[4:]
	if n < 0 || len(src) < n {
		return nil, nil, errors.New("truncated field payload")
	}
	out := append([]byte(nil), src[:n]...)
	return out, src[n:], nil
}
