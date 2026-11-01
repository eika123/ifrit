package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/golang/protobuf/proto"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
)

var (
	// ErrNilCodec indicates that a nil ItemCodec was provided where an active codec is required.
	ErrNilCodec = errors.New("reconciler: codec cannot be nil")

	// ErrDigestMismatch indicates that a streamed item's computed digest does not match the expected digest.
	ErrDigestMismatch = errors.New("reconciler: digest mismatch")

	// ErrDecodeFailed indicates that an item failed to decode from the incoming stream.
	ErrDecodeFailed = errors.New("reconciler: failed to decode item")

	// ErrEncodeFailed indicates that an item failed to encode to the outgoing stream.
	ErrEncodeFailed = errors.New("reconciler: failed to encode item")
)

// ItemCodec defines the serialization and deserialization contract for data items
// transferred across the network during set reconciliation bulk streaming.
type ItemCodec[T any] interface {
	Encode(item T, w io.Writer) error
	Decode(r io.Reader) (T, error)
}

type byteSliceCodec struct{}

func (c *byteSliceCodec) Encode(item []byte, w io.Writer) error {
	_, err := w.Write(item)
	return err
}

func (c *byteSliceCodec) Decode(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}

type stringCodec struct{}

func (c *stringCodec) Encode(item string, w io.Writer) error {
	_, err := io.WriteString(w, item)
	return err
}

func (c *stringCodec) Decode(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type protoPtrCodec[T any] struct {
	elemType reflect.Type
}

func (c *protoPtrCodec[T]) Encode(item T, w io.Writer) error {
	msg, ok := any(item).(proto.Message)
	if !ok || msg == nil {
		return errors.New("reconciler: item is not a valid proto.Message")
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func (c *protoPtrCodec[T]) Decode(r io.Reader) (T, error) {
	var zero T
	b, err := io.ReadAll(r)
	if err != nil {
		return zero, err
	}
	val := reflect.New(c.elemType).Interface()
	msg, ok := val.(proto.Message)
	if !ok {
		return zero, errors.New("reconciler: instantiated type does not implement proto.Message")
	}
	if err := proto.Unmarshal(b, msg); err != nil {
		return zero, err
	}
	return val.(T), nil
}

type protoValCodec[T any] struct {
	tType reflect.Type
}

func (c *protoValCodec[T]) Encode(item T, w io.Writer) error {
	msg, ok := any(item).(proto.Message)
	if !ok {
		return errors.New("reconciler: item does not implement proto.Message")
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func (c *protoValCodec[T]) Decode(r io.Reader) (T, error) {
	var zero T
	b, err := io.ReadAll(r)
	if err != nil {
		return zero, err
	}
	ptr := reflect.New(c.tType).Interface()
	msg, ok := ptr.(proto.Message)
	if !ok {
		return zero, errors.New("reconciler: pointer does not implement proto.Message")
	}
	if err := proto.Unmarshal(b, msg); err != nil {
		return zero, err
	}
	return reflect.ValueOf(ptr).Elem().Interface().(T), nil
}

type jsonCodec[T any] struct{}

func (c *jsonCodec[T]) Encode(item T, w io.Writer) error {
	return json.NewEncoder(w).Encode(item)
}

func (c *jsonCodec[T]) Decode(r io.Reader) (T, error) {
	var item T
	if err := json.NewDecoder(r).Decode(&item); err != nil {
		return item, err
	}
	return item, nil
}

// DefaultItemCodec returns the default ItemCodec implementation for type T:
// - []byte: raw byte stream with direct I/O
// - string: UTF-8 string stream
// - proto.Message (or pointer to proto.Message): protobuf wire encoding
// - Arbitrary types/structs: streaming JSON encoder/decoder.
func DefaultItemCodec[T any]() ItemCodec[T] {
	var zero T
	switch any(zero).(type) {
	case []byte:
		return any(&byteSliceCodec{}).(ItemCodec[T])
	case string:
		return any(&stringCodec{}).(ItemCodec[T])
	default:
		tType := reflect.TypeOf(zero)
		protoMsgType := reflect.TypeOf((*proto.Message)(nil)).Elem()
		if tType != nil && tType.Implements(protoMsgType) {
			if tType.Kind() == reflect.Ptr {
				return &protoPtrCodec[T]{elemType: tType.Elem()}
			}
			return &protoValCodec[T]{tType: tType}
		}
		if tType != nil && reflect.PointerTo(tType).Implements(protoMsgType) {
			return &protoValCodec[T]{tType: tType}
		}
		return &jsonCodec[T]{}
	}
}

// DataReconciler provides a type-erased reconciliation interface for arbitrary application data stores.
type DataReconciler interface {
	Digests() []revIdxStore.DigestSymbol
	Fingerprint() revIdxStore.DigestSymbol
	Reconcile(incomingDigests []revIdxStore.DigestSymbol) (localMissingOnCaller, remoteMissingLocally []revIdxStore.DigestSymbol, err error)

	// OpenItemReader retrieves an item by digest and returns an io.ReadCloser for its encoded stream and total size hint.
	// If the item does not exist, it returns (nil, 0, false, nil).
	OpenItemReader(d revIdxStore.DigestSymbol) (rc io.ReadCloser, sizeHint int64, ok bool, err error)

	// IngestItem decodes an item from r, validates that its computed digest equals expected,
	// and inserts it into the underlying store. If the digest mismatches or decoding fails,
	// the store is not modified and an error is returned.
	IngestItem(expected revIdxStore.DigestSymbol, r io.Reader) error
}

type typedDataReconciler[T any] struct {
	store       ReverseIndexStore[T, revIdxStore.DigestSymbol]
	codec       ItemCodec[T]
	constructor SessionConstructor[T, revIdxStore.DigestSymbol]
}

func (r *typedDataReconciler[T]) Digests() []revIdxStore.DigestSymbol {
	if r.store == nil {
		return nil
	}
	return r.store.DigestsCopy()
}

func (r *typedDataReconciler[T]) Fingerprint() revIdxStore.DigestSymbol {
	if r.store == nil {
		return 0
	}
	return r.store.Fingerprint()
}

func (r *typedDataReconciler[T]) Reconcile(incomingDigests []revIdxStore.DigestSymbol) ([]revIdxStore.DigestSymbol, []revIdxStore.DigestSymbol, error) {
	if r.store == nil {
		return nil, nil, ErrNilStore
	}
	session, err := r.constructor(r.store)
	if err != nil {
		return nil, nil, err
	}
	session.ProcessIncomingDigests(incomingDigests)
	return session.LocalDigests(), session.RemoteDigests(), nil
}

func (r *typedDataReconciler[T]) OpenItemReader(d revIdxStore.DigestSymbol) (io.ReadCloser, int64, bool, error) {
	if r.store == nil {
		return nil, 0, false, ErrNilStore
	}
	if r.codec == nil {
		return nil, 0, false, ErrNilCodec
	}
	item, found := r.store.GetByDigest(d)
	if !found {
		return nil, 0, false, nil
	}

	if _, isDefaultBytes := any(r.codec).(*byteSliceCodec); isDefaultBytes {
		b := any(item).([]byte)
		return io.NopCloser(bytes.NewReader(b)), int64(len(b)), true, nil
	}
	if _, isDefaultString := any(r.codec).(*stringCodec); isDefaultString {
		s := any(item).(string)
		return io.NopCloser(strings.NewReader(s)), int64(len(s)), true, nil
	}

	var buf bytes.Buffer
	if err := r.codec.Encode(item, &buf); err != nil {
		return nil, 0, false, fmt.Errorf("%w: %v", ErrEncodeFailed, err)
	}
	return io.NopCloser(bytes.NewReader(buf.Bytes())), int64(buf.Len()), true, nil
}

func (r *typedDataReconciler[T]) IngestItem(expected revIdxStore.DigestSymbol, reader io.Reader) error {
	if r.store == nil {
		return ErrNilStore
	}
	if r.codec == nil {
		return ErrNilCodec
	}
	item, err := r.codec.Decode(reader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDecodeFailed, err)
	}
	actual := r.store.Digest(item)
	if actual != expected {
		return fmt.Errorf("%w: expected %016x, got %016x", ErrDigestMismatch, expected, actual)
	}
	r.store.Insert(item)
	return nil
}

// NewTypedDataReconciler wraps an application's typed store into a DataReconciler
// using DefaultItemCodec[T]() and the configured or default session constructor.
func NewTypedDataReconciler[T any](
	store ReverseIndexStore[T, revIdxStore.DigestSymbol],
	constructor ...SessionConstructor[T, revIdxStore.DigestSymbol],
) DataReconciler {
	return NewTypedDataReconcilerWithCodec(store, DefaultItemCodec[T](), constructor...)
}

// NewTypedDataReconcilerWithCodec wraps an application's typed store into a DataReconciler
// with an explicit ItemCodec[T] and session constructor.
// If codec is nil, DefaultItemCodec[T]() is used.
// If constructor is omitted or nil, it defaults to the configured default session constructor.
func NewTypedDataReconcilerWithCodec[T any](
	store ReverseIndexStore[T, revIdxStore.DigestSymbol],
	codec ItemCodec[T],
	constructor ...SessionConstructor[T, revIdxStore.DigestSymbol],
) DataReconciler {
	if codec == nil {
		codec = DefaultItemCodec[T]()
	}
	var c SessionConstructor[T, revIdxStore.DigestSymbol]
	if len(constructor) > 0 && constructor[0] != nil {
		c = constructor[0]
	} else {
		c = DefaultSessionConstructor[T]()
	}
	return &typedDataReconciler[T]{
		store:       store,
		codec:       codec,
		constructor: c,
	}
}
