package core

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	pb "github.com/joonnna/ifrit/protobuf"
	revIdxStore "github.com/joonnna/ifrit/reverseindexstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPayload struct {
	Name  string   `json:"name"`
	Count int      `json:"count"`
	Tags  []string `json:"tags"`
}

func (p testPayload) CryptographicIdentity() []byte {
	return fmt.Appendf(nil, "%s:%d", p.Name, p.Count)
}

func TestDefaultItemCodec_ByteSlice(t *testing.T) {
	codec := DefaultItemCodec[[]byte]()
	require.NotNil(t, codec)

	cases := [][]byte{
		[]byte("hello world"),
		{},
		{0x00, 0x01, 0xfe, 0xff, 0x42},
	}

	for _, original := range cases {
		var buf bytes.Buffer
		err := codec.Encode(original, &buf)
		require.NoError(t, err)

		decoded, err := codec.Decode(&buf)
		require.NoError(t, err)
		assert.Equal(t, original, decoded)
	}
}

func TestDefaultItemCodec_String(t *testing.T) {
	codec := DefaultItemCodec[string]()
	require.NotNil(t, codec)

	cases := []string{
		"standard string",
		"",
		"UTF-8 string: 🚀 こんにちは мир",
	}

	for _, original := range cases {
		var buf bytes.Buffer
		err := codec.Encode(original, &buf)
		require.NoError(t, err)

		decoded, err := codec.Decode(&buf)
		require.NoError(t, err)
		assert.Equal(t, original, decoded)
	}
}

func TestDefaultItemCodec_ProtoMessage(t *testing.T) {
	codec := DefaultItemCodec[*pb.Note]()
	require.NotNil(t, codec)

	original := &pb.Note{
		Id:    []byte("node-1"),
		Epoch: 42,
		Mask:  7,
	}

	var buf bytes.Buffer
	err := codec.Encode(original, &buf)
	require.NoError(t, err)

	decoded, err := codec.Decode(&buf)
	require.NoError(t, err)
	assert.True(t, proto.Equal(original, decoded))
}

func TestDefaultItemCodec_JSON(t *testing.T) {
	codec := DefaultItemCodec[testPayload]()
	require.NotNil(t, codec)

	original := testPayload{
		Name:  "dataset-alpha",
		Count: 12345,
		Tags:  []string{"fast", "reconcile", "sync"},
	}

	var buf bytes.Buffer
	err := codec.Encode(original, &buf)
	require.NoError(t, err)

	decoded, err := codec.Decode(&buf)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestTypedDataReconciler_OpenItemReader_And_IngestItem(t *testing.T) {
	store, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[[]byte]())
	require.NoError(t, err)

	reconciler := NewTypedDataReconciler(store)
	require.NotNil(t, reconciler)

	itemA := []byte("element-alpha-payload")
	itemB := []byte("element-bravo-payload")

	digestA, added := store.Insert(itemA)
	require.True(t, added)

	digestB := store.Digest(itemB)

	// 1. OpenItemReader for existing item
	rc, sizeHint, ok, err := reconciler.OpenItemReader(digestA)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, rc)
	defer rc.Close()

	readBytes, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, int64(len(readBytes)), sizeHint)
	assert.Equal(t, itemA, readBytes)

	// 2. OpenItemReader for non-existing item
	missingRc, missingSize, missingOk, missingErr := reconciler.OpenItemReader(digestB)
	require.NoError(t, missingErr)
	assert.False(t, missingOk)
	assert.Nil(t, missingRc)
	assert.Equal(t, int64(0), missingSize)

	// 3. IngestItem success
	err = reconciler.IngestItem(digestB, bytes.NewReader(itemB))
	require.NoError(t, err)

	assert.Equal(t, 2, store.Size())
	storedItem, found := store.GetByDigest(digestB)
	require.True(t, found)
	assert.Equal(t, itemB, storedItem)

	// 4. IngestItem digest mismatch
	bogusExpected := digestB ^ 0xdeadbeef
	itemC := []byte("element-charlie-payload")
	err = reconciler.IngestItem(bogusExpected, bytes.NewReader(itemC))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDigestMismatch))
	assert.Equal(t, 2, store.Size(), "store must not be mutated on digest mismatch")

	// 5. IngestItem decode failure
	errReader := &failingReader{err: io.ErrUnexpectedEOF}
	err = reconciler.IngestItem(digestB, errReader)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDecodeFailed))
}

func TestTypedDataReconciler_StringAndJSONStores(t *testing.T) {
	t.Run("string store", func(t *testing.T) {
		store, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
		require.NoError(t, err)

		reconciler := NewTypedDataReconciler(store)
		item := "reconcile-string-stream"
		d, _ := store.Insert(item)

		rc, sizeHint, ok, err := reconciler.OpenItemReader(d)
		require.NoError(t, err)
		require.True(t, ok)
		defer rc.Close()

		readBytes, err := io.ReadAll(rc)
		require.NoError(t, err)
		assert.Equal(t, int64(len(item)), sizeHint)
		assert.Equal(t, item, string(readBytes))
	})

	t.Run("json struct store", func(t *testing.T) {
		store, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[testPayload]())
		require.NoError(t, err)

		reconciler := NewTypedDataReconciler(store)
		item := testPayload{Name: "data1", Count: 100, Tags: []string{"tag1"}}
		d := store.Digest(item)

		var buf bytes.Buffer
		err = DefaultItemCodec[testPayload]().Encode(item, &buf)
		require.NoError(t, err)

		err = reconciler.IngestItem(d, &buf)
		require.NoError(t, err)
		assert.Equal(t, 1, store.Size())

		rc, sizeHint, ok, err := reconciler.OpenItemReader(d)
		require.NoError(t, err)
		require.True(t, ok)
		defer rc.Close()

		readBytes, err := io.ReadAll(rc)
		require.NoError(t, err)
		assert.Equal(t, int64(len(readBytes)), sizeHint)

		decoded, err := DefaultItemCodec[testPayload]().Decode(bytes.NewReader(readBytes))
		require.NoError(t, err)
		assert.Equal(t, item, decoded)
	})
}

type prefixCodec struct{}

func (c *prefixCodec) Encode(item string, w io.Writer) error {
	_, err := io.WriteString(w, "PREFIX:"+item)
	return err
}

func (c *prefixCodec) Decode(r io.Reader) (string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	s := string(b)
	if !strings.HasPrefix(s, "PREFIX:") {
		return "", errors.New("missing prefix")
	}
	return strings.TrimPrefix(s, "PREFIX:"), nil
}

func TestTypedDataReconciler_CustomCodec(t *testing.T) {
	store, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)

	codec := &prefixCodec{}
	reconciler := NewTypedDataReconcilerWithCodec(store, codec)

	item := "payload"
	d := store.Digest(item)

	// Ingest with custom encoded format
	err = reconciler.IngestItem(d, strings.NewReader("PREFIX:"+item))
	require.NoError(t, err)
	assert.Equal(t, 1, store.Size())

	// OpenItemReader should stream using the custom codec
	rc, sizeHint, ok, err := reconciler.OpenItemReader(d)
	require.NoError(t, err)
	require.True(t, ok)
	defer rc.Close()

	streamed, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "PREFIX:"+item, string(streamed))
	assert.Equal(t, int64(len("PREFIX:"+item)), sizeHint)
}

func TestTypedDataReconciler_NilGuards(t *testing.T) {
	// Nil store
	nilStoreReconciler := &typedDataReconciler[string]{
		store: nil,
		codec: DefaultItemCodec[string](),
	}

	assert.Nil(t, nilStoreReconciler.Digests())
	assert.Equal(t, revIdxStore.DigestSymbol(0), nilStoreReconciler.Fingerprint())

	_, _, err := nilStoreReconciler.Reconcile(nil)
	assert.True(t, errors.Is(err, ErrNilStore))

	_, _, _, err = nilStoreReconciler.OpenItemReader(1)
	assert.True(t, errors.Is(err, ErrNilStore))

	err = nilStoreReconciler.IngestItem(1, strings.NewReader("data"))
	assert.True(t, errors.Is(err, ErrNilStore))

	// Nil codec
	store, err := revIdxStore.NewDigestSet(revIdxStore.MustDefaultHasher[string]())
	require.NoError(t, err)
	nilCodecReconciler := &typedDataReconciler[string]{
		store: store,
		codec: nil,
	}

	_, _, _, err = nilCodecReconciler.OpenItemReader(1)
	assert.True(t, errors.Is(err, ErrNilCodec))

	err = nilCodecReconciler.IngestItem(1, strings.NewReader("data"))
	assert.True(t, errors.Is(err, ErrNilCodec))
}

type failingReader struct {
	err error
}

func (f *failingReader) Read(p []byte) (n int, err error) {
	return 0, f.err
}
