package reconcile

import (
	"errors"
	"reflect"

	"github.com/golang/protobuf/proto"
)

type bytesCodec struct{}

func (bytesCodec) Encode(item []byte) ([]byte, error) {
	out := make([]byte, len(item))
	copy(out, item)
	return out, nil
}

func (bytesCodec) Decode(data []byte) ([]byte, error) {
	out := make([]byte, len(data))
	copy(out, data)
	return out, nil
}

type stringCodec struct{}

func (stringCodec) Encode(item string) ([]byte, error) {
	return []byte(item), nil
}

func (stringCodec) Decode(data []byte) (string, error) {
	return string(data), nil
}

type protoPtrCodec[T any] struct {
	elemType reflect.Type
}

func (c protoPtrCodec[T]) Encode(item T) ([]byte, error) {
	msg, ok := any(item).(proto.Message)
	if !ok || msg == nil {
		return nil, errors.New("reconcile: item is not a valid proto.Message")
	}
	return proto.Marshal(msg)
}

func (c protoPtrCodec[T]) Decode(data []byte) (T, error) {
	var zero T
	val := reflect.New(c.elemType).Interface()
	msg, ok := val.(proto.Message)
	if !ok {
		return zero, errors.New("reconcile: instantiated type does not implement proto.Message")
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return zero, err
	}
	return val.(T), nil
}

type protoValCodec[T any] struct {
	tType reflect.Type
}

func (c protoValCodec[T]) Encode(item T) ([]byte, error) {
	msg, ok := any(item).(proto.Message)
	if !ok {
		return nil, errors.New("reconcile: item does not implement proto.Message")
	}
	return proto.Marshal(msg)
}

func (c protoValCodec[T]) Decode(data []byte) (T, error) {
	var zero T
	ptr := reflect.New(c.tType).Interface()
	msg, ok := ptr.(proto.Message)
	if !ok {
		return zero, errors.New("reconcile: pointer does not implement proto.Message")
	}
	if err := proto.Unmarshal(data, msg); err != nil {
		return zero, err
	}
	return reflect.ValueOf(ptr).Elem().Interface().(T), nil
}

// DefaultItemCodec returns the default ItemCodec[T] for []byte, string,
// proto.Message (pointer or value), or JSON-encoded arbitrary types.
func DefaultItemCodec[T any]() ItemCodec[T] {
	var zero T
	switch any(zero).(type) {
	case []byte:
		return any(bytesCodec{}).(ItemCodec[T])
	case string:
		return any(stringCodec{}).(ItemCodec[T])
	default:
		tType := reflect.TypeOf(zero)
		protoMsgType := reflect.TypeOf((*proto.Message)(nil)).Elem()
		if tType != nil && tType.Implements(protoMsgType) {
			if tType.Kind() == reflect.Ptr {
				return protoPtrCodec[T]{elemType: tType.Elem()}
			}
			return protoValCodec[T]{tType: tType}
		}
		if tType != nil && reflect.PointerTo(tType).Implements(protoMsgType) {
			return protoValCodec[T]{tType: tType}
		}
		return JSONCodec[T]{}
	}
}
