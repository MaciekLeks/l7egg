package syncx

import "sync"

type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

type Integer interface {
	Signed | Unsigned
}

type ISeqId[T Integer] interface {
	Next() T
}

type SeqId[T Integer] struct {
	id  T
	mux sync.Mutex
}

func New[T Integer]() ISeqId[T] {
	return &SeqId[T]{}
}

func (si *SeqId[T]) Next() T {
	si.mux.Lock()
	defer si.mux.Unlock()
	si.id = si.id + 1
	return si.id
}
