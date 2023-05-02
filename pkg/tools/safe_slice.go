package tools

import (
	"fmt"
	"sync"
)

type SafeSlice[T any] struct {
	mux   sync.RWMutex
	slice []T
}

// Append is a thread-safe version of the Go built-in append function.
func (ss *SafeSlice[T]) Append(item ...T) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	ss.slice = append(ss.slice, item...)

	fmt.Printf("Slice addr: %p\n", ss.slice)
}

// Len is a thread-safe function to get the length of the inner slice.
func (ss *SafeSlice[T]) Len() int {
	ss.mux.RLock()
	defer ss.mux.RUnlock()

	return len(ss.slice)
}

// Set is a thread-safe function to assign a new value to a key in the inner slice.
func (ss *SafeSlice[T]) Set(key int, value T) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	ss.slice[key] = value
}

// Update is a thread-safe function to set value's fields for a key in the inner slice.
func (ss *SafeSlice[T]) Update(key int, updateFunc func(val *T)) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	updateFunc(&ss.slice[key])
}

// Get is a thread-safe function to get a value by key in the inner slice.
func (ss *SafeSlice[T]) Get(key int) T {

	ss.mux.RLock()
	defer ss.mux.RUnlock()

	return ss.slice[key]
}
