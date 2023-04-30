// Package tsslice provides a collection of thread-safe slice functions that can be safely used between multiple goroutines.
package tools

import "sync"

type SafeSlice[T any] struct {
	mux   sync.RWMutex
	slice []T
}

// Append is a thread-safe version of the Go built-in append function.
func (ss *SafeSlice[T]) Append(item ...T) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	ss.slice = append(ss.slice, item...)
}

// Len is a thread-safe function to get the length of the inner slice.
func (ss *SafeSlice[T]) Len() int {
	ss.mux.RLock()
	defer ss.mux.RUnlock()

	return len(ss.slice)
}

// Set is a thread-safe function to assign a value to a key in the inner slice.
func (ss *SafeSlice[T]) Set(key int, value T) {
	ss.mux.Lock()
	defer ss.mux.Unlock()

	ss.slice[key] = value
}

// TODO: add comment
func (ss *SafeSlice[T]) GetRef(key int) *T {
	ss.mux.Lock()
	return &ss.slice[key]
}

// TODO: add comment
func (ss *SafeSlice[T]) Commit() {
	ss.mux.Unlock()
}

func (ss *SafeSlice[T]) GetReadRef(key int) *T {
	ss.mux.RLock()
	return &ss.slice[key]
}

// TODO: add comment
func (ss *SafeSlice[T]) Release() {
	ss.mux.RUnlock()
}

// Get is a thread-safe function to get a value by key in the inner slice.
func (ss *SafeSlice[T]) GetValue(key int) T {

	ss.mux.RLock()
	defer ss.mux.RUnlock()

	return ss.slice[key]
}
