package tools

import "sync"

// SafeMap is a thread-safe generic map
type SafeMap[K comparable, V any] struct {
	sync.Mutex
	m map[K]V
}

// Load returns the value stored in the map for a key, or nil if no value is present.
// The ok result indicates whether value was found in the map.
func (m *SafeMap[T, V]) Load(k T) (V, bool) {
	m.Lock()
	v, ok := m.m[k]
	m.Unlock()
	return v, ok
}

// Store sets the value for a key.
func (m *SafeMap[K, V]) Store(k K, v V) {
	m.Lock()
	m.m[k] = v
	m.Unlock()
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
func (m *SafeMap[K, V]) Range(f func(k K, v V) bool) {
	m.Lock()
	for k, v := range m.m {
		if !f(k, v) {
			break
		}
	}
	m.Unlock()
}
