package syncx

import "sync"

// SafeMap is a generic wrapper around sync.Map
type SafeMap[K comparable, V any] struct {
	m sync.Map
}

func (m *SafeMap[K, V]) Delete(key K) {
	m.m.Delete(key)
}

func (m *SafeMap[K, V]) Load(key K) (value V, ok bool) {
	v, ok := m.m.Load(key)
	if !ok {
		return value, ok
	}
	return v.(V), ok
}
func (m *SafeMap[K, V]) LoadAndDelete(key K) (value V, loaded bool) {
	v, loaded := m.m.LoadAndDelete(key)
	if !loaded {
		return value, loaded
	}
	return v.(V), loaded
}
func (m *SafeMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	v, loaded := m.m.LoadOrStore(key, value)
	return v.(V), loaded
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
func (m *SafeMap[K, V]) Range(f func(key K, value V) bool) {
	m.m.Range(func(key, value any) bool {
		return f(key.(K), value.(V))
	})
}
func (m *SafeMap[K, V]) Store(key K, value V) {
	m.m.Store(key, value)
}
