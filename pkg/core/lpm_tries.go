package core

import "unsafe"

type ILPMKey interface {
	GetPointer() unsafe.Pointer
}

type ipv4LPMKey struct {
	prefixLen uint32
	port      uint16
	protocol  uint8
	data      [4]uint8
}

func (k ipv4LPMKey) GetPointer() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

type ipv6LPMKey struct {
	prefixLen uint32
	port      uint16
	protocol  uint8
	data      [16]uint8
}

func (k ipv6LPMKey) GetPointer() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

// ipLPMVal represents the value stored in the ipv4_lpm_map and ipv6_lpm_map maps.
// It contains the following fields:
// - ttl: The time-to-live value for the entry, 0 for infinity.
// - counter: Number of hits.
// - id: The of the entry.
// - status: The status of the entry (0 - sync, 1 - stale, 2 - new).
type ipLPMVal struct {
	ttl     uint64
	counter uint64
	id      uint16
	status  uint8
}

type ipProtocolVersion int8

const (
	ipv4, ipv6 ipProtocolVersion = 4, 6
)
