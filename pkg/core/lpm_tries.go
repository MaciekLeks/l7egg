package core

import "unsafe"

type ILPMKey interface {
	GetPointer() unsafe.Pointer
}

type ipv4LPMKey struct {
	prefixLen uint32
	port      uint16
	data      [4]uint8
}

func (k ipv4LPMKey) GetPointer() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

type ipv6LPMKey struct {
	prefixLen uint32
	port      uint16
	data      [16]uint8
}

func (k ipv6LPMKey) GetPointer() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

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
