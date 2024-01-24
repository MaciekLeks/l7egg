package core

import (
	"fmt"
	"unsafe"
)

const PortProtocolPrefixLen = 16 + 8                      //size of port + protocol
const PortProtocolSize = 2 + 1                            //size of port + protocol
const PortProtocolIpv4AddressSize = PortProtocolSize + 4  //size of port + protocol
const PortProtocolIpv6AddressSize = PortProtocolSize + 16 //size of port + protocol

type ILPMKey interface {
	Pointer() unsafe.Pointer
	MaskLen() uint8
	Port() uint16
	Protocol() uint8
	Addr() []uint8
}

type ipv4Key struct {
	maskLen  uint8
	port     uint16
	protocol uint8
	addr     [4]uint8
}

type ipv4LPMKeyBytes struct {
	prefixLen uint32
	data      [PortProtocolIpv4AddressSize]uint8
}

func (key ipv4Key) MaskLen() uint8 {
	return key.maskLen
}

func (key ipv4Key) Port() uint16 {
	return key.port
}

func (key ipv4Key) Protocol() uint8 {
	return key.protocol
}

func (key ipv4Key) Addr() []uint8 {
	return key.addr[:]
}

// ipv4KeyToBytes converts an ipv4Key into ipv4LPMKeyBytes data structure.
// It sets the prefix length by adding PortProtocolPrefixLen and maskLen.
// It converts the port into bytes and sets it in the data field.
// It sets the protocol byte in the data field.
// It copies the address bytes into the data field.
// Finally, it returns the resulting ipv4LPMKeyBytes.
func (key ipv4Key) ipv4KeyToBytes() ipv4LPMKeyBytes {
	var result ipv4LPMKeyBytes
	result.prefixLen = uint32(PortProtocolPrefixLen + key.maskLen)

	// Convert port to bytes
	endian.PutUint16(result.data[0:2], key.port)

	// Set protocol byte
	result.data[2] = key.protocol

	// Set address bytes
	copy(result.data[3:], key.addr[:])

	fmt.Println("-------------ipv4KeyToBytes", result)

	return result
}

func (kb ipv4LPMKeyBytes) ipv4BytesToKey() ipv4Key {
	var result ipv4Key

	// Convert port bytes to uint16
	result.port = endian.Uint16(kb.data[0:2])

	// Set protocol byte
	result.protocol = kb.data[2]

	// Set address bytes
	copy(result.addr[:], kb.data[3:])

	// Set mask length
	result.maskLen = uint8(kb.prefixLen - PortProtocolPrefixLen)

	fmt.Println("-------------ipv4BytesToKey", result)

	return result
}

func (key ipv4Key) Pointer() unsafe.Pointer {
	var bytes = key.ipv4KeyToBytes()
	return unsafe.Pointer(&bytes)
}

//func (kb ipv4LPMKeyBytes) Pointer() unsafe.Pointer {
//	return unsafe.Pointer(&kb)
//}

//func (k ipv4LPMKey) Pointer() unsafe.Pointer {
//	return unsafe.Pointer(&k)
//}

type ipv6Key struct {
	maskLen  uint8
	port     uint16
	protocol uint8
	addr     [16]uint8
}

type ipv6LPMKeyBytes struct {
	prefixLen uint32
	data      [PortProtocolIpv6AddressSize]uint8
}

func (key ipv6Key) MaskLen() uint8 {
	return key.maskLen
}

func (key ipv6Key) Port() uint16 {
	return key.port
}

func (key ipv6Key) Protocol() uint8 {
	return key.protocol
}

func (key ipv6Key) Addr() []uint8 {
	return key.addr[:]
}

func (key ipv6Key) ipv6KeyToBytes() ipv6LPMKeyBytes {
	var result ipv6LPMKeyBytes
	result.prefixLen = uint32(PortProtocolPrefixLen + key.maskLen)

	// Convert port to bytes
	endian.PutUint16(result.data[0:2], key.port)

	// Set protocol byte
	result.data[2] = key.protocol

	// Set address bytes
	copy(result.data[3:], key.addr[:])

	return result
}

func (kb ipv6LPMKeyBytes) ipv6BytesToKey() ipv6Key {
	var result ipv6Key

	// Convert port bytes to uint16
	result.port = endian.Uint16(kb.data[0:2])

	// Set protocol byte
	result.protocol = kb.data[2]

	// Set address bytes
	copy(result.addr[:], kb.data[3:])

	// Set mask length
	result.maskLen = uint8(kb.prefixLen - PortProtocolPrefixLen)

	return result
}

func (key ipv6Key) Pointer() unsafe.Pointer {
	var bytes = key.ipv6KeyToBytes()
	return unsafe.Pointer(&bytes)
}

//func (kb ipv6LPMKeyBytes) Pointer() unsafe.Pointer {
//	return unsafe.Pointer(&kb)
//}

// ipLPMVal represents the value stored in the ipv4_lpm_map and ipv6_lpm_map maps.
// It contains the following fields:
// - ttl: The time-to-live value for the entry, 0 for infinity.
// - counter: Number of hits.
// - id: The of the entry.
// - status: The status of the entry (0 - sync, 1 - stale, 2 - new).
// - inAcl: 0 - not in ACL, 1 - in ACL
type ipLPMVal struct {
	ttl     uint64
	counter uint64
	id      uint16
	status  uint8
	inAcl   uint8
}

type ipProtocolVersion int8

const (
	ipv4, ipv6 ipProtocolVersion = 4, 6
)
