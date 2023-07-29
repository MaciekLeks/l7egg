package syncx

import (
	"sync"
)

type sequencer struct {
	seqIdGen ISeqId[uint16]
}

var (
	instance *sequencer
	once     sync.Once
)

func Sequencer() *sequencer {
	once.Do(func() {
		instance = &sequencer{
			seqIdGen: New[uint16](),
		}
	})
	return instance
}

func (s *sequencer) Next() uint16 {
	return s.seqIdGen.Next()
}
