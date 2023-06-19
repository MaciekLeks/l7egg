package controller

type ctxAssetValue int8
type ctxAssetType string

type assetStatus byte

const (
	assetSynced assetStatus = iota
	assetStale              //could be removed
	assetNew                //new to add to the ebpf map
)

const (
	ctxCeggValue ctxAssetValue = iota + 1
	ctxPodValue
)

type ProgramType string

const (
	ProgramTypeTC     ProgramType = "tc"
	ProgramTypeCgroup ProgramType = "cgroup"
)
