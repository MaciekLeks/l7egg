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

// ProgramInfo is a struct that holds information about the program type and network namespace path and cgroup path;
// It's used by eggBox and it's subject to change, e.g. when box is going to run for a pod
type ProgramInfo struct {
	programType ProgramType
	netNsPath   string
	cgroupPath  string
}
