package common

type ProgramType string
type CtxAssetType string
type CtxAssetValue int8
type AssetStatus byte

const (
	AssetSynced AssetStatus = iota
	AssetStale              //could be removed
	AssetNew                //new to add to the ebpf map

	ProgramTypeTC     ProgramType = "tc"
	ProgramTypeCgroup ProgramType = "cgroup"
)

// ProgramInfo is a struct that holds information about the program type and network namespace path and cgroup path;
// It's used by eggBox, and it's subject to change, e.g. when box is going to run for a pod
type ProgramInfo struct {
	ProgramType ProgramType
	NetNsPath   string
	CgroupPath  string
}

//type BoxKey struct {
//	Egg         types.NamespacedName
//	Pod         types.NamespacedName
//	ContainerId string
//}

//func (bk BoxKey) String() string {
//	return fmt.Sprintf("%s|%s|%s", bk.Egg.String(), bk.Pod.String(), bk.ContainerId)
//}
