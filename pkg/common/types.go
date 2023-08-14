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
//type ProgramInfo struct {
//	ProgramType ProgramType
//	NetNsPath   string
//	CgroupPath  string
//}

//type BoxKey struct {
//	Egg         types.NamespacedName
//	Pod         types.NamespacedName
//	ContainerId string
//}

//func (bk BoxKey) String() string {
//	return fmt.Sprintf("%s|%s|%s", bk.Egg.String(), bk.Pod.String(), bk.ContainerId)
//}

// { For CNs, CIDRs,...
type Asset[T comparable] struct {
	Value       T
	AssetStatus AssetStatus
}
type PtrAssetList[T comparable] []*Asset[T]

// Add adds element to ptrAssetList[T] if it does not exist already.
// Returns true if element was added, false otherwise.
func (l *PtrAssetList[T]) Add(element T) bool {
	for _, e := range *l {
		if e.Value == element {
			return false
		}
	}
	*l = append(*l, &Asset[T]{Value: element, AssetStatus: AssetNew})
	return true
}

// Remove removes element from ptrAssetList[T] if it exists.
// Returns true if element was removed, false otherwise.
func (l *PtrAssetList[T]) Remove(element T) bool {
	for i, e := range *l {
		if e.Value == element {
			*l = append((*l)[:i], (*l)[i+1:]...)
			return true
		}
	}
	return false
}

// Contains returns true if ptrAssetList[T] contains element, false otherwise.
func (l *PtrAssetList[T]) Contains(element T) bool {
	for _, e := range *l {
		if e.Value == element {
			return true
		}
	}
	return false
}

// Update updates element in the receiver pointer list on the basis a new ptrAssetList[T]
// It adds element if not exist on receiver list, sets AssetSync status if they are the same,
// or AssetStale receiver list contains element which does not exist on a new list.
// Returns true if element was updated, false otherwise.
func (l *PtrAssetList[T]) Update(newList PtrAssetList[T]) bool {
	for _, e := range *l {
		if !newList.Contains(e.Value) {
			e.AssetStatus = AssetStale
		} else {
			e.AssetStatus = AssetSynced
		}
	}
	for _, e := range newList {
		if !l.Contains(e.Value) {
			l.Add(e.Value)
		}
	}
	return true
}

// Cleans clean ptrAssetList[T] from elements with status common.AssetStale
func (l *PtrAssetList[T]) Clean() {
	for i, e := range *l {
		if e.AssetStatus == AssetStale {
			*l = append((*l)[:i], (*l)[i+1:]...)
		}
	}
}

// Cleans clean ptrAssetList[T] from elements with status common.AssetStatusDeleted.
