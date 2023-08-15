package common

import "fmt"

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

// Generic type X which is comparable and implements Stringer interface

// { For CommonNames, Cidrs,...
type Asset[T fmt.Stringer] struct {
	Value  *T
	Status AssetStatus
}
type AssetList[T fmt.Stringer] []Asset[T]

// Len returns the length of ptrAssetList[T]
func (l *AssetList[T]) Len() int {
	return len(*l)
}

// Add adds element to ptrAssetList[T] if it does not exist already.
// Returns true if element was added, false otherwise.
func (l *AssetList[T]) Add(element *T) bool {
	for _, e := range *l {
		if (*e.Value).String() == (*element).String() {
			return false
		}
	}
	*l = append(*l, Asset[T]{Value: element, Status: AssetNew})
	return true
}

// RemoveStale removes element from ptrAssetList[T] if it exists.
// Returns true if element was removed, false otherwise.
func (l *AssetList[T]) RemoveStale() bool {
	for i, e := range *l {
		if e.Status == AssetStale {
			*l = append((*l)[:i], (*l)[i+1:]...)
			return true
		}
	}
	return false
}

// Contains returns true if ptrAssetList[T] contains element, false otherwise.
func (l *AssetList[T]) Contains(element *T) bool {
	for _, e := range *l {
		if (*e.Value).String() == (*element).String() {
			return true
		}
	}
	return false
}

// Update updates element in the receiver pointer list on the basis a new ptrAssetList[T]
// It adds element if not exist on receiver list, sets AssetSync status if they are the same,
// or AssetStale receiver list contains element which does not exist on a new list.
func (l *AssetList[T]) Update(newList AssetList[T]) {
	for i := range *l {
		if !newList.Contains((*l)[i].Value) {
			(*l)[i].Status = AssetStale
		} else {
			(*l)[i].Status = AssetSynced
		}
	}
	for _, e := range newList {
		if !l.Contains(e.Value) {
			l.Add(e.Value)
		}
	}
}

// Cleans clean ptrAssetList[T] from elements with status common.AssetStale
//func (l AssetList[T]) Clean() {
//	for i, e := range l {
//		if e.Status == AssetStale {
//			l = append((l)[:i], (l)[i+1:]...)
//		}
//	}
//}

// SetStatus sets status to AssetStatus for all elements except Stale
func (l *AssetList[T]) SetStatus(status AssetStatus) {
	for i := range *l {
		if (*l)[i].Status != AssetStale {
			(*l)[i].Status = status
		}
	}
}

// Cleans clean ptrAssetList[T] from elements with status common.AssetStatusDeleted.
