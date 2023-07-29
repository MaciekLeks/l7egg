package common

type ProgramType string

const (
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
