package user

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"os"
	"path/filepath"
	"regexp"
)

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

func attachCgroupProg(bpfModule *bpf.Module, progName string, attachType bpf.BPFAttachType, cgroupPath string) error {
	cgroupRootDir := getCgroupV2RootDir()
	cgroupDir := cgroupRootDir + filepath.Dir(cgroupPath)
	//cgroupDir := cgroupRootDir + cgroupPath

	fmt.Println("\n\n\n-------getCgroupV2Dir:", cgroupDir)

	prog, err := bpfModule.GetProgram(progName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	//link, err := prog.AttachCgroup(cgroupDir)
	link, err := prog.AttachCgroupLegacy(cgroupDir, attachType)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link.FileDescriptor() == 0 {
		os.Exit(-1)
	}

	return nil
}

func getCgroupV2RootDir() string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		fmt.Fprintf(os.Stderr, "read /proc/mounts failed: %+v\n", err)
		os.Exit(-1)
	}
	items := reCgroup2Mount.FindStringSubmatch(string(data))
	if len(items) < 2 {
		fmt.Fprintln(os.Stderr, "cgroupv2 is not mounted")
		os.Exit(-1)
	}

	return items[1]
}
