package core

import (
	"context"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"k8s.io/klog/v2"
	"os"
	"regexp"
)

var reCgroup2Mount = regexp.MustCompile(`(?m)^cgroup2\s(/\S+)\scgroup2\s`)

// attachCgroupProg attaches a BPF program to a cgroup v2 and return the link between them.
func attachCgroupProg(ctx context.Context, bpfModule *bpf.Module, progName string, attachType bpf.BPFAttachType, cgroupPath string) (*bpf.BPFLink, error) {
	logger := klog.FromContext(ctx)
	cgroupRootDir, err := getCgroupV2RootDir()
	if err != nil {
		return nil, err
	}
	//cgroupDir := cgroupRootDir + filepath.Dir(cgroupPath)
	cgroupDir := cgroupRootDir + cgroupPath

	logger.V(2).Info("cgroup directory", "dir", cgroupDir)

	prog, err := bpfModule.GetProgram(progName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	//link, err := prog.AttachCgroup(cgroupDir)
	link, err := prog.AttachCgroupLegacy(cgroupDir, attachType)
	if err != nil {
		return nil, err
	}
	if link.FileDescriptor() == 0 {
		return nil, fmt.Errorf("link fd is 0")
	}

	return link, nil
}

func getCgroupV2RootDir() (string, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("read /proc/mounts failed: %+s", err)
	}
	items := reCgroup2Mount.FindStringSubmatch(string(data))
	if len(items) < 2 {
		return "", fmt.Errorf("cgroupv2 is not mounted")
	}

	return items[1], nil
}
