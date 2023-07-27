package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/containerd/containerd"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	"sync"
)

// PodInfo holds POD crucial metadata.
type PodInfo struct {
	sync.RWMutex
	//UID       string
	name          string
	namespace     string
	labels        map[string]string
	nodeName      string
	containerIDs  []string
	matchedKeyBox core.BoxKey
}

// set sets in a safe manner PodInfo fields.
func (pi *PodInfo) set(fn func(v *PodInfo)) {
	pi.Lock()
	defer pi.Unlock()
	fn(pi)
}

func (pi *PodInfo) runEgg(ctx context.Context, boxKey core.BoxKey) error {
	logger := klog.FromContext(ctx)

	logger.V(2).Info("runEgg-1")
	client, err := containerd.New("/var/snap/microk8s/common/run/containerd.sock", containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return fmt.Errorf("Can't connect to containerd socket", err)
	}
	defer client.Close()

	logger.V(2).Info("runEgg-2")

	container, err := client.LoadContainer(ctx, pi.containerIDs[0]) //TODO not only 0 ;)
	if err != nil {
		return fmt.Errorf("Can't load container", err)
	}

	logger.V(2).Info("runEgg-3")

	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("Can't get container task", err)
	}

	logger.V(2).Info("runEgg-4")

	pid := task.Pid()
	if err != nil {
		return fmt.Errorf("Can't get container task PID", err)
	}

	var pids = []uint32{pid}

	logger.V(2).Info("runEgg-5")

	manager := core.BpfManagerInstance()
	box, ok := manager.Boxes.Load(boxKey)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("Box %s not found", boxKey))
		return fmt.Errorf("Box %s not found", boxKey)
	}
	logger.V(2).Info("runEgg-6")

	var cgroupPath string
	netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)

	if box.Egg().ProgramType == common.ProgramTypeCgroup {
		logger.V(2).Info("runEgg-7-cgroup")
		cgroupPath, err = getContainerdCgroupPath(pid)
		if err != nil {
			return fmt.Errorf("cgroup path error: %v", err)
		}
	} else {
		logger.V(2).Info("runEgg-7-tc")
	}

	return manager.BoxStart(ctx, boxKey, netNsPath, cgroupPath, pids...)
}

func (pi *PodInfo) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: pi.namespace, Name: pi.name}
}
