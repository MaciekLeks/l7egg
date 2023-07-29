package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/containerd/containerd"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	"sync"
)

type ContainerStateInfo byte

const (
	ContainerStateUnknown ContainerStateInfo = iota
	ContainerStateWaiting
	ContainerStateRunning
	ContainerStateTerminated
)

type ContainerStatusInfo struct {
	Name          string
	LastStateInfo ContainerStateInfo
	StateInfo     ContainerStateInfo
	Ready         bool
	RestartCount  int32
	ContainerID   string
}

// PodInfo holds POD crucial metadata.
type PodInfo struct {
	sync.RWMutex
	//UID       string
	name              string
	namespace         string
	labels            map[string]string
	nodeName          string
	containerStatuses []ContainerStatusInfo
	matchedKeyBox     core.BoxKey
}

// set sets in a safe manner PodInfo fields.
func (pi *PodInfo) set(fn func(v *PodInfo)) {
	pi.Lock()
	defer pi.Unlock()
	fn(pi)
}

func extractContainerStatuses(pod *corev1.Pod) ([]ContainerStatusInfo, error) {
	csis := make([]ContainerStatusInfo, len(pod.Status.ContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		if cid, err := extractContainerdContainerId(pod.Status.ContainerStatuses[i].ContainerID); err == nil {
			csi := ContainerStatusInfo{
				Name:          pod.Status.ContainerStatuses[i].Name,
				StateInfo:     mapContainerStateInfo(pod.Status.ContainerStatuses[i].State),
				LastStateInfo: mapContainerStateInfo(pod.Status.ContainerStatuses[i].LastTerminationState),
				Ready:         pod.Status.ContainerStatuses[i].Ready,
				RestartCount:  pod.Status.ContainerStatuses[i].RestartCount,
				ContainerID:   cid,
			}
			csis[i] = csi
		} else {
			return nil, err
		}
	}
	return csis, nil

}

func (pi *PodInfo) runEgg(ctx context.Context, boxKey core.BoxKey) error {
	logger := klog.FromContext(ctx)

	logger.V(2).Info("runEgg-1")
	client, err := containerd.New("/var/snap/microk8s/common/run/containerd.sock", containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return fmt.Errorf("Can't connect to containerd socket", err)
	}
	defer client.Close()

	logger.V(2).Info("runEgg-2", pi.containerStatuses[0].ContainerID)

	container, err := client.LoadContainer(ctx, pi.containerStatuses[0].ContainerID) //TODO not only 0 ;)
	if err != nil {
		fmt.Println("runnEgg: Can't load container")
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
