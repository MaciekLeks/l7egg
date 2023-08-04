package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/containerd/containerd"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"strings"
)

type ContainerStateInfo byte

const (
	ContainerStateUnknown ContainerStateInfo = iota
	ContainerStateWaiting
	ContainerStateRunning
	ContainerStateTerminated
)

type ContainerBox struct {
	Name          string
	LastStateInfo ContainerStateInfo
	StateInfo     ContainerStateInfo
	Ready         bool
	RestartCount  int32
	ContainerID   string
	Pid           uint32
	AssetStatus   common.AssetStatus
	Boxer         core.Boxer
}

type ContainerBoxList []*ContainerBox

func NewContainerBox(cs *corev1.ContainerStatus) (*ContainerBox, error) {
	var cid string
	var pid uint32
	var err error
	if cid, err = extractContainerdContainerId(cs.ContainerID); err != nil {
		return nil, err
	}

	if pid, err = GetContainerPid(context.Background(), cid); err != nil {
		return nil, err
	}

	return &ContainerBox{
		Name:          cs.Name,
		StateInfo:     mapContainerStateInfo(cs.State),
		LastStateInfo: mapContainerStateInfo(cs.LastTerminationState),
		Ready:         cs.Ready,
		RestartCount:  cs.RestartCount,
		ContainerID:   cid,
		Pid:           pid,
		AssetStatus:   common.AssetNew,
	}, nil
}

// Update updates ContainerBox with ContainerStatus based on deep equality of ContainerBox
func (ci *ContainerBox) Update(cs *corev1.ContainerStatus) (bool, error) {
	var changed bool
	nci, err := NewContainerBox(cs)

	if err != nil {
		return changed, err
	}

	if &ci != &nci {
		//changed
		changed = true
		//copy ci to nci fields
		ci.Name = nci.Name
		ci.LastStateInfo = nci.LastStateInfo
		ci.StateInfo = nci.StateInfo
		ci.Ready = nci.Ready
		ci.RestartCount = nci.RestartCount
		ci.ContainerID = nci.ContainerID
	}

	return changed, nil
}

func ExtractContainersBox(pod *corev1.Pod) ([]*ContainerBox, error) {
	cis := make([]*ContainerBox, len(pod.Status.ContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		if ci, err := NewContainerBox(&pod.Status.ContainerStatuses[i]); err == nil {
			cis[i] = ci
		} else {
			return nil, err
		}
	}
	return cis, nil
}

// mapContainerStateInfo maps container state to ContainerStateInfo
func mapContainerStateInfo(cs corev1.ContainerState) ContainerStateInfo {
	if cs.Waiting != nil {
		return ContainerStateWaiting
	}
	if cs.Running != nil {
		return ContainerStateRunning
	}
	if cs.Terminated != nil {
		return ContainerStateTerminated
	}
	return ContainerStateUnknown
}

// extractContainerId extracts containerd id only from fully qualified container id, e.g. containerd://<containerd-id>
func extractContainerdContainerId(fqcid string) (string, error) {
	var err error
	const crn = "containerd://"
	if !strings.Contains(fqcid, crn) {
		return fqcid, fmt.Errorf("only containerd supported")
	}
	cid := strings.TrimPrefix(fqcid, crn)
	return cid, err
}

func GetContainerPid(ctx context.Context, containerId string) (uint32, error) {
	var pid uint32
	logger := klog.FromContext(ctx)

	client, err := containerd.New("/var/snap/microk8s/common/run/containerd.sock", containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return pid, fmt.Errorf("can't connect to containerd socket", err)
	}
	defer client.Close()

	logger.V(2).Info("Container client ready")

	container, err := client.LoadContainer(ctx, containerId)
	if err != nil {
		return pid, fmt.Errorf("can't load container", err)
	}

	logger.V(2).Info("Container loaded")

	task, err := container.Task(ctx, nil)
	if err != nil {
		return pid, fmt.Errorf("can't get container task", err)
	}

	logger.V(2).Info("runEgg-4")

	pid = task.Pid()
	if err != nil {
		return pid, fmt.Errorf("Can't get container task PID", err)
	}

	return pid, nil
}

func (cil ContainerBoxList) GetContainerInfoByContainerId(containerId string) *ContainerBox {
	for _, ci := range cil {
		if ci.ContainerID == containerId {
			return ci
		}
	}
	return nil
}

func (cil ContainerBoxList) GetContainerInfoByName(containerName string) *ContainerBox {
	for _, ci := range cil {
		if ci.Name == containerName {
			return ci
		}
	}
	return nil
}

// ChangedContainers returns list of containers that have been changed - added, removed, updated
func (cil ContainerBoxList) UpdateContainers(current ContainerBoxList) (ContainerBoxList, error) {
	var newList ContainerBoxList
	var resErr error
	for i := range current {
		name := current[i].Name
		c := cil.GetContainerInfoByName(name)
		if c == nil {
			// container is not found in previous list
			newList = append(newList, current[i])
		} else {
			// container is found in previous list
			//TODO add more conditions
			if c.ContainerID != current[i].ContainerID {
				c.AssetStatus = common.AssetStale
				if err := c.Boxer.Stop(); err != nil { //should Stop be here?
					resErr = fmt.Errorf("%s: %w", err.Error(), resErr)
				}
				newList = append(newList, current[i])
			} else {
				c.AssetStatus = common.AssetSynced
				current[i].AssetStatus = common.AssetSynced
				newList = append(newList, current[i])
			}
		}
	}
	return newList, resErr
}
