package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
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

type Containery struct {
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

type ContaineryList []*Containery

func NewContainery(cs *corev1.ContainerStatus) (*Containery, error) {
	var cid string
	var pid uint32
	var err error
	if cid, err = extractContainerdContainerId(cs.ContainerID); err != nil {
		return nil, err
	}

	if pid, err = containerPid(context.Background(), cid); err != nil {
		fmt.Printf("deep[containerPid] - error %s\n", err)
		return nil, err
	}

	return &Containery{
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

// Update updates Containery with ContainerStatus based on deep equality of Containery
func (ci *Containery) Update(cs *corev1.ContainerStatus) (bool, error) {
	var changed bool
	nci, err := NewContainery(cs)

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

func ExtractContainersBox(pod *corev1.Pod) ([]*Containery, error) {
	cis := make([]*Containery, len(pod.Status.ContainerStatuses))
	for i := range pod.Status.ContainerStatuses {
		if ci, err := NewContainery(&pod.Status.ContainerStatuses[i]); err == nil {
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

const containerdSocketFileAbsPath = "/var/snap/microk8s/common/run/containerd.sock" //TODO move to config

// findContainerByContainerId finds container by containerd id
// TODO: do not look after container in all namespaces every call - cache namespaces
func findContainerByContainerId(ctx context.Context, containerId string) (containerd.Container, error) {
	// Creates client to connect to containerd
	client, err := containerd.New(containerdSocketFileAbsPath)
	defer client.Close()

	if err != nil {
		return nil, fmt.Errorf("can't connect to containerd socket %s", err)
	}
	defer client.Close()

	// Gets available namespaces
	nsService := client.NamespaceService()
	nsList, err := nsService.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't get containerd namespaces %s", err)
	}

	// Searches for container in each ns
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, ns)
		container, err := client.LoadContainer(nsCtx, containerId)
		if err == nil {
			fmt.Printf("\n\ndeep[xxx]The sought container %s is in the %s ns\n\n", containerId, ns)
			return container, nil
		}
	}
	return nil, fmt.Errorf("container %s not found", containerId)
}

//func containerPid(ctx context.Context, containerId string) (uint32, error) {
//	var pid uint32
//	logger := klog.FromContext(ctx)
//
//	// Creates client to connect to containerd
//	client, err := containerd.New(containerdSocketFileAbsPath)
//	defer client.Close()
//
//	if err != nil {
//		return pid, fmt.Errorf("can't connect to containerd socket %s", err)
//	}
//	defer client.Close()
//
//	// Gets available namespaces
//	// TODO: do not look after container in all namespaces every call - cache namespaces
//	nsService := client.NamespaceService()
//	nsList, err := nsService.List(ctx)
//	if err != nil {
//		return pid, fmt.Errorf("can't get containerd namespaces %s", err)
//	}
//
//	// Searches for container in each ns
//	var container containerd.Container
//	var found bool
//
//	var nsCtx context.Context
//	for i := range nsList {
//		nsCtx = namespaces.WithNamespace(ctx, nsList[i])
//		container, err = client.LoadContainer(nsCtx, containerId)
//		if err == nil {
//			fmt.Printf("\n\ndeep[xxx]The sought container %s is in the %s ns\n\n", containerId, nsCtx)
//			found = true
//			break
//		}
//	}
//	if !found {
//		return pid, fmt.Errorf("container %s not found", containerId)
//	}
//
//	//{ old code
//	//client, err := containerd.New(containerdSocketFileAbsPath, containerd.WithDefaultNamespace("k8s.io"))
//	//if err != nil {
//	//	return pid, fmt.Errorf("can't connect to containerd socket", err)
//	//}
//	//defer client.Close()
//	//
//	//logger.V(2).Info("Container client ready")
//	//
//	//container, err := client.LoadContainer(ctx, containerId)
//	//if err != nil {
//	//	return pid, fmt.Errorf("can't load container", err)
//	//}
//	//}
//
//	logger.V(2).Info("Container loaded")
//
//	task, err := container.Task(nsCtx, nil)
//	if err != nil {
//		return pid, fmt.Errorf("can't get container task", err)
//	}
//
//	logger.V(2).Info("runEgg-4")
//
//	pid = task.Pid()
//	if err != nil {
//		return pid, fmt.Errorf("Can't get container task PID", err)
//	}
//
//	return pid, nil
//}

func containerPid(ctx context.Context, containerId string) (uint32, error) {
	var pid uint32
	logger := klog.FromContext(ctx)

	client, err := createContainerdClient()
	if err != nil {
		return pid, fmt.Errorf("can't connect to containerd socket: %s", err)
	}
	defer client.Close()

	container, err := findContainer(ctx, client, containerId)
	if err != nil {
		return pid, err
	}

	logger.V(2).Info("Container loaded")

	task, err := container.Task(ctx, nil)
	if err != nil {
		return pid, fmt.Errorf("can't get container task: %s", err)
	}

	pid = task.Pid()
	if err != nil {
		return pid, fmt.Errorf("can't get container task PID: %s", err)
	}

	return pid, nil
}

func createContainerdClient() (*containerd.Client, error) {
	return containerd.New(containerdSocketFileAbsPath)
}

func findContainer(ctx context.Context, client *containerd.Client, containerId string) (containerd.Container, error) {
	nsService := client.NamespaceService()
	nsList, err := nsService.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't get containerd namespaces: %s", err)
	}

	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, ns)
		container, err := client.LoadContainer(nsCtx, containerId)
		if err == nil {
			return container, nil
		}
	}

	return nil, fmt.Errorf("container %s not found", containerId)
}

func (cyl ContaineryList) containeryByContainerId(containerId string) *Containery {
	for _, ci := range cyl {
		if ci.ContainerID == containerId {
			return ci
		}
	}
	return nil
}

func (cyl ContaineryList) containeryByName(containerName string) *Containery {
	for _, ci := range cyl {
		if ci.Name == containerName {
			return ci
		}
	}
	return nil
}

// CheckContainers checks if containers are changed and returns list of containers to be updated (new, synced) and deleted (stale);
// Old list is not changed
func (cyl ContaineryList) CheckContainers(newcyl ContaineryList) (tbuList, tbdList ContaineryList, update bool, resErr error) {
	for i := range newcyl {
		name := newcyl[i].Name
		c := cyl.containeryByName(name)
		if c == nil {
			// container is not found in previous list
			tbuList = append(tbuList, newcyl[i])
			update = true
		} else {
			// container is found in previous list
			//TODO add more conditions
			if c.ContainerID != newcyl[i].ContainerID {
				// we do not modify receiver, so we need to create a copy
				oldc := *c
				oldc.AssetStatus = common.AssetStale
				tbdList = append(tbdList, &oldc)
				tbuList = append(tbuList, newcyl[i])
				update = true
			} else {
				c.AssetStatus = common.AssetSynced
				newcyl[i].AssetStatus = common.AssetSynced
				tbuList = append(tbuList, newcyl[i])
			}
		}
	}
	return
}
