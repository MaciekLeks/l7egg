package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	corev1 "k8s.io/api/core/v1"
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

// Reset resets Containery to AssetNew state and nils Boxer
func (ci *Containery) Reset() {
	ci.AssetStatus = common.AssetNew
	ci.Boxer = nil
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

func createClient() (*containerd.Client, error) {
	client, err := containerd.New(containerdSocketFileAbsPath)
	if err != nil {
		return nil, fmt.Errorf("can't connect to containerd socket: %w", err)
	}
	return client, nil
}

func listNamespaces(client *containerd.Client, ctx context.Context) ([]string, error) {
	nsService := client.NamespaceService()
	nsList, err := nsService.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't get containerd namespaces: %w", err)
	}
	return nsList, nil
}

func findContainer(ctx context.Context, client *containerd.Client, containerId string, nsList []string) (containerd.Container, string, error) {
	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, ns)
		container, err := client.LoadContainer(nsCtx, containerId)
		if err == nil {
			return container, ns, nil
		}
	}
	return nil, "", fmt.Errorf("container %s not found", containerId)
}

func getTaskPid(ctx context.Context, container containerd.Container, namespace string) (uint32, error) {
	task, err := container.Task(namespaces.WithNamespace(ctx, namespace), nil)
	if err != nil {
		return 0, fmt.Errorf("can't get container task: %w", err)
	}
	return task.Pid(), nil
}

func containerPid(ctx context.Context, containerId string) (uint32, error) {
	client, err := createClient()
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// TODO: optimize the code - cache namespaces
	nsList, err := listNamespaces(client, ctx)
	if err != nil {
		return 0, err
	}

	container, namespace, err := findContainer(ctx, client, containerId, nsList)
	if err != nil {
		return 0, err
	}

	return getTaskPid(ctx, container, namespace)
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
