package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"k8s.io/klog/v2"
	"os"

	//"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/MaciekLeks/l7egg/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sync"
)

//type NodeBox struct {
//	sync.RWMutex
//	NodeName      string
//	PairedWithEgg *types.NamespacedName
//	Boxer         core.Boxer
//}
//

// Pody holds POD crucial metadata.
type Pody struct {
	sync.RWMutex
	//UID       string
	Name          string
	Namespace     string
	Labels        map[string]string
	NodeName      string
	Containers    ContaineryList
	PairedWithEgg *types.NamespacedName
	Boxer         core.Boxer
}

//type ComponentBoxer interface {
//	Set(fn func(v *Pody) error) error
//	NamespaceName() types.NamespacedName
//	RunBoxySet(ctx context.Context, eggi *core.Eggy) error
//	StopBoxySet() error
//}

//func NewNodeBox() (*NodeBox, error) {
//	return &NodeBox{}, nil
//}

func NewPody(pod *corev1.Pod) (*Pody, error) {
	containers, err := ExtractContainersBox(pod)
	if err != nil {
		return nil, err
	}

	podNodeHostname, err := utils.CleanHostame(pod.Spec.NodeName)
	if err != nil {
		return nil, err
	}

	pi := &Pody{
		Name:       pod.Name,
		Namespace:  pod.Namespace,
		Labels:     pod.Labels,
		NodeName:   podNodeHostname,
		Containers: containers,
	}

	return pi, nil
}

// NewNodePody creates Pody with only one Containery filled with Pid from os.GetPid();
// It's used to not have to create polimorphic code for nodes (e.g. TC working on a host ifaces).
func NewNodePody(name string) (*Pody, error) {
	// Creates empty Containers list with only one Containery filled with Pid from os.GetPid()
	hosts := make([]*Containery, 0)
	pid := uint32(os.Getpid())
	hostBox := &Containery{
		Name:        name,
		Ready:       true,
		AssetStatus: common.AssetNew,
	}
	hostBox.Pid = pid
	hosts = append(hosts, hostBox)

	fakePodNodeHostname, err := utils.GetHostname()
	if err != nil {
		return nil, err
	}

	fakePody := &Pody{
		Name:       "",
		Namespace:  "",
		Labels:     nil,
		NodeName:   fakePodNodeHostname,
		Containers: hosts,
	}

	return fakePody, nil
}

func (py *Pody) String() string {
	return fmt.Sprintf("Pody: %s/%s", py.Namespace, py.Name)
}

// Set sets in a safe manner Pody fields.
func (py *Pody) Set(fn func(v *Pody) error) error {
	py.Lock()
	defer py.Unlock()
	return fn(py)
}

func (py *Pody) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: py.Namespace, Name: py.Name}
}

func (py *Pody) handleTCProgramType(ctx context.Context, ey *core.Eggy) error {
	container := py.Containers[0]
	if container.Ready == true && container.AssetStatus == common.AssetNew {
		var err error
		if py.Boxer == nil {
			py.Boxer, err = core.NewBoxy(ey, core.WithPid(container.Pid))
			if err != nil {
				return err
			}
		}
		err = py.Boxer.Install(ctx)
		container.AssetStatus = common.AssetSynced
		if err != nil {
			return err
		}
	}
	return nil
}

func (py *Pody) handleCgroupProgramType(ctx context.Context, eggi *core.Eggy) error {
	var err error
	if eggi.Shaping != nil && py.Boxer == nil {
		py.Boxer, err = core.NewBoxy(eggi, core.WithNetCls(), core.WithPid(py.Containers[0].Pid))
		if err != nil {
			return err
		}
		err = py.Boxer.Install(ctx)
		if err != nil {
			return err
		}
	}

	for i := range py.Containers {
		container := py.Containers[i]
		if container.Ready == true && container.AssetStatus == common.AssetNew {
			container.Boxer, err = core.NewBoxy(eggi, core.WithPid(container.Pid))
			if err != nil {
				return err
			}
			err = container.Boxer.Install(ctx)
			if err != nil {
				return err
			}
			if py.Boxer != nil {
				err = py.Boxer.DoAction(ctx, core.WithPid(container.Pid))
				if err != nil {
					return err
				}
			}
			container.AssetStatus = common.AssetSynced
		}
	}
	return nil
}

func (py *Pody) RunBoxySet(ctx context.Context, ey *core.Eggy) error {
	py.Lock()
	defer py.Unlock()

	eggKey := ey.NamespaceName()
	py.PairedWithEgg = &eggKey

	if len(py.Containers) < 1 {
		return fmt.Errorf("no containers in pod %s", py.Name)
	}

	if py.Boxer != nil {
		container := py.Containers[0]
		err := py.Boxer.Upgrade(ctx, core.WithPid(container.Pid))
		if err != nil {
			return err
		}
	}

	if ey.ProgramType == common.ProgramTypeTC && py.Boxer == nil {
		return py.handleTCProgramType(ctx, ey)
	} else if ey.ProgramType == common.ProgramTypeCgroup {
		return py.handleCgroupProgramType(ctx, ey)
	}

	return nil
}

func (py *Pody) StopBoxySet() error {
	py.Lock()
	defer py.Unlock()

	var err error
	var resErr error
	if py.Boxer != nil {
		err = py.Boxer.Stop()
		if err != nil {
			// append err to existing resErr if not nil
			resErr = fmt.Errorf("%v\n%v", resErr, err)

		}
		py.Boxer = nil
	}

	for i := range py.Containers {
		if py.Containers[i].Boxer != nil {
			err = py.Containers[i].Boxer.Stop()
			if err != nil {
				// append err to existing resErr if not nil
				resErr = fmt.Errorf("%v\n%v", resErr, err)
			}
			py.Containers[i].Reset() //could be used once again e.g. a new ClusterEgg on the same pod
		}
	}

	py.PairedWithEgg = nil

	return resErr
}

// WaitBoxySet waits for all boxes to finish. Blocking call.
func (py *Pody) WaitBoxySet() {
	var podyWaitGroup sync.WaitGroup

	if py.Boxer != nil {
		podyWaitGroup.Add(1)
		go func() {
			defer podyWaitGroup.Done()
			py.Boxer.Wait()
		}()
	}

	for i := range py.Containers {
		if py.Containers[i].Boxer != nil {
			podyWaitGroup.Add(1)
			go func() {
				defer podyWaitGroup.Done()
				py.Containers[i].Boxer.Wait()
			}()
		}
	}

	podyWaitGroup.Wait()
}

func (py *Pody) ReconcileBoxySet(ctx context.Context) error {
	py.Lock()
	defer py.Unlock()

	var err error
	var resErr error
	if py.Boxer != nil {
		err = py.Boxer.Reconcile(ctx)
		if err != nil {
			// append err to existing resErr if not nil
			resErr = fmt.Errorf("%v\n%v", resErr, err)

		}
	}

	for i := range py.Containers {
		if py.Containers[i].Boxer != nil {
			err = py.Containers[i].Boxer.Reconcile(ctx)
			if err != nil {
				// append err to existing resErr if not nil
				resErr = fmt.Errorf("%v\n%v", resErr, err)
			}
		}
	}

	return resErr

}

// CheckReconcileBoxySet checks if there are new containers to install, or old containers to stop; It's mutating method - it updates container list
func (py *Pody) CheckReconcileBoxySet(ctx context.Context, newContaineryList ContaineryList, ey *core.Eggy) error {
	logger := klog.FromContext(ctx)

	tbuList, tbdList, update, err := py.Containers.CheckContainers(newContaineryList)
	if err != nil {
		return err
	}

	if !update {
		return nil
	}

	// UpdateSpec container list
	_ = py.Set(func(p *Pody) error {
		p.Containers = tbuList
		return nil
	})

	logger.V(2).Info("pody container list update")
	err = py.RunBoxySet(ctx, ey)
	if err != nil {
		return err
	}

	logger.V(2).Info("new boxy set run")

	// Stops old boxy set
	for i := range tbdList {
		// only cgroup programs are stopped here, cause only cgroup programs are started at the container
		if tbdList[i].Boxer != nil {
			err = tbdList[i].Boxer.Stop()
			if err != nil {
				return fmt.Errorf("failed to stop boxy: %s", err)
			}
		}
	}

	return nil
}
