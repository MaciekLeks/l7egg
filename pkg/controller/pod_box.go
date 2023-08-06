package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
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
	Containers    ContainerBoxList
	PairedWithEgg *types.NamespacedName
	Boxer         core.Boxer
}

type ComponentBoxer interface {
	Set(fn func(v *Pody) error) error
	NamespaceName() types.NamespacedName
	RunBoxes(ctx context.Context, eggi *core.EggInfo) error
	StopBoxes() error
}

//func NewNodeBox() (*NodeBox, error) {
//	return &NodeBox{}, nil
//}

func NewPodBox(pod *corev1.Pod) (*Pody, error) {
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

func NewFakePodBox(name string) (*Pody, error) {
	// Creates empty Containers list with only one ContainerBox filled with Pid from os.GetPid()
	hosts := make([]*ContainerBox, 0)
	pid := uint32(os.Getpid())
	hostBox := &ContainerBox{
		Name: name,
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

func (pb *Pody) String() string {
	return fmt.Sprintf("Pody: %s/%s", pb.Namespace, pb.Name)
}

// Set sets in a safe manner Pody fields.
func (pb *Pody) Set(fn func(v *Pody) error) error {
	pb.Lock()
	defer pb.Unlock()
	return fn(pb)
}

//func (nb *NodeBox) Set(fn func(v *NodeBox) error) error {
//	nb.Lock()
//	defer nb.Unlock()
//	return fn(nb)
//}

//func (pi *Pody) Update(pod *corev1.Pod) (bool, error) {
//	var changed bool
//	pi.RLock()
//	defer pi.RUnlock()
//
//	npi, err := NewPodBox(pod)
//	if err != nil {
//		return changed, err
//	}
//
//	if reflect.DeepEqual(&pi, &npi) {
//		changed = true
//		// Update Pody fields
//		v.name = npi.name
//		v.namespace = npi.namespace
//		v.labels = npi.labels
//		v.nodeName = npi.nodeName
//		v.containers = npi.containers
//
//	}
//
//	return changed, nil
//}

func (pb *Pody) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: pb.Namespace, Name: pb.Name}
}

//func (pb *NodeBox) NamespaceName() types.NamespacedName {
//	return types.NamespacedName{Namespace: "", Name: ""}
//}

func (pb *Pody) RunBoxes(ctx context.Context, eggi *core.EggInfo) error {
	pb.Lock()
	defer pb.Unlock()

	if len(pb.Containers) < 1 {
		return fmt.Errorf("no containers in pod %s", pb.Name)
	}

	if eggi.ProgramType == common.ProgramTypeTC && pb.Boxer == nil {
		container := pb.Containers[0]
		if container.Ready == true && container.AssetStatus == common.AssetNew {
			// not nil for Node
			if pb.Boxer == nil {
				pb.Boxer = core.NewBoxy(eggi)
			}
			err := pb.Boxer.RunWithContainer(ctx, container)
			if err != nil {
				return err
			}

		}
		return nil
	} else {
		for i := range pb.Containers {
			container := pb.Containers[i]
			if container.Ready == true && container.AssetStatus == common.AssetNew {
				// not nil for Node
				if pb.Boxer == nil {
					container.Boxer = core.NewBoxy(eggi)
				}
				err := container.Boxer.RunWithContainer(ctx, container)
				if err != nil {
					return err
				}
			}
		}
	}

	pb.PairedWithEgg = &types.NamespacedName{Namespace: "", Name: eggi.Name}

	return nil
}

//func (nb *NodeBox) RunBoxes(ctx context.Context, eggi *core.EggInfo) error {
//	nb.Lock()
//	defer nb.Unlock()
//
//	boxy := core.NewBoxy(eggi)
//
//	err := boxy.RunWithPid(ctx, uint32(os.Getpid()))
//	if err != nil {
//		return err
//	}
//
//	nb.Boxer = boxy
//	nb.PairedWithEgg = &types.NamespacedName{Namespace: "", Name: eggi.Name}
//
//	return nil
//}

func (pb *Pody) StopBoxes() error {
	pb.Lock()
	defer pb.Unlock()

	var err error
	var resErr error
	if pb.Boxer != nil {
		err = pb.Boxer.Stop()
		if err != nil {
			// append err to existing resErr if not nil
			resErr = fmt.Errorf("%v\n%v", resErr, err)

		}
	}

	for i := range pb.Containers {
		if pb.Containers[i].Boxer != nil {
			err = pb.Containers[i].Boxer.Stop()
			if err != nil {
				// append err to existing resErr if not nil
				resErr = fmt.Errorf("%v\n%v", resErr, err)
			}
		}
	}

	return resErr
}

// WaitBoxes waits for all boxes to finish. Blocking call.
func (pb *Pody) WaitBoxes() {
	var podyWaitGroup sync.WaitGroup

	if pb.Boxer != nil {
		podyWaitGroup.Add(1)
		go func() {
			defer podyWaitGroup.Done()
			pb.Boxer.Wait()
		}()
	}

	for i := range pb.Containers {
		if pb.Containers[i].Boxer != nil {
			podyWaitGroup.Add(1)
			go func() {
				defer podyWaitGroup.Done()
				pb.Containers[i].Boxer.Wait()
			}()
		}
	}

	podyWaitGroup.Wait()
}

func (pb *Pody) UpdateBoxes(ctx context.Context) error {
	pb.Lock()
	defer pb.Unlock()

	var err error
	var resErr error
	if pb.Boxer != nil {
		err = pb.Boxer.UpdateRunning(ctx)
		if err != nil {
			// append err to existing resErr if not nil
			resErr = fmt.Errorf("%v\n%v", resErr, err)

		}
	}

	for i := range pb.Containers {
		if pb.Containers[i].Boxer != nil {
			err = pb.Containers[i].Boxer.UpdateRunning(ctx)
			if err != nil {
				// append err to existing resErr if not nil
				resErr = fmt.Errorf("%v\n%v", resErr, err)
			}
		}
	}

	return resErr

}

//func (nb *NodeBox) StopBoxes() error {
//	nb.Lock()
//	defer nb.Unlock()
//
//	var err error
//	var resErr error
//	if nb.Boxer != nil {
//		err = nb.Boxer.Stop()
//		if err != nil {
//			return fmt.Errorf("%v\n%v", resErr, err)
//
//		}
//	}
//
//	return nil
//}
