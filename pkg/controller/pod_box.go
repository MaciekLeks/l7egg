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

type NodeBox struct {
	sync.RWMutex
	NodeName      string
	PairedWithEgg *types.NamespacedName
	Boxer         core.Boxer
}

// PodBox holds POD crucial metadata.
type PodBox struct {
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
	Set(fn func(v *PodBox) error) error
	NamespaceName() types.NamespacedName
	RunBoxes(ctx context.Context, eggi *core.EggInfo) error
	StopBoxes() error
}

func NewNodeBox() (*NodeBox, error) {
	return &NodeBox{}, nil
}

func NewPodBox(pod *corev1.Pod) (*PodBox, error) {
	containers, err := ExtractContainersBox(pod)
	if err != nil {
		return nil, err
	}

	podNodeHostname, err := utils.CleanHostame(pod.Spec.NodeName)
	if err != nil {
		return nil, err
	}

	pi := &PodBox{
		Name:       pod.Name,
		Namespace:  pod.Namespace,
		Labels:     pod.Labels,
		NodeName:   podNodeHostname,
		Containers: containers,
	}

	return pi, nil
}

// Set sets in a safe manner PodBox fields.
func (pb *PodBox) Set(fn func(v *PodBox) error) error {
	pb.Lock()
	defer pb.Unlock()
	return fn(pb)
}

func (nb *NodeBox) Set(fn func(v *NodeBox) error) error {
	nb.Lock()
	defer nb.Unlock()
	return fn(nb)
}

//func (pi *PodBox) Update(pod *corev1.Pod) (bool, error) {
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
//		// Update PodBox fields
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

func (pb *PodBox) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: pb.Namespace, Name: pb.Name}
}

func (pb *NodeBox) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: "", Name: pb.NodeName}
}

func (pb *PodBox) RunBoxes(ctx context.Context, eggi *core.EggInfo) error {
	pb.Lock()
	defer pb.Unlock()

	if len(pb.Containers) < 1 {
		return fmt.Errorf("no containers in pod %s", pb.Name)
	}

	if eggi.ProgramType == common.ProgramTypeTC && pb.Boxer == nil {
		container := pb.Containers[0]
		if container.Ready == true && container.AssetStatus == common.AssetNew {
			boxy := core.NewBoxy(eggi)
			err := boxy.RunWithContainer(ctx, container)
			if err != nil {
				return err
			}

			pb.Boxer = boxy
		}
		return nil
	} else {
		for i := range pb.Containers {
			container := pb.Containers[i]
			if container.Ready == true && container.AssetStatus == common.AssetNew {
				boxy := core.NewBoxy(eggi)
				err := boxy.RunWithContainer(ctx, container)
				if err != nil {
					return err
				}
			}
			container.Boxer = pb.Boxer
		}
	}

	pb.PairedWithEgg = &types.NamespacedName{Namespace: "", Name: eggi.Name}

	return nil
}

func (nb *NodeBox) RunBoxes(ctx context.Context, eggi *core.EggInfo) error {
	nb.Lock()
	defer nb.Unlock()

	boxy := core.NewBoxy(eggi)

	err := boxy.RunWithPid(ctx, uint32(os.Getpid()))
	if err != nil {
		return err
	}

	nb.Boxer = boxy
	nb.PairedWithEgg = &types.NamespacedName{Namespace: "", Name: eggi.Name}

	return nil
}

func (pb *PodBox) StopBoxes() error {
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

func (nb *NodeBox) StopBoxes() error {
	nb.Lock()
	defer nb.Unlock()

	var err error
	var resErr error
	if nb.Boxer != nil {
		err = nb.Boxer.Stop()
		if err != nil {
			return fmt.Errorf("%v\n%v", resErr, err)

		}
	}

	return nil
}
