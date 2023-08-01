package common

import (
	//"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/MaciekLeks/l7egg/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sync"
)

// PodInfo holds POD crucial metadata.
type PodInfo struct {
	sync.RWMutex
	//UID       string
	Name            string
	Namespace       string
	Labels          map[string]string
	NodeName        string
	Containers      []*ContainerInfo
	MatchedKeyBoxes []BoxKey
}

func NewPodInfo(pod *corev1.Pod) (*PodInfo, error) {
	containers, err := ExtractContainersInfo(pod)
	if err != nil {
		return nil, err
	}

	podNodeHostname, err := utils.CleanHostame(pod.Spec.NodeName)
	if err != nil {
		return nil, err
	}

	pi := &PodInfo{
		Name:       pod.Name,
		Namespace:  pod.Namespace,
		Labels:     pod.Labels,
		NodeName:   podNodeHostname,
		Containers: containers,
	}

	return pi, nil
}

// Set sets in a safe manner PodInfo fields.
func (pi *PodInfo) Set(fn func(v *PodInfo) error) error {
	pi.Lock()
	defer pi.Unlock()
	return fn(pi)
}

//func (pi *PodInfo) Update(pod *corev1.Pod) (bool, error) {
//	var changed bool
//	pi.RLock()
//	defer pi.RUnlock()
//
//	npi, err := NewPodInfo(pod)
//	if err != nil {
//		return changed, err
//	}
//
//	if reflect.DeepEqual(&pi, &npi) {
//		changed = true
//		// Update PodInfo fields
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

func (pi *PodInfo) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: pi.Namespace, Name: pi.Name}
}
