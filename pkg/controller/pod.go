package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/user"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
)

// PodStub to hold POD crucial info.
type PodInfo struct {
	//UID       string
	name        string
	labels      map[string]string
	namespace   string
	nodeName    string
	containerID string
}

func (c *Controller) handleObject(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}

	logger := klog.FromContext(context.Background())

	logger.Info("POD", "name", pod.Name, "namespace", pod.Namespace)
	for i := range pod.Status.ContainerStatuses {
		logger.Info("Container", "containerID", pod.Status.ContainerStatuses[i].ContainerID)
	}

	//Check if egg should be applied
	fmt.Println("+++++ before checking ")
	ok, keyBox := c.checkAny(pod)
	fmt.Println("+++++ after checking ", ok, keyBox)

}

// CheckAny searches for first matching between cegg PodSelector and the pod. Returns keyBox name
func (c *Controller) checkAny(pod *corev1.Pod) (bool, string) {
	var found bool
	var keyBox string

	manager := user.BpfManagerInstance()
	podLabels := labels.Set(pod.Labels)

	manager.BoxAny(func(key string, box user.IClientEggBox) bool {
		eggPodLabels := box.GetEgg().ClientEgg.PodLabels
		fmt.Println("+++++ eggPodLabels:", eggPodLabels)
		if len(eggPodLabels) > 0 {
			selector := labels.Set(eggPodLabels).AsSelectorPreValidated()
			fmt.Printf("\n\nSelector: %s; podLabels:%s\n\n", selector, podLabels)

			if selector.Matches(podLabels) {
				found = true
				keyBox = key
				return true
			}
		}
		return false
	})

	if !found {
		fmt.Println("+++++ found no matching pod to egg ")
	} else {

		fmt.Println("+++++ found matching pod to policy ")
	}

	return found, keyBox
}
