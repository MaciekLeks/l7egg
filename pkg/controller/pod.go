package controller

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
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

}

//func (c *Controller) checkAndAddToPodList(pod *corev1.Pod) (bool, error) {
//	m := user.BpfManagerInstance()
//	if policy.Namespace != info.Namespace {
//		return false, nil
//	}
//	if policy.Spec.PodSelector.Size() != 0 {
//		policyMap, err := metav1.LabelSelectorAsMap(&policy.Spec.PodSelector)
//		if err != nil {
//			return false, fmt.Errorf("bad label selector for policy [%s]: %w",
//				types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}.String(), err)
//		}
//		policyPodSelector := labels.Set(policyMap).AsSelectorPreValidated()
//		if !policyPodSelector.Matches(labels.Set(info.Labels)) {
//			return false, nil
//		}
//	}
//	return true, nil
//}
