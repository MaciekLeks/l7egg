package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/user"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"sync"
)

// PodInfo holds POD crucial metadata.
type PodInfo struct {
	//UID       string
	name        string
	labels      map[string]string
	namespace   string
	nodeName    string
	containerID string
}

// PodInfoMap maps Pod namespace name to PodInfo
type PodInfoMap sync.Map

func (c *Controller) handlePodAdd(obj interface{}) {
	c.enqueuePod(obj)
}

func (c *Controller) handlePodDelete(obj interface{}) {
	c.enqueuePod(obj)
}

func (c *Controller) handlePodUpdate(prev interface{}, obj interface{}) {
	podPrev := prev.(*corev1.Pod)
	pod := obj.(*corev1.Pod)
	if podPrev.GetResourceVersion() != pod.GetResourceVersion() {
		//handle only update not sync event
		c.enqueuePod(obj)
	}
}

// enqueue pod takes a Pod resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Foo.
func (c *Controller) enqueuePod(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.podQueue.Add(key)
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Foo resource
// with the current status of the resource.
func (c *Controller) syncPodHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	namespace, name, err := splitNamespaceNameFormKey(key)
	if err != nil {
		return err
	}

	// Get pod with this namespace/name
	pod, err := c.podLister.Pods(namespace).Get(name)
	if err != nil {
		// processing.
		if apierrors.IsNotFound(err) {
			//utilruntime.HandleError(fmt.Errorf("clusteregg '%s' in work queue no longer exists", key))
			err = c.forgetPod(ctx, name) //TODO
			if err != nil {
				return fmt.Errorf("delete clusteregg '%s':%s failed", name, err)
			}
			return nil
		}
		return err
	}

	logger.Info("Update pod info.")
	err = c.updatePodInfo(ctx, pod) //TODO
	if err != nil {
		return fmt.Errorf("update clusteregg '%s':%s failed", name, err)
	}

	c.recorder.Event(pod, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}

func (c *Controller) updatePodInfo(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)
	logger.Info("Update pod info.")

	if _, ok := c.podInfoMap.Load(types.NamespacedName{pod.Namespace, pod.Name}); ok {
		fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!Update not add")
	} else {

		fmt.Println("!!!!!!!!!!!!!!Add")
	}

	return nil
}

func (c *Controller) forgetPod(ctx context.Context, key string) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)
	logger.Info("Delete pod info.")
	return nil
}

//--

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

//func (pim *PodInfoMap) Load(pod *corev1.Pod) (PodInfo, bool) {
//	var pi PodInfo
//	sm := (*sync.Map)(pim)
//	smv, ok := sm.Load(types.NamespacedName{pod.Namespace, pod.Name})
//	if !ok {
//		return pi, false
//	}
//	return smv.(PodInfo), true
//}
