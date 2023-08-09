package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	"github.com/MaciekLeks/l7egg/pkg/utils"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"strings"
)

// PodInfoMap maps Pod namespace name to Pody
//type PodInfoMap sync.Map

func (c *Controller) handlePodAdd(obj interface{}) {
	//fmt.Println("******************* handlePodAdd, listerSynced:", c.podCacheSynced())
	//c.enqueuePod(obj)
	c.handlePodObject(obj)
}

func (c *Controller) handlePodDelete(obj interface{}) {
	//fmt.Println("******************* handlePodDelete, listerSynced:", c.podCacheSynced())
	//c.enqueuePod(obj)
	c.handlePodAdd(obj)
}

func (c *Controller) handlePodUpdate(prev interface{}, obj interface{}) {
	oldPod := prev.(*corev1.Pod)
	curPod := obj.(*corev1.Pod)

	if oldPod.GetResourceVersion() != curPod.GetResourceVersion() {
		//_json, _ := json.Marshal(curPod.Status)
		//fmt.Printf("******************* handlePodUpdate-change[%s]: old-rev:%s cur-rev: %s \n\n%+v\n\n", curPod.Name, oldPod.GetResourceVersion(), curPod.GetResourceVersion(), string(_json))
		//handle only update not sync event
		//c.enqueuePod(obj)
		c.handlePodObject(obj)
	}
}

func (c *Controller) handlePodObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	logger := klog.FromContext(context.Background())
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		logger.V(4).Info("Recovered deleted object", "resourceName", object.GetName())
	}
	logger.V(4).Info("Processing object", "object", klog.KObj(object))

	c.enqueuePod(obj)
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
// with the current Status of the resource.
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
			logger.Info("Pod in work queue no longer exists.")
			err = c.forgetPod(ctx, name) //TODO
			if err != nil {
				return fmt.Errorf("delete clusteregg '%s':%s failed", name, err)
			}
			return nil
		}
		return err
	}

	if pod.DeletionTimestamp != nil {
		logger.Info("Pod is being deleted.")
		// when a curPod is deleted gracefully it's deletion timestamp is first modified to reflect a grace period,
		// and after such time has passed, the kubelet actually deletes it from the store. We receive an update
		// for modification of the deletion timestamp, not waituntil the kubelet actually deletes the curPod.
		// This is different from the Phase of a curPod changing.
		err = c.deletePody(ctx, pod)
		return err
	}

	//logger.Info("Update pod info.")
	err = c.updatePodInfo(ctx, pod) //TODO
	if err != nil {
		return fmt.Errorf("update pod '%s':%s failed", name, err)
	}

	//c.recorder.Event(pod, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}

func getContainerdIDs(css []corev1.ContainerStatus) ([]string, error) {
	cids := make([]string, len(css))
	var err error
	const crn = "containerd://"
	for i := range css {
		//TODO check Status of the container, e.g. Status, is init container, ...
		if !strings.Contains(css[i].ContainerID, crn) {
			return cids, fmt.Errorf("only containerd supported")
		}
		cid := strings.TrimPrefix(css[i].ContainerID, crn)
		cids[i] = cid
	}
	return cids, err
}

func (c *Controller) deletePody(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)

	key := types.NamespacedName{pod.Namespace, pod.Name}
	if pb, ok := c.podyInfoMap.Load(key); ok {
		if err := pb.StopBoxes(); err != nil {
			logger.Error(err, "can't stop box")
			return err
		}
		logger.Info("Delete pod info.")
		c.podyInfoMap.Delete(key)
	}

	return nil
}

// isPodInStatus checks if the pod is in the given status, e.g. when podCondType=corev1.PodReady and status is "True" then it returns true.
func isPodInStatus(pod *corev1.Pod, podCondType corev1.PodConditionType) bool {
	for _, cond := range pod.Status.Conditions {
		if cond.Type == podCondType && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func (c *Controller) updatePodInfo(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)
	logger.Info("Update pod info.")
	podKey := types.NamespacedName{pod.Namespace, pod.Name}

	//fmt.Printf("******************* pod %s status: \nPodScheduled:%t\nInitialized:%t\nContainersReady:%t\nPodReady:%t\n",
	//	pod.Name,
	//	isPodInStatus(pod, corev1.PodScheduled),
	//	isPodInStatus(pod, corev1.PodInitialized),
	//	isPodInStatus(pod, corev1.ContainersReady),
	//	isPodInStatus(pod, corev1.PodReady))
	//
	//for i := range pod.Status.ContainerStatuses {
	//	fmt.Printf("************** POD container statuses: %+v\n", pod.Status.ContainerStatuses[i])
	//}

	//podJson, err := json.MarshalIndent(pod.Status, "", "    ")
	//if err != nil {
	//	fmt.Println("Błąd podczas konwersji na JSON:", err)
	//	return err
	//}
	if pb, found := c.podyInfoMap.Load(podKey); found && isPodInStatus(pod, corev1.PodReady) {

		//fmt.Println("***************************Update not add ", podKey.String(), pod.Status.Phase, pod.DeletionTimestamp, pb)

		wasPaired := pb.PairedWithEgg != nil && len(pb.PairedWithEgg.Name) > 0
		fmt.Printf("deep[updatePodnfo] wasPaired: %t, pod:%s \n", wasPaired, podKey.String())

		var stillPaired, isMatched bool
		var eggi *core.Eggy
		if eggKeys := c.checkEggMatch(pod); eggKeys.Len() > 0 {
			if eggKeys.Len() > 1 {
				logger.Info("More than one egg matched. Choosing the first one", "eggs", eggKeys)
			}
			eggKey := eggKeys.Get(0)
			var ok bool
			eggi, ok = c.eggInfoMap.Load(eggKey)
			if !ok {
				return fmt.Errorf("egg not found", "egg", eggKey.String())
			}

			isMatched = true
			// all MatchedKeyBoxes must have the same Egg
			if pb.PairedWithEgg != nil && eggi.NamespaceName() == *pb.PairedWithEgg {
				stillPaired = true
				fmt.Printf("deep[updatePodnfo] stillPaired: %t, pod:%s \n", stillPaired, podKey.String())
			}
		}

		if wasPaired && !stillPaired {
			// Stop old boxes
			fmt.Printf("deep[updatePodnfo] stopping boxes pod:%s \n", podKey.String())
			if err := pb.StopBoxes(); err != nil {
				return err
			}

		}

		if isMatched && !stillPaired {
			// Run new boxes
			fmt.Printf("deep[updatePodnfo] running boxes pod:%s \n", podKey.String())
			if err := runBoxySetOnHost(ctx, eggi, pb); err != nil {
				return err
			}
		}

		if isMatched && stillPaired {
			fmt.Printf("deep[updatePodnfo] isMatched:%t stillPaired:%t pod:%s\n", isMatched, stillPaired, podKey.String())
			cpi, err := NewPody(pod)
			if err != nil {
				return err
			}
			// Check: Check containers changes
			fmt.Printf("deep[updatePodnfo][2] isMatched:%t stillPaired:%t pod:%s\n", isMatched, stillPaired, podKey.String())
			if newContainerList, err := pb.Containers.UpdateContainers(cpi.Containers); err == nil {
				err = pb.Set(func(v *Pody) error {
					fmt.Printf("deep[updatePodnfo][3] isMatched:%t stillPaired:%t pod:%s\n", isMatched, stillPaired, podKey.String())
					v.Containers = newContainerList
					return nil
				})
				fmt.Printf("deep[updatePodnfo][4] isMatched:%t stillPaired:%t pod:%s\n", isMatched, stillPaired, podKey.String())
				if err != nil {
					return err
				}
				fmt.Printf("deep[updatePodnfo][5] isMatched:%t stillPaired:%t pod:%s\n", isMatched, stillPaired, podKey.String())
				if err := runBoxySetOnHost(ctx, eggi, pb); err != nil {
					return err
				}
				fmt.Printf("deep[updatePodnfo][6] isMatched:%t stillPaired:%t pod:%s\n", isMatched, stillPaired, podKey.String())
			} else {
				return err
			}
		}

	} else if isPodInStatus(pod, corev1.PodReady) && !found { //ADD
		return c.addPodBox(ctx, pod)
	}

	return nil
}

// RunBoxySetOnHost runs one or many Boxy(s) on the host depends on Eggy.ProgramType and Shaping settings
func runBoxySetOnHost(ctx context.Context, eggi *core.Eggy, pb *Pody) error {
	nodeHostname, err := utils.GetHostname()
	if err != nil {
		return err
	}

	fmt.Println("deep[runBoxesOnHost]", nodeHostname, pb.NodeName)
	if nodeHostname == pb.NodeName {
		err = pb.RunBoxySet(ctx, eggi)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) addPodBox(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)
	podKey := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}

	if pod.Status.Phase == corev1.PodRunning {
		pb, err := NewPody(pod)
		if err != nil {
			return err
		}

		if eggKeys := c.checkEggMatch(pod); eggKeys.Len() > 0 {
			fmt.Printf("deep[controller:addPodBox] - checkEggMatched passed for pod: %s\n", pod.Name)

			if eggKeys.Len() > 1 {
				logger.Info("More than one egg matched. Choosing the first one", "eggs", eggKeys)
			}

			eggKey := eggKeys.Get(0)
			eggi, ok := c.eggInfoMap.Load(eggKey)
			if !ok {
				return fmt.Errorf("egg not found", "egg", eggKey.String())
			}

			err = runBoxySetOnHost(ctx, eggi, pb)
			if err != nil {
				return err
			}

			pb.PairedWithEgg = &eggKey

		} else {
			fmt.Println("**************************** - no egg matched")
		}
		// only now add to the list
		c.podyInfoMap.Store(podKey, pb)
	} else {
		logger.V(4).Info("Nor update nor add done")
	}
	return nil
}

func (c *Controller) forgetPod(ctx context.Context, key string) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)
	logger.Info("Delete pod info.")
	return nil
}

// checkPodMatch searches for all matchings between cegg PodSelector and pods. Returns TODO ???
func (c *Controller) checkEggMatch(pod *corev1.Pod) *syncx.SafeSlice[types.NamespacedName] {
	eggKeys := syncx.SafeSlice[types.NamespacedName]{}
	podLabels := labels.Set(pod.Labels)

	c.eggInfoMap.Range(func(key types.NamespacedName, eggi *core.Eggy) bool {
		matchLabels := labels.Set(eggi.PodLabels)
		selector := matchLabels.AsSelectorPreValidated()
		if selector.Matches(podLabels) {
			eggKeys.Append(key)
			return true
		}
		return true
	})

	//{to be commented:
	if eggKeys.Len() > 0 {
		fmt.Println("||||||||||||||||| checkPodMatch found matching pod to egg(policy)")
	} else {

		fmt.Println("||||||||||||||||||| checkPodMatch NOT found matching pod to egg(policy)")
	}
	//}

	return &eggKeys
}
