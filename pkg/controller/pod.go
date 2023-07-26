package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	"github.com/MaciekLeks/l7egg/pkg/utils"
	cgroupsv2 "github.com/containerd/cgroups/v2"
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

// PodInfoMap maps Pod namespace name to PodInfo
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
		err = c.deletePodInfo(ctx, pod)
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

func getContainerdCgroupPath(pid uint32) (string, error) {
	return cgroupsv2.PidGroupPath(int(pid))
}

func (c *Controller) deletePodInfo(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)

	key := types.NamespacedName{pod.Namespace, pod.Name}
	if pi, ok := c.podInfoMap.Load(key); ok {
		manager := core.BpfManagerInstance()
		var err error
		manager.Boxes.Range(func(key core.BoxKey, value *core.EggBox) bool {
			if key.Pod.Name == pi.name && key.Pod.Namespace == pi.namespace {
				logger.Info("Stopping pod info.")
				// Stop clean up the whole box and deletes the key
				err = manager.Stop(key)
				return false
			}
			return true
		})

		logger.Info("Delete pod info.")
		c.podInfoMap.Delete(key)
		if err != nil {
			logger.Error(err, "can't stop box")
			return err
		}
	}

	return nil
}

func (c *Controller) updatePodInfo(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)
	logger.Info("Update pod info.")
	podKey := types.NamespacedName{pod.Namespace, pod.Name}

	var found bool
	var pi *PodInfo
	manager := core.BpfManagerInstance()
	if pi, found = c.podInfoMap.Load(podKey); found {
		//fmt.Println("***************************Update not add ", podKey.String(), pod.Status.Phase, pod.DeletionTimestamp)

		boxKey, foundBox := c.findPodBox(pod)
		var zeroBoxKey core.BoxKey
		fmt.Printf("pi.matchedBoxKey:%+vboxKey:%+v, foundBox: %t \n", pi.matchedKeyBox, boxKey, foundBox)
		if !foundBox && pi.matchedKeyBox != zeroBoxKey {
			//old-matching->cur-not-matching (e.g. someone changed POD label app:test->app:testBlah)

			logger.Info("Stopping box", "box", podKey.String())
			err := manager.Stop(pi.matchedKeyBox)
			if err != nil {
				logger.Error(err, "Can't stop box", "box", podKey.String())
				//TODO are we sure we want to return here?
				return err
			}
			pi.set(func(v *PodInfo) {
				v.matchedKeyBox = zeroBoxKey
			})
			logger.Info("Box stopped", "box", podKey.String())
		}

		if !foundBox {
			if eggKeys := c.checkEggMatch(pod); eggKeys.Len() > 0 {
				//old-not-matching->cur-matching (e.g. someone changed POD label app:testBlah->app:test)
				if eggKeys.Len() > 1 {
					logger.Info("More than one egg matched. Choosing the first one.", "eggs", eggKeys)
				}

				nodeHostname, err := utils.GetHostname()
				if err != nil {
					return err
				}
				podNodeHostname, err := utils.CleanHostame(pod.Spec.NodeName)
				if err != nil {
					return err
				}
				eggKey := eggKeys.Get(0)
				eggi, ok := c.eggInfoMap.Load(eggKey)
				if !ok {
					return fmt.Errorf("egg not found", "egg", eggKey.String())
				}
				boxKey := core.BoxKey{Pod: podKey, Egg: eggKey}

				manager.BoxStore(ctx, boxKey, eggi)

				// only different code against code for ADD
				pi.set(func(v *PodInfo) {
					v.matchedKeyBox = boxKey
				})
				logger.Info("Starting box for the flow pod->egg", "box", podKey.String(), "node", nodeHostname, "pod node", podNodeHostname)
				if nodeHostname == podNodeHostname {
					err = pi.runEgg(ctx, boxKey)
					if err != nil {
						return err
					}
					logger.Info("Box started for the flow pod->egg", "box", podKey.String(), "node", nodeHostname, "pod node", podNodeHostname)
				} /*else {

					fmt.Printf("\n****************{ not running in this node\n")
				}
				fmt.Println("**********************}")*/
			}
		}

		//fmt.Printf("************************Update Done: %+v\n", pi)

	} else { //ADD
		//fmt.Println("***************************Trying to add")
		if pod.Status.Phase == corev1.PodRunning {
			containerdIDs, err := getContainerdIDs(pod.Status.ContainerStatuses)
			if err != nil {
				return err
			}
			podNodeHostname, err := utils.CleanHostame(pod.Spec.NodeName)
			if err != nil {
				return err
			}
			pi := PodInfo{
				name:         pod.Name,
				namespace:    pod.Namespace,
				labels:       pod.Labels,
				nodeName:     podNodeHostname,
				containerIDs: containerdIDs,
				//containerCgroupPaths:
				matchedKeyBox: core.BoxKey{},
			}

			c.podInfoMap.Store(podKey, &pi)
			if eggKeys := c.checkEggMatch(pod); eggKeys.Len() > 0 {
				if eggKeys.Len() > 1 {
					logger.Info("More than one egg matched. Choosing the first one", "eggs", eggKeys)
				}

				nodeHostname, err := utils.GetHostname()
				if err != nil {
					return err
				}

				eggKey := eggKeys.Get(0)
				eggi, ok := c.eggInfoMap.Load(eggKey)
				if !ok {
					return fmt.Errorf("egg not found", "egg", eggKey.String())
				}
				boxKey := core.BoxKey{Pod: podKey, Egg: eggKey}
				pi.set(func(v *PodInfo) {
					v.matchedKeyBox = boxKey
				})
				manager.BoxStore(ctx, boxKey, eggi)

				//fmt.Printf("********************Add Done: %+v\n", pi)

				//fmt.Printf("\n*******************{  ..Startin egg - hostname:%s, pod node:%s\n\n", nodeHostname, podNodeHostname)
				logger.Info("Starting box for the flow pod->egg", "box", podKey.String(), "node", nodeHostname, "pod node", podNodeHostname)
				if nodeHostname == podNodeHostname {
					err = pi.runEgg(ctx, boxKey)
					if err != nil {
						return err
					}
					logger.Info("Box started for the flow pod->egg", "box", podKey.String(), "node", nodeHostname, "pod node", podNodeHostname)
				} /*else {

					fmt.Printf("\n****************{ not running in this node\n")
				}
				fmt.Println("**********************}")*/

			} else {

			}
		} else {
			logger.V(4).Info("Nor update nor add done")
		}
	}

	return nil
}

func (c *Controller) forgetPod(ctx context.Context, key string) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)
	logger.Info("Delete pod info.")
	return nil
}

//--

//func (c *Controller) handleObject(obj interface{}) {
//	pod, ok := obj.(*corev1.Pod)
//	if !ok {
//		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
//		return
//	}
//
//	logger := klog.FromContext(context.Background())
//
//	logger.Info("POD", "name", pod.Name, "namespace", pod.Namespace)
//	for i := range pod.Status.ContainerStatuses {
//		logger.Info("Container", "containerID", pod.Status.ContainerStatuses[i].ContainerID)
//	}
//
//	//Check if egg should be applied
//	fmt.Println("+++++ before checking ")
//	keyBox, ok := c.checkEggMatch(pod)
//	fmt.Println("+++++ after checking ", ok, keyBox)
//
//}

// CheckAny searches for first matching between cegg PodSelector and the pod. Returns keyBox name
func (c *Controller) findPodBox(pod *corev1.Pod) (core.BoxKey, bool) {
	var found bool
	var boxKey core.BoxKey

	manager := core.BpfManagerInstance()
	podLabels := labels.Set(pod.Labels)

	//fmt.Println("****************** +++++ findPodBox podCacheSynced:%t ceggCacheSynced:%t", c.podCacheSynced(), c.podCacheSynced())

	manager.BoxAny(func(key core.BoxKey, box core.IEggBox) bool {
		eggPodLabels := box.Egg().EggInfo.PodLabels
		fmt.Println("+++++ eggPodLabels:", eggPodLabels)
		if len(eggPodLabels) > 0 {
			selector := labels.Set(eggPodLabels).AsSelectorPreValidated()
			//fmt.Printf("\n\nSelector: %s; podLabels:%s\n\n", selector, podLabels)

			if selector.Matches(podLabels) {
				found = true
				boxKey = key
				return false //true
			}
		}
		return true //false
	})

	/*
		if !found {
			fmt.Println("+++++ findPodBox found no matching pod to egg ")
		} else {

			fmt.Println("+++++  findPodBox found matching pod to policy ")
		}*/

	return boxKey, found
}

// checkPodMatch searches for all matchings between cegg PodSelector and pods. Returns TODO ???
func (c *Controller) checkEggMatch(pod *corev1.Pod) *syncx.SafeSlice[types.NamespacedName] {
	eggKeys := syncx.SafeSlice[types.NamespacedName]{}

	podLabels := labels.Set(pod.Labels)

	//fmt.Println("****************** +++++ checkEggMach podCacheSynced:%t ceggCacheSynced:%t", c.podCacheSynced(), c.podCacheSynced())

	c.eggInfoMap.Range(func(key types.NamespacedName, eggi *core.EggInfo) bool {
		matchLabels := labels.Set(eggi.PodLabels)
		selector := matchLabels.AsSelectorPreValidated()
		if selector.Matches(podLabels) {
			eggKeys.Append(key)
			//fmt.Println("****************** +++++ checkEggMach key:%v added", key)
			return true
		}
		return true
	})

	/*
		if eggKeys.Len() > 0 {
			fmt.Println("+++++ checkPodMatch found no matching pod to egg")
		} else {

			fmt.Println("+++++ checkPodMatch found matching pod to policy")
		}*/

	return &eggKeys
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
