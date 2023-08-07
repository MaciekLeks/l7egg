package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"reflect"
)

func (c *Controller) handleEggAdd(obj interface{}) {
	//c.enqueueEgg(obj)
	c.handleEggObject(obj)
}

func (c *Controller) handleEggDelete(obj interface{}) {
	c.handleEggObject(obj)
	//c.enqueueEgg(obj)
}

func (c *Controller) handleEggUpdate(prev interface{}, obj interface{}) {
	ceggPrev := prev.(*v1alpha1.ClusterEgg)
	cegg := obj.(*v1alpha1.ClusterEgg)
	if ceggPrev.GetResourceVersion() != cegg.GetResourceVersion() {
		//handle only update not sync event
		//c.enqueueEgg(obj)
		c.handleEggObject(obj)
	}
}

func (c *Controller) handleEggObject(obj interface{}) {
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

	c.enqueueEgg(obj)
}

// enqueue cegg takes a ClusterEgg resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Foo.
func (c *Controller) enqueueEgg(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.ceggQueue.Add(key)
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Foo resource
// with the current Status of the resource.
func (c *Controller) syncEggHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	namespace, name, err := splitNamespaceNameFormKey(key)
	if err != nil {
		return err
	}

	// Get the ClusterEgg with this /name
	cegg, err := c.ceggLister.Get(name)
	if err != nil {
		// The ClusterEgg  may no longer exist, in which case we stop
		// processing.
		if apierrors.IsNotFound(err) {
			//utilruntime.HandleError(fmt.Errorf("clusteregg '%s' in work queue no longer exists", key))
			logger.Info("Delete clusteregg.")
			err = c.deleteEgg(ctx, types.NamespacedName{Namespace: namespace, Name: name})
			if err != nil {
				return fmt.Errorf("delete clusteregg '%s':%s failed", name, err)
			}
			return nil
		}
		return err
	}

	logger.Info("Update clusteregg.")
	err = c.updateEgg(ctx, *cegg)
	if err != nil {
		return fmt.Errorf("update clusteregg '%s':%s failed", name, err)
	}

	logger.Info("Update clusteregg Status.")
	err = c.updateEggStatus(ctx, cegg)
	if err != nil {
		return err
	}

	c.recorder.Event(cegg, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}

func (c *Controller) updateEggStatus(ctx context.Context, cegg *v1alpha1.ClusterEgg) error {
	// cegg is from the store, so we can't modify it, we need to deep copy it first
	ceggCopy := cegg.DeepCopy()
	ceggCopy.Status.Ready = true
	_, err := c.ceggClientset.MaciekleksV1alpha1().ClusterEggs().UpdateStatus(ctx, ceggCopy, metav1.UpdateOptions{})
	return err
}

func (c *Controller) updateEgg(ctx context.Context, cegg v1alpha1.ClusterEgg) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", cegg.Name)

	logger.Info("tbd - 0")
	fmt.Println("tbd - 0p")
	//manager := core.BpfManagerInstance()
	var err error

	logger.Info("tbd - 1")
	fmt.Println("tbd - 1p")
	// Either add or update
	// If the egg already exists, update it
	eggNsNm := types.NamespacedName{Namespace: cegg.Namespace, Name: cegg.Name}
	if eggi, ok := c.eggInfoMap.Load(eggNsNm); ok {
		//changed := false
		//err = eggi.Set(func(eggi *core.EggInfo) error {
		neggi, err := core.NewEggInfo(cegg)

		if err != nil {
			return fmt.Errorf("failed to create new egg info: %w", err)
		}

		fmt.Printf("\ntbd -update- eggi p:%p\n", eggi)
		//egg already exists
		fmt.Printf("tbd - 2p - update: %+v\n", eggi)
		logger.Info("Updating egg")

		if eq := reflect.DeepEqual(neggi.PodLabels, eggi.PodLabels); !eq {
			c.podInfoMap.Range(func(podNsnm types.NamespacedName, pb *Pody) bool {
				// Find all boxes using the same egg specified by the cegg

				if *pb.PairedWithEgg == eggNsNm {
					if len(podNsnm.Namespace) > 0 && len(podNsnm.Name) > 0 {
						if matched := c.checkSinglePodMatch(*pb, cegg); !matched {
							logger.Info("Stopping box", "pod", pb)
							err = pb.StopBoxes()
							if err != nil {
								logger.Error(err, "can't stop box", "pod", pb)
							}
							logger.Info("Box stopped", "pb", pb)
						} else {
							logger.Info("Egg labels changes but still match", "pod", pb)
						}
					}
				}
				return true
			})

			// a new pods may match right now:)

			if podKeys := c.checkPodMatch(cegg); podKeys.Len() > 0 {
				for i := 0; i < podKeys.Len(); i++ {
					//TODO: {refactor to one method
					pb, ok := c.podInfoMap.Load(podKeys.Get(i))
					if ok {
						if pb.PairedWithEgg != nil {
							return fmt.Errorf("pod '%s' already paired with egg '%s'", podKeys.Get(i).String(), pb.PairedWithEgg.String())
						}

						logger.Info("Starting box for the flow egg->pod", "pb", pb)
						return pb.RunBoxySet(ctx, eggi)

					}
					//}
				}
			}
		}

		if err != nil {
			return err
		}

		err = eggi.Update(cegg)
		if err != nil {
			return err
		}

		// update CNs, CIDRs,...for remaining boxes
		logger.Info("Updating egg for CNs, CIDRs....")
		c.podInfoMap.Range(func(podNsNm types.NamespacedName, py *Pody) bool {
			// Find all boxes using the same egg specified by the cegg
			if *py.PairedWithEgg == eggNsNm {
				err = py.UpdateBoxes(ctx)
				if err != nil {
					err = fmt.Errorf("updating clusteregg '%s': %s failed", cegg.Name, err.Error())
					return false
				}
			}
			return true
		})

		return err
		//	})

	} else {
		//new egg
		logger.Info("Adding egg")

		eggi, err := core.NewEggInfo(cegg)
		if err != nil {
			return fmt.Errorf("creating egginfo '%s' object failed: %s", cegg.Name, err.Error())
		}

		// store eggInfo in map
		err = eggi.Set(func(eggi *core.EggInfo) error {
			fmt.Printf("\ntbd -add- eggi p:%p\n", eggi)
			c.eggInfoMap.Store(eggNsNm, eggi)
			// BoxStart cluster scope egg only if podLabels is empty
			if len(eggi.PodLabels) == 0 {
				// cluster scope cegg
				//err = manager.BoxStore(ctx, boxKey, eggi)
				if err != nil {
					return fmt.Errorf("storing box '%s' failed: %s", cegg.Name, err.Error())
				}
				logger.Info("Staring NODE box with cegg.", "pod", nil)
				fakeNodePod, err := NewNodePody("fake-node-pod")

				if err != nil {
					return fmt.Errorf("creating fake node pod failed: %s", err.Error())
				}
				if err := fakeNodePod.RunBoxySet(ctx, eggi); err != nil {
					return fmt.Errorf("starting fake node pod box failed: %s", err.Error())
				}
				c.podInfoMap.Store(types.NamespacedName{"", ""}, fakeNodePod)
			} else {
				if podKeys := c.checkPodMatch(cegg); podKeys.Len() > 0 {
					for i := 0; i < podKeys.Len(); i++ {
						pb, ok := c.podInfoMap.Load(podKeys.Get(i))
						if ok {
							if pb.PairedWithEgg != nil {
								return fmt.Errorf("pod '%s' already paired with egg '%s'", podKeys.Get(i).String(), pb.PairedWithEgg.String())
							}

							logger.Info("Starting box for the flow egg->pod", "pod", pb)
							return pb.RunBoxySet(ctx, eggi)
						}
						//
					}
				}
			}
			return nil
		})
	} // end of else

	return err
}

// deleteEgg deletes EggInfo and stops its boxes
func (c *Controller) deleteEgg(ctx context.Context, eggNamespaceName types.NamespacedName) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", eggNamespaceName.Name)

	logger.Info("Deleting egg's boxes")
	var err error
	c.podInfoMap.Range(func(key types.NamespacedName, pb *Pody) bool {
		if *pb.PairedWithEgg == eggNamespaceName {
			logger.Info("Stopping box", "pod", key)
			if err = pb.StopBoxes(); err != nil {
				logger.Error(err, "stopping box failed", "pod", key)
				return false
			}
		}
		return true
	})

	if err != nil {
		return err
	}

	logger.Info("Egg deleted.")
	c.eggInfoMap.Delete(eggNamespaceName)

	return nil
}

// checkPodMatch searches for all matchings between cegg PodSelector and pods. Returns TODO ???
func (c *Controller) checkPodMatch(cegg v1alpha1.ClusterEgg) *syncx.SafeSlice[types.NamespacedName] {
	var matchLabels labels.Set
	var err error
	podKeys := syncx.SafeSlice[types.NamespacedName]{}

	if cegg.Spec.Egress.PodSelector.Size() != 0 {
		matchLabels, err = metav1.LabelSelectorAsMap(cegg.Spec.Egress.PodSelector)
		if err != nil {
			utilruntime.HandleError(err)
			return nil
		}
	}

	//fmt.Println("****************** +++++ checkPodMach podCacheSynced:%t ceggCacheSynced:%t", c.podCacheSynced(), c.podCacheSynced())

	c.podInfoMap.Range(func(key types.NamespacedName, pi *Pody) bool {
		selector := matchLabels.AsSelectorPreValidated()
		if selector.Matches(labels.Set(pi.Labels)) {
			podKeys.Append(key)
			//fmt.Println("****************** +++++ checkPodMach key:%v added", key)
			return true
		}
		return true
	})

	/*
		if podKeys.Len() > 0 {
			fmt.Println("+++++ checkPodMatch found no matching pod to egg")
		} else {

			fmt.Println("+++++ checkPodMatch found matching pod to policy")
		}*/

	return &podKeys
}

// checkSinglePodMatch matches pod info with cegg PdoSelector and returns true if matches
func (c *Controller) checkSinglePodMatch(pi Pody, cegg v1alpha1.ClusterEgg) bool {
	var matchLabels labels.Set
	var err error

	if cegg.Spec.Egress.PodSelector.Size() != 0 {
		matchLabels, err = metav1.LabelSelectorAsMap(cegg.Spec.Egress.PodSelector)
		if err != nil {
			utilruntime.HandleError(err)
			return false
		}
	}

	selector := matchLabels.AsSelectorPreValidated()
	if selector.Matches(labels.Set(pi.Labels)) {
		return true
	}

	return false
}
