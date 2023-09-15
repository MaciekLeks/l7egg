package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	"github.com/go-logr/logr"
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

	logger.Info("Reconcile clusteregg.")
	err = c.updateEgg(ctx, *cegg)
	if err != nil {
		return fmt.Errorf("update clusteregg '%s':%s failed", name, err)
	}

	logger.Info("Reconcile clusteregg Status.")
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

	logger.Info("updating")
	eggNsNm := types.NamespacedName{Namespace: cegg.Namespace, Name: cegg.Name}

	if ey, ok := c.eggyInfoMap.Load(eggNsNm); ok {
		logger.Info("updating existing egg")
		err := c.updateExistingEggy(ctx, ey, cegg, eggNsNm)
		logger.Info("updating existing egg done")
		return err
	} else {
		logger.Info("adding new egg")
		err := c.addNewEggy(ctx, logger, eggNsNm, cegg)
		logger.Info("adding new egg done")
		return err
	}
}

func (c *Controller) updateExistingEggy(ctx context.Context, ey *core.Eggy, cegg v1alpha1.ClusterEgg, eggNsNm types.NamespacedName) error {
	ney, err := core.NewEggy(cegg)
	if err != nil {
		return fmt.Errorf("failed to create new egg info: %w", err)
	}

	var labelsChanged = !reflect.DeepEqual(ney.PodLabels, ey.PodLabels)
	if labelsChanged {
		err = c.stopNotMatchingBoxySets(ctx, ey, eggNsNm)
		if err != nil {
			return err
		}
	}

	// Updates eggy with new spec, e.g. cidrs, common names, labels
	err = ey.UpdateSpec(ney)
	if err != nil {
		return err
	}

	// Reconciles existing boxy sets with updated eggy
	err = c.updateBoxySet(ctx, eggNsNm)
	if err != nil {
		return err
	}

	// Starts a new boxy set if labels changed
	if labelsChanged {
		// Handle eggy scope for the new pod matching new labels
		if err = c.handleEggyScope(ctx, ey); err != nil {
			return err
		}
	}

	ey.UpdateDone()

	return nil
}

func (c *Controller) addNewEggy(ctx context.Context, logger logr.Logger, eggNsNm types.NamespacedName, ceg v1alpha1.ClusterEgg) error {
	logger.Info("Adding egg")

	ey, err := core.NewEggy(ceg)
	if err != nil {
		return fmt.Errorf("creating eggy '%s' object failed: %s", ceg.Name, err.Error())
	}

	err = c.storeEggy(eggNsNm, ey)
	if err != nil {
		return err
	}

	err = c.handleEggyScope(ctx, ey)
	if err != nil {
		return err
	}

	ey.UpdateDone()

	return nil
}

func (c *Controller) stopNotMatchingBoxySets(ctx context.Context, ey *core.Eggy, eggNsNm types.NamespacedName) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", ey.Name)
	var err error
	c.podyInfoMap.Range(func(podNsnm types.NamespacedName, py *Pody) bool {
		if py.PairedWithEgg != nil && *py.PairedWithEgg == eggNsNm {
			// Labels changed, perform your logic here
			// Stop the box if needed
			logger.Info("Stopping box", "pod", py)
			err = py.StopBoxySet()
			if err != nil {
				err = fmt.Errorf("can't stop boxy set for pod %s", py)
				return false
			}
			logger.Info("boxy set stopped", "pody", py)
		}
		return true
	})
	return err
}

func (c *Controller) updateBoxySet(ctx context.Context, eggNsNm types.NamespacedName) error {
	var err error
	c.podyInfoMap.Range(func(podNsNm types.NamespacedName, py *Pody) bool {
		if py.PairedWithEgg != nil && *py.PairedWithEgg == eggNsNm {
			err = py.ReconcileBoxySet(ctx)
			if err != nil {
				err = fmt.Errorf("updating clusteregg '%s': %s failed", err.Error())
				return false
			}
		}
		return true
	})
	return err
}

func (c *Controller) storeEggy(eggNsNm types.NamespacedName, ey *core.Eggy) error {
	c.eggyInfoMap.Store(eggNsNm, ey)
	return nil
}

func (c *Controller) handleEggyScope(ctx context.Context, ey *core.Eggy) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", ey.Name)
	// Determine if it's a cluster scope egg
	if len(ey.PodLabels) == 0 {
		// cluster scope cegg
		// Handle the logic for a cluster scope egg
		// For example, starting a fake node pod
		logger.Info("Staring NODE box with cegg.", "pod", nil)
		fakeNodePod, err := NewNodePody("fake-node-pod")

		if err != nil {
			return fmt.Errorf("creating fake node pod failed: %s", err.Error())
		}
		if err := fakeNodePod.RunBoxySet(ctx, ey); err != nil {
			return fmt.Errorf("starting fake node pod box failed: %s", err.Error())
		}
		c.podyInfoMap.Store(types.NamespacedName{"", ""}, fakeNodePod)
	} else {
		// pod scope cegg
		// Handle the logic for a pod scope egg
		// Check for matching pods and start boxes if needed
		//if podKeys := c.checkPodMatch(cegg); podKeys.Len() > 0 {
		if podKeys := c.checkMatchesEggy(ey.PodLabels); podKeys.Len() > 0 {
			for i := 0; i < podKeys.Len(); i++ {
				py, ok := c.podyInfoMap.Load(podKeys.Get(i))
				if ok {
					if py.PairedWithEgg != nil {
						return fmt.Errorf("pod '%s' already paired with egg '%s'", podKeys.Get(i).String(), py.PairedWithEgg.String())
					}

					logger.Info("Starting box for the flow egg->pod", "pod", py)
					return py.RunBoxySet(ctx, ey)
				}
			}
		}
	}
	return nil
}

// deleteEgg deletes Eggy and stops its boxes
func (c *Controller) deleteEgg(ctx context.Context, eggNamespaceName types.NamespacedName) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", eggNamespaceName.Name)

	logger.Info("Deleting egg's boxes")
	var err error
	c.podyInfoMap.Range(func(key types.NamespacedName, pb *Pody) bool {
		if pb.PairedWithEgg != nil && *pb.PairedWithEgg == eggNamespaceName {
			logger.Info("Stopping box", "pod", key)
			if err = pb.StopBoxySet(); err != nil {
				logger.Error(err, "stopping box failed", "pod", key)
				return false
			}
		}
		return true
	})

	if err != nil {
		return err
	}

	logger.Info("egg deleted.", "egg", eggNamespaceName)
	ey, ok := c.eggyInfoMap.LoadAndDelete(eggNamespaceName)
	if ok {
		ey.Stop()
	}

	return nil
}

// checkPodyMatchesEggy searches for all matching between cegg PodSelector and pods. Returns slice of pod keys (namespace/name)
func (c *Controller) checkMatchesEggy(podSelector map[string]string) *syncx.SafeSlice[types.NamespacedName] {
	var matchLabels labels.Set = podSelector
	podKeys := syncx.SafeSlice[types.NamespacedName]{}

	c.podyInfoMap.Range(func(key types.NamespacedName, py *Pody) bool {
		selector := matchLabels.AsSelectorPreValidated()
		if selector.Matches(labels.Set(py.Labels)) {
			podKeys.Append(key)
			return true
		}
		return true
	})

	return &podKeys
}
