package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	"github.com/MaciekLeks/l7egg/pkg/user"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

func (c *Controller) handleCEggAdd(obj interface{}) {
	c.enqueueCEgg(obj)
}

func (c *Controller) handleCEggDelete(obj interface{}) {
	c.enqueueCEgg(obj)
}

func (c *Controller) handleCEggUpdate(prev interface{}, obj interface{}) {
	ceggPrev := prev.(*v1alpha1.ClusterEgg)
	cegg := obj.(*v1alpha1.ClusterEgg)
	if ceggPrev.GetResourceVersion() != cegg.GetResourceVersion() {
		//handle only update not sync event
		c.enqueueCEgg(obj)
	}
}

// enqueue cegg takes a ClusterEgg resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Foo.
func (c *Controller) enqueueCEgg(obj interface{}) {
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
// with the current status of the resource.
func (c *Controller) syncCEggHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	_, name, err := splitNamespaceNameFormKey(key)
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
			err = c.deleteEgg(ctx, name)
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

	logger.Info("Update clusteregg status.")
	err = c.updateCEggStatus(ctx, cegg)
	if err != nil {
		return err
	}

	c.recorder.Event(cegg, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}

func (c *Controller) updateCEggStatus(ctx context.Context, cegg *v1alpha1.ClusterEgg) error {
	// cegg is from the store, so we can't modify it, we need to deep copy it first
	ceggCopy := cegg.DeepCopy()
	ceggCopy.Status.Ready = true
	_, err := c.ceggClientset.MaciekleksV1alpha1().ClusterEggs().UpdateStatus(ctx, ceggCopy, metav1.UpdateOptions{})
	return err
}

func (c *Controller) updateEgg(ctx context.Context, cegg v1alpha1.ClusterEgg) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", cegg.Name)

	manager := user.BpfManagerInstance()
	if manager.BoxExists(cegg.Name) {
		err := manager.UpdateClientEgg(cegg.Name, cegg.Spec.CIDRs, cegg.Spec.CommonNames)
		if err != nil {
			return fmt.Errorf("updating clusteregg '%s': %s failed", cegg.Name, err.Error())
		}
		return nil
	}

	var podLabels map[string]string
	var err error
	if cegg.Spec.PodSelector.Size() != 0 {
		podLabels, err = metav1.LabelSelectorAsMap(cegg.Spec.PodSelector)
		if err != nil {
			return fmt.Errorf("bad label selector for cegg [%s]: %w", cegg.Name, err)
		}
	}

	//TODO tbc
	iiface := cegg.Spec.IngressInterface
	eiface := cegg.Spec.EgressInterface
	if len(podLabels) != 0 {
		iiface = "eth0" //TODO #
		eiface = "eth0" //TODO #
	}
	ceggi, err := manager.NewCEggInfo(iiface, eiface, cegg.Spec.CommonNames, cegg.Spec.CIDRs, podLabels)
	if err != nil {
		return fmt.Errorf("creating clusteregg '%s': %s failed", cegg.Name, err.Error())
	}

	boxKey := cegg.Name
	manager.BoxStore(boxKey, ceggi)

	// BoxStart cluster socpe egg only if podLabels is empty
	if len(podLabels) == 0 {
		// cluster scope cegg
		logger.Info("Staring box with cegg.", "box", boxKey)
		err = manager.BoxStart(ctx, boxKey, "", "")
		if err != nil {
			return fmt.Errorf("starting clusteregg '%s': %s", cegg.Name, err.Error())
		}
	} else {
		logger.Info("-----!!!!!!!!!!!!!!!!!!!!!!--------------Pod scope cegg box not started, waiting for pods.", "box", boxKey)
		if podKeys := c.checkPodMatch(cegg); podKeys.Len() > 0 {
			for i := 0; i < podKeys.Len(); i++ {
				pi, ok := c.podInfoMap.Load(podKeys.Get(i))
				if ok {
					//TODO handle error
					logger.Info("-----!!!!!!!!!!!!!!!!!!!!!!--------------starting egg egg->pod.", "box", boxKey)
					pi.runEgg(ctx, boxKey)
					logger.Info("-----!!!!!!!!!!!!!!!!!!!!!!--------------started egg egg->pod.", "box", boxKey)
				}
			}
		}
	}

	return nil
}

func (c *Controller) deleteEgg(ctx context.Context, name string) error {
	manager := user.BpfManagerInstance()
	return manager.Stop(name)
}

// checkPodMatch searches for all matchings between cegg PodSelector and pods. Returns TODO ???
func (c *Controller) checkPodMatch(cegg v1alpha1.ClusterEgg) *syncx.SafeSlice[types.NamespacedName] {
	var matchLabels labels.Set
	var err error
	podKeys := syncx.SafeSlice[types.NamespacedName]{}

	if cegg.Spec.PodSelector.Size() != 0 {
		matchLabels, err = metav1.LabelSelectorAsMap(cegg.Spec.PodSelector)
		if err != nil {
			utilruntime.HandleError(err)
			return nil
		}
	}

	fmt.Println("****************** +++++ checkPodMach podCacheSynced:%t ceggCacheSynced:%t", c.podCacheSynced(), c.podCacheSynced())

	c.podInfoMap.Range(func(key types.NamespacedName, pi PodInfo) bool {
		selector := matchLabels.AsSelectorPreValidated()
		if selector.Matches(labels.Set(pi.labels)) {
			podKeys.Append(key)
			return true
		}
		return true
	})

	if podKeys.Len() > 0 {
		fmt.Println("+++++ checkPodMatch found no matching pod to egg ")
	} else {

		fmt.Println("+++++ checkPodMatch found matching pod to policy ")
	}

	return &podKeys
}
