package controller

import (
	"context"
	"fmt"
	ceggscheme "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	corev1 "k8s.io/api/core/v1"

	//"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	cegginformer "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions/maciekleks.dev/v1alpha1"
	cegglister "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/user"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"time"
)

const controllerAgentName = "l7egg-controller"

const (
	// SuccessSynced is used as part of the Event 'reason' when a CllusterEgg is synced
	SuccessSynced = "Synced"
	// ErrResourceExists is used as part of the Event 'reason' when a ClusterEgg fails
	// to sync due to a Deployment of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceSynced is the message used for an Event fired when a ClusterEgg
	// is synced successfully
	MessageResourceSynced = "ClusterEgg synced successfully"
)

type Controller struct {
	// kubeclientset is a standard kubernetes clientset
	kubeClientset kubernetes.Interface
	// ceggClientset is a clientset for our API group
	ceggClientset ceggclientset.Interface

	ceggCacheSynced cache.InformerSynced
	ceggLister      cegglister.ClusterEggLister

	podLister      corelisters.PodLister
	podCacheSynced cache.InformerSynced

	workqueue workqueue.RateLimitingInterface
	recorder  record.EventRecorder
}

const (
	queueName string = "clusterEgg"
)

func NewController(ctx context.Context,
	kubeClientset kubernetes.Interface,
	ceggClientset ceggclientset.Interface,
	ceggInformer cegginformer.ClusterEggInformer,
	podInformer coreinformers.PodInformer) *Controller {
	logger := klog.FromContext(ctx)
	// Create event broadcaster
	// Add clientegg types to the default Kubernetes Scheme so Events can be
	// logged for clientegg types.
	utilruntime.Must(ceggscheme.AddToScheme(scheme.Scheme))
	logger.V(2).Info("Creating event broadcaster")

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	c := &Controller{
		kubeClientset:   kubeClientset,
		ceggClientset:   ceggClientset,
		ceggLister:      ceggInformer.Lister(),
		ceggCacheSynced: ceggInformer.Informer().HasSynced,
		podLister:       podInformer.Lister(),
		podCacheSynced:  podInformer.Informer().HasSynced,
		workqueue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), queueName),
		recorder:        recorder,
	}

	logger.Info("Setting up event handlers")

	ceggInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleClusterEggAdd,
			UpdateFunc: c.handleClusterEggUpdate,
			DeleteFunc: c.handleClusterEggDelete,
		},
	)

	podInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: c.handleObject,
			UpdateFunc: func(old, new interface{}) {
				newPod := new.(*corev1.Pod)
				oldPod := old.(*corev1.Pod)
				if newPod.ResourceVersion == oldPod.ResourceVersion {
					return
				}
				c.handleObject(new)
			},
			DeleteFunc: c.handleObject,
		},
	)

	return c
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shut down the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()
	logger := klog.FromContext(ctx)

	logger.Info("Starting l7egg controller.")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync.")
	if ok := cache.WaitForCacheSync(ctx.Done(), c.ceggCacheSynced); !ok {
		return fmt.Errorf("Failed to wait for cache to sync.")
	}

	logger.Info("Starting workers.", "count", workers)
	// Launch two workers to process Foo resources
	for i := 0; i < workers; i++ {
		// Run c.runWorker again after 1 sec only the previous launch ends
		go wait.UntilWithContext(ctx, c.runWorker, 1*time.Second)
	}

	logger.Info("Started workers.")
	<-ctx.Done()
	logger.Info("Shutting down workers.")

	return nil
}

// enqueueFoo takes a Foo resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Foo.
func (c *Controller) enqueueClusterEgg(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.Add(key)
}

// runWorker is a long-running function that will continually call the
// processNextWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	obj, quit := c.workqueue.Get() //blocking op
	logger := klog.FromContext(ctx)

	if quit {
		return false
	}

	// We wrap this block in a func so we can defer c.workqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.workqueue.Done(obj)
		var key string
		var ok bool

		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err := c.syncHandler(ctx, key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.workqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.workqueue.Forget(obj)
		logger.Info("Successfully synced.", "resourceName", key)
		return nil

	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Foo resource
// with the current status of the resource.
func (c *Controller) syncHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
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
	err = c.updateStatus(ctx, cegg)
	if err != nil {
		return err
	}

	c.recorder.Event(cegg, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}

func (c *Controller) updateStatus(ctx context.Context, cegg *v1alpha1.ClusterEgg) error {
	// cegg is from the store, so we can't modify it, we need to deep copy it first
	ceggCopy := cegg.DeepCopy()
	ceggCopy.Status.Ready = true
	_, err := c.ceggClientset.MaciekleksV1alpha1().ClusterEggs().UpdateStatus(context.TODO(), ceggCopy, metav1.UpdateOptions{})
	return err
}

func (c *Controller) Wait() {
	user.BpfManagerInstance().Wait()
}

func (c *Controller) updateEgg(ctx context.Context, cegg v1alpha1.ClusterEgg) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", cegg.Name)

	manager := user.BpfManagerInstance()
	if manager.Exists(cegg.Name) {
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

	clientegg, err := manager.NewClientEgg(cegg.Spec.IngressInterface, cegg.Spec.EgressInterface, cegg.Spec.CommonNames, cegg.Spec.CIDRs, podLabels)
	if err != nil {
		return fmt.Errorf("creating clusteregg '%s': %s failed", cegg.Name, err.Error())
	}

	boxKey := cegg.Name

	logger.Info("Staring box with clientegg.")
	err = manager.Start(ctx, boxKey, clientegg)
	if err != nil {
		return fmt.Errorf("starting clusteregg '%s': %s box failed", cegg.Name, err.Error())
	}

	return nil
}

func (c *Controller) deleteEgg(ctx context.Context, name string) error {
	manager := user.BpfManagerInstance()
	return manager.Stop(name)
}

func (c *Controller) handleClusterEggAdd(obj interface{}) {
	c.enqueueClusterEgg(obj)
}

func (c *Controller) handleClusterEggDelete(obj interface{}) {
	c.enqueueClusterEgg(obj)
}

func (c *Controller) handleClusterEggUpdate(prev interface{}, obj interface{}) {
	ceggPrev := prev.(*v1alpha1.ClusterEgg)
	cegg := obj.(*v1alpha1.ClusterEgg)
	if ceggPrev.GetResourceVersion() != cegg.GetResourceVersion() {
		//handle only update not sync event
		c.enqueueClusterEgg(obj)
	}
}
