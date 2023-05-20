package controller

import (
	"context"
	"fmt"
	ceggscheme "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned/scheme"
	"github.com/MaciekLeks/l7egg/pkg/tools"
	"github.com/MaciekLeks/l7egg/pkg/user"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/record"

	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	cegginformer "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions/maciekleks.dev/v1alpha1"
	cegglister "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
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

	ctxAssetKey ctxAssetType = "asset"
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

	ceggQueue workqueue.RateLimitingInterface
	podQueue  workqueue.RateLimitingInterface

	recorder record.EventRecorder

	podInfoMap tools.SafeMap[types.NamespacedName, PodInfo]
}

const (
	ceggQueueName string = "ceggs"
	podQueueName  string = "pods"
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
		kubeClientset: kubeClientset,
		ceggClientset: ceggClientset,

		ceggLister:      ceggInformer.Lister(),
		ceggCacheSynced: ceggInformer.Informer().HasSynced,

		podLister:      podInformer.Lister(),
		podCacheSynced: podInformer.Informer().HasSynced,

		ceggQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), ceggQueueName),
		podQueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), podQueueName),

		recorder: recorder,

		//podInfoMap: PodInfoMap{},
		podInfoMap: tools.SafeMap[types.NamespacedName, PodInfo]{},
	}

	logger.Info("Setting up event handlers")

	ceggInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleCEggAdd,
			UpdateFunc: c.handleCEggUpdate,
			DeleteFunc: c.handleCEggDelete,
		},
	)

	podInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			//AddFunc: c.handleObject,
			//UpdateFunc: func(old, new interface{}) {
			//	newPod := new.(*corev1.Pod)
			//	oldPod := old.(*corev1.Pod)
			//	if newPod.ResourceVersion == oldPod.ResourceVersion {
			//		return
			//	}
			//	c.handleObject(new)
			//},
			//DeleteFunc: c.handleObject,
			AddFunc:    c.handlePodAdd,
			UpdateFunc: c.handlePodUpdate,
			DeleteFunc: c.handlePodDelete,
		},
	)

	return c
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shut down the ceggQueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(ctx context.Context, ceggWorkers int, podWorkers int) error {
	defer utilruntime.HandleCrash()
	defer c.ceggQueue.ShutDown()
	logger := klog.FromContext(ctx)

	logger.Info("Starting l7egg controller.")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync.")
	if ok := cache.WaitForCacheSync(ctx.Done(), c.ceggCacheSynced); !ok {
		return fmt.Errorf("Failed to wait for ceggs cache to sync.")
	}
	if ok := cache.WaitForCacheSync(ctx.Done(), c.podCacheSynced); !ok {
		return fmt.Errorf("Failed to wait for pods cache to sync.")
	}

	logger.Info("Starting cegg workers.", "count", ceggWorkers)
	// Launch 1..* workers to process ceggs resources
	for i := 0; i < ceggWorkers; i++ {
		// Run c.runWorker again after 1 sec only the previous launch ends
		go wait.UntilWithContext(context.WithValue(ctx, ctxAssetKey, ctxCeggValue), c.runWorker, 1*time.Second)
	}

	logger.Info("Starting pod workers.", "count", podWorkers)
	// Launch 1..* workers to process pods resources
	for i := 0; i < podWorkers; i++ {
		// Run c.runWorker again after 1 sec only the previous launch ends
		go wait.UntilWithContext(context.WithValue(ctx, ctxAssetKey, ctxPodValue), c.runWorker, 1*time.Second)
	}

	logger.Info("Started workers.")
	<-ctx.Done()
	logger.Info("Shutting down workers.")

	return nil
}

func (c *Controller) Wait() {
	user.BpfManagerInstance().Wait()
}

// runWorker is a long-running function that  continually call the
// processNextWorkItem function in order to read and process a message on the
// ceggQueue.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem will read a single work item off the ceggQueue and
// attempt to process it, by calling the syncHandler.
func (c *Controller) processNextWorkItem(ctx context.Context) bool {

	key, quit, err := c.queueGet(ctx) //blocking op
	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	logger := klog.FromContext(ctx)

	if quit {
		return false
	}

	// We wrap this block in a func so we can defer c.ceggQueue.Done.
	err = func(key string) error {
		// We call Done here so the ceggQueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the ceggQueue and attempted again after a back-off
		// period.
		defer func() {
			err = c.queueDone(ctx, key)
			utilruntime.HandleError(err)
		}()

		// Run the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err = c.syncHandler(ctx, key); err != nil {
			err = c.queueAddRateLimited(ctx, key)
			if err != nil {
				return err
			}
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}

		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		if err = c.queueForget(ctx, key); err != nil {
			return err
		}
		logger.Info("Successfully synced.", "resourceName", key)

		return nil
	}(key)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}
