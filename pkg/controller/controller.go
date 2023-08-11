package controller

import (
	"context"
	"fmt"
	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	ceggscheme "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned/scheme"
	cegginformer "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions/maciekleks.dev/v1alpha1"
	cegglister "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sync"
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

	ctxAssetKey common.CtxAssetType = "asset"
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

	// podyInfoMap is a map of pody object
	podyInfoMap       syncx.SafeMap[types.NamespacedName, *Pody]
	containeryInfoMap syncx.SafeMap[ContainerName, *Containery]
	eggInfoMap        syncx.SafeMap[types.NamespacedName, *core.Eggy] //namespace not used
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

		//podyInfoMap: PodInfoMap{},
		podyInfoMap: syncx.SafeMap[types.NamespacedName, *Pody]{},
		eggInfoMap:  syncx.SafeMap[types.NamespacedName, *core.Eggy]{},
	}

	logger.Info("Setting up event handlers")

	ceggInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleEggAdd,
			UpdateFunc: c.handleEggUpdate,
			DeleteFunc: c.handleEggDelete,
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
// as syncing informer caches and starting workers.
func (c *Controller) Run(ctx context.Context, ceggWorkers int, podWorkers int) error {
	logger := klog.FromContext(ctx)
	logger.Info("Starting controller.")

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
		// Install c.runWorker again after 1 sec only the previous launch ends
		go func() {
			fmt.Println("waiting...............................")
			time.Sleep(5 * time.Second)
			fmt.Println("waiting.............................../done")
			wait.UntilWithContext(context.WithValue(ctx, ctxAssetKey, ctxCeggValue), c.runWorker, 1*time.Second)
		}()
	}

	logger.Info("Starting pod workers.", "count", podWorkers)
	// Launch 1..* workers to process pods resources
	for i := 0; i < podWorkers; i++ {
		// Install c.runWorker again after 1 sec only the previous launch ends
		go wait.UntilWithContext(context.WithValue(ctx, ctxAssetKey, ctxPodValue), c.runWorker, 1*time.Second)
	}

	logger.Info("deep[controller:Install] - workers started")
	//<-ctx.Done()
	//logger.Info("deep[controller:Install] - shutting down workers.")

	return nil
}

// Wait waits for all workers to be done processing work. It's blocking until ctx channel is closed,
// at which point it will shut down the ceggQueue and wait for workers to finish processing their current work items.
func (c *Controller) Wait(ctx context.Context) {
	defer utilruntime.HandleCrash()
	defer c.ceggQueue.ShutDown()
	defer c.podQueue.ShutDown()

	logger := klog.FromContext(ctx)
	done := ctx.Done()
	wg := sync.WaitGroup{}

	logger.Info("deep[Waiting] starts\n")
	//waits until done is closed
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("deep[Waiting]before <-done\n")
		<-done
		fmt.Printf("deep[Waiting]after <-done\n")
		c.podyInfoMap.Range(func(podNsNm types.NamespacedName, py *Pody) bool {
			fmt.Printf("deep[Waiting][range][0] - %s\n", podNsNm)
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Printf("deep[Waiting][range][1] - %s\n", podNsNm)
				if err := py.StopBoxes(); err != nil {
					fmt.Printf("deep[Waiting][range][error] - %s - %s\n", podNsNm, err)
				}

				fmt.Printf("deep[Waiting][range][2] - %s\n", podNsNm)
			}()
			return true
		})
	}()

	fmt.Printf("deep[Waiting] for all pody finishes\n")
	wg.Wait()
	fmt.Printf("deep[Waiting] done.\n")

}

// runWorker is a long-running function that  continually call the
// processNextWorkItem function in order to read and process a message on the
// ceggQueue.
func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

// processNextWorkItem will read a single work item off a queue and
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

		// Install the syncHandler, passing it the namespace/name string of the
		// Foo resource to be synced.
		if err = c.syncHandler(ctx, key); err != nil {
			c.queueAddRateLimited(ctx, key)
			fmt.Printf("deep[processNextWorkItem] after queueAddRateLimited %s\n", err)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}

		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		if err = c.queueForget(ctx, key); err != nil {
			fmt.Printf("deep[processNextWorkItem] after queueForget %s\n", err)
			return err
		}
		logger.Info("Successfully synced.", "resourceName", key)

		return nil
	}(key)

	if err != nil {
		fmt.Printf("deep[processNextWorkItem] before HandleError %s\n", err)
		utilruntime.HandleError(err)
		return true
	}

	return true
}
