package controller

import (
	"context"
	"fmt"
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
	"log"
	"time"
)

type Controller struct {
	ceggClientset   ceggclientset.Interface
	ceggCacheSynced cache.InformerSynced
	ceggLister      cegglister.ClusterEggLister
	workqueue       workqueue.RateLimitingInterface
	//wg              sync.WaitGroup
	//clienteggs map[string]user.ClientEgg
}

const (
	queueName string = "clusterEgg"
)

func NewController(ceggClientset ceggclientset.Interface, ceggInformer cegginformer.ClusterEggInformer) *Controller {
	c := &Controller{
		ceggClientset:   ceggClientset,
		ceggLister:      ceggInformer.Lister(),
		ceggCacheSynced: ceggInformer.Informer().HasSynced,
		workqueue:       workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), queueName),
		//clienteggs:      map[string]user.ClientEgg{},
	}

	ceggInformer.Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleAdd,
			UpdateFunc: c.handleUpdate,
			DeleteFunc: c.handleDelete,
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
	logger.Info("Waiting for informer caches to sync")
	if ok := cache.WaitForCacheSync(ctx.Done(), c.ceggCacheSynced); !ok {
		return fmt.Errorf("Failed to wait for cache to sync.")
	}

	logger.Info("Starting workers", "count", workers)
	// Launch two workers to process Foo resources
	for i := 0; i < workers; i++ {
		// Run c.worker again after 1 sec only the previous launch ends
		go wait.UntilWithContext(ctx, c.worker, 1*time.Second)
	}

	logger.Info("Started workers.")
	<-ctx.Done()
	logger.Info("Shutting down workers.")

	return nil
}

func (c *Controller) worker(ctx context.Context) {
	workFunc := func() bool {

		fmt.Println("--->>>before BpfManagerInstance")
		keyObj, quit := c.workqueue.Get() //blocking op
		defer fmt.Println("--->>>processNextItem ended.")
		if quit {
			log.Println("--->>> Cache shut down.")
			return true
		}
		defer c.workqueue.Done(keyObj)

		fmt.Println("--->>>after BpfManagerInstance")

		key, err := cache.MetaNamespaceKeyFunc(keyObj)
		if err != nil {
			log.Printf("--->>>Getting key(<ns>/<name>) from cache %s\n", err)
			return false
		}
		_, name, err := cache.SplitMetaNamespaceKey(key) //namespace not expected here
		if err != nil {
			log.Printf("--->>>Splitting key (<ns>/<name>) into name %s\n", err)
			return false
		}

		fmt.Printf("--->>>cluster object name: %s\n", name)

		cegg, err := c.ceggLister.Get(name)
		if err == nil {
			// The ClusterEgg still exists in informer cache, the event must have
			// been add/update
			fmt.Printf("--->>>clusteregg object: %+v\n", cegg)
			c.updateEgg(ctx, *cegg)
			return false
		}
		//check directly on the server (not lister) if the object has been deleted form the k8s cluster
		//cegg, err := c.ceggClientset.MaciekleksV1alpha1().ClusterEggs().BpfManagerInstance(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			log.Printf("--->>>Handle delete for clusteregg %s\n", name)
		}

		//err = c.reconcile(ns, name)
		//if err != nil {
		//	//re-try
		//	fmt.Printf("Reconciling %s\n", err)
		//	return false
		//}
		c.deleteEgg(ctx, name)
		return false
	}
	for {
		if quit := workFunc(); quit {
			fmt.Println("--->>>Worker workqueue shutting down")
			return
		}
	}
}

func (c *Controller) Wait() {
	user.BpfManagerInstance().Wait()
}

func (c *Controller) updateEgg(ctx context.Context, cegg v1alpha1.ClusterEgg) {

	manager := user.BpfManagerInstance()
	if manager.Exists(cegg.Name) {
		err := manager.UpdateClientEgg(cegg.Name, cegg.Spec.CIDRs, cegg.Spec.CommonNames)
		if err != nil {
			fmt.Printf("****>>>Updating CIDRs, CNs %#v", err)
			return
		}
		fmt.Println("****>>>Updating")
		return
	}

	clientegg, err := manager.NewClientEgg(cegg.Spec.IngressInterface, cegg.Spec.EgressInterface, cegg.Spec.CommonNames, cegg.Spec.CIDRs)
	if err != nil {
		return
	}

	boxKey := cegg.Name
	manager.Start(ctx, boxKey, clientegg)

}

func (c *Controller) deleteEgg(ctx context.Context, name string) {
	fmt.Println("$$$>>>deleteEgg")

	manager := user.BpfManagerInstance()
	manager.Stop(name)

	fmt.Println("$$$>>>deleteEgg: map entry deleted")
}

func (c *Controller) handleAdd(obj interface{}) {
	log.Println("handleAdd was called.")

	c.workqueue.Add(obj)
}

func (c *Controller) handleDelete(obj interface{}) {
	log.Println("handleDelete was called.")
	c.workqueue.Add(obj)
}

func (c *Controller) handleUpdate(prev interface{}, obj interface{}) {
	log.Println("handleUpdate was called.")
	ceggPrev := prev.(*v1alpha1.ClusterEgg)
	cegg := obj.(*v1alpha1.ClusterEgg)
	if ceggPrev.GetResourceVersion() != cegg.GetResourceVersion() {
		//handle only update not sync event
		c.workqueue.Add(obj)
	}
}
