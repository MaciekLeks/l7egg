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
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"log"
	"sync"
	"time"
)

type Controller struct {
	ceggClientset   ceggclientset.Interface
	ceggCacheSynced cache.InformerSynced
	ceggLister      cegglister.ClusterEggLister
	queue           workqueue.RateLimitingInterface
	//wg              sync.WaitGroup
	clienteggs map[string]user.ClientEgg
}

const (
	queueName string = "clusterEgg"
)

func NewController(ceggClientset ceggclientset.Interface, ceggInformer cegginformer.ClusterEggInformer) *Controller {
	c := &Controller{
		ceggClientset:   ceggClientset,
		ceggLister:      ceggInformer.Lister(),
		ceggCacheSynced: ceggInformer.Informer().HasSynced,
		queue:           workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), queueName),
		clienteggs:      map[string]user.ClientEgg{},
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

func (c *Controller) Run(ctx context.Context) {
	fmt.Println("Starting controller.")
	defer c.queue.ShutDown()
	defer fmt.Println("###>>>Run ending...")

	if !cache.WaitForCacheSync(ctx.Done(), c.ceggCacheSynced) {
		log.Println("Cache not synced.")
	}

	fmt.Println("---1")
	// spin up only one gorouitne for now
	go wait.UntilWithContext(ctx, c.worker, 1*time.Second) //runs again after 1 sec only if c.worker ends
	fmt.Println("---2")

	<-ctx.Done()
	fmt.Println("---3")
	//TOOD wait for user space bpf to terminate
	fmt.Println("---4")
}

func (c *Controller) worker(ctx context.Context) {
	workFunc := func() bool {

		fmt.Println("--->>>before Get")
		keyObj, quit := c.queue.Get() //blocking op
		defer fmt.Println("--->>>processNextItem ended.")
		if quit {
			log.Println("--->>> Cache shut down.")
			return true
		}
		defer c.queue.Done(keyObj)

		fmt.Println("--->>>after Get")

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
			// been add/update/sync
			fmt.Printf("--->>>clusteregg object: %+v\n", cegg)
			c.updateEgg(ctx, *cegg)
			return false
		}
		//check directly on the server (not lister) if the object has been deleted form the k8s cluster
		//cegg, err := c.ceggClientset.MaciekleksV1alpha1().ClusterEggs().Get(ctx, name, metav1.GetOptions{})
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
			fmt.Println("--->>>Worker queue shutting down")
			return
		}
	}
}

func (c *Controller) Wait() {

	var stopWaitGroup sync.WaitGroup
	for k, v := range c.clienteggs {
		stopWaitGroup.Add(1)
		go func() {
			defer stopWaitGroup.Done()
			fmt.Println("Stopping %s", k)
			v.WaitGroup.Wait()
		}()
	}
	stopWaitGroup.Wait()

}

func (c *Controller) updateEgg(ctx context.Context, cegg v1alpha1.ClusterEgg) {

	subCtx, stopFunc := context.WithCancel(ctx)
	var subWaitGroup sync.WaitGroup
	clientegg := user.ClientEgg{
		IngressInterface: cegg.Spec.IngressInterface,
		EgressInterface:  cegg.Spec.EgressInterface,
		CNs:              cegg.Spec.CommonNames,
		CIDRs:            cegg.Spec.CIDRs,
		BPFObjectPath:    "./l7egg.bpf.o",

		StopFunc:  stopFunc,
		WaitGroup: &subWaitGroup,
	}

	clientegg.Run(subCtx)

	c.clienteggs[cegg.Name] = clientegg
}

func (c *Controller) deleteEgg(ctx context.Context, name string) {
	fmt.Println("$$$>>>deleteEgg")
	for k := range c.clienteggs {
		fmt.Println("$$$>>>%s", k)
	}
	clientegg, found := c.clienteggs[name]
	if !found {
		fmt.Printf("Checking key map exists %s\n", name)
		return
	}

	fmt.Println("$$$>>>deleteEgg: stopping")
	clientegg.StopFunc()
	fmt.Println("$$$>>>deleteEgg: waiting")
	clientegg.WaitGroup.Wait()
	fmt.Println("$$$>>>deleteEgg: done")
	delete(c.clienteggs, name)

	fmt.Println("$$$>>>deleteEgg: map entry deleted")
}

func (c *Controller) handleAdd(obj interface{}) {
	log.Println("handleAdd was called.")

	c.queue.Add(obj)
}

func (c *Controller) handleDelete(obj interface{}) {
	log.Println("handleDelete was called.")
	c.queue.Add(obj)
}

func (c *Controller) handleUpdate(prev interface{}, obj interface{}) {
	log.Println("handleUpdate was called.")
	//ceggPrev := prev.(*v1alpha1.ClusterEgg)
	//cegg := obj.(*v1alpha1.ClusterEgg)
	//if ceggPrev.GetResourceVersion() != cegg.GetResourceVersion() {
	//	//handle only update not sync event
	//	c.queue.Add(obj)
	//}
}
