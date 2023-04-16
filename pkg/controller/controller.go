package controller

import (
	"fmt"
	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	cegginformer "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions/maciekleks.dev/v1alpha1"
	cegglister "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"log"
	"time"
)

type Controller struct {
	ceggClientset   ceggclientset.Interface
	ceggCacheSynced cache.InformerSynced
	ceggLister      cegglister.ClusterEggLister
	queue           workqueue.RateLimitingInterface
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

func (c *Controller) Run(ch <-chan struct{}) {
	fmt.Println("Starting controller")
	if !cache.WaitForCacheSync(ch, c.ceggCacheSynced) {
		log.Println("Cache not synced.")
	}

	fmt.Println("---1")
	// spin up only one gorouitne for now
	go wait.Until(c.worker, 1*time.Second, ch) //runs again after 1 sec only if c.worker ends
	fmt.Println("---2")

	<-ch
}

func (c *Controller) worker() {
	fmt.Printf("worker started\n")
	//fmt.Println("worker")
	for c.processNextItem() {
		fmt.Printf("-")
	}
	fmt.Printf("/")
}

func (c *Controller) processNextItem() bool {
	//fmt.Printf("\\")
	//item, shutdown := c.queue.Get() //blocking op
	//fmt.Printf("|")
	//if shutdown {
	//	fmt.Println("shutdown")
	//	return false
	//}
	//defer c.queue.Forget(item)
	//
	//key, err := cache.MetaNamespaceKeyFunc(item)
	//if err != nil {
	//	fmt.Printf("Getting key(<namespace>/<name>) from cache %s\n", err)
	//}
	//ns, name, err := cache.SplitMetaNamespaceKey(key)
	//if err != nil {
	//	fmt.Printf("Splitting key(<namespace>/<name>) into namespace and name %s\n", err)
	//}
	//
	//fmt.Printf("%s/%s\n", ns, name)
	//
	//err = c.reconcile(ns, name)
	//if err != nil {
	//	//re-try
	//	fmt.Printf("Reconciling %s\n", err)
	//	return false
	//}
	return true
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
	c.queue.Add(obj)
}
