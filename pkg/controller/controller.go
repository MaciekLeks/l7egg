package controller

import (
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	cegginformer "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions/maciekleks.dev/v1alpha1"
	cegglister "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/user"
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
	done            chan struct{}
	//wg              sync.WaitGroup
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

func (c *Controller) Run(done <-chan struct{}) {
	fmt.Println("Starting controller.")
	c.done = make(chan struct{})
	if !cache.WaitForCacheSync(done, c.ceggCacheSynced) {
		log.Println("Cache not synced.")
	}

	fmt.Println("---1")
	// spin up only one gorouitne for now
	go wait.Until(c.worker, 1*time.Second, done) //runs again after 1 sec only if c.worker ends
	fmt.Println("---2")

	<-done
	fmt.Println("---3")
	close(c.done)

	fmt.Println("---4")
}

func (c *Controller) worker() {
	fmt.Printf("worker started\n")
	//fmt.Println("worker")
	for c.processNextItem() {
		//fmt.Printf("-")
	}
	fmt.Printf("/")
}

func (c *Controller) processNextItem() bool {
	fmt.Printf("processNextItem[0]\n")
	item, shutdown := c.queue.Get() //blocking op
	//fmt.Printf("|")
	if shutdown {
		log.Println("Cache shut down.")
		return false
	}
	defer c.queue.Forget(item)
	//
	key, err := cache.MetaNamespaceKeyFunc(item)
	if err != nil {
		log.Printf("Getting key(<ns>/<name>) from cache %s\n", err)
		return false
	}
	_, name, err := cache.SplitMetaNamespaceKey(key) //namespace not xpected here
	if err != nil {
		log.Printf("Splitting key (<ns>/<name>) into name %s\n", err)
		return false
	}

	fmt.Printf("cluster object name: %s\n", name)

	cegg, err := c.ceggLister.Get(name)
	if err != nil {
		log.Printf("Error %v, gettting the clusteregg resource from lister.", err)
		return false
	}

	fmt.Printf("clusteregg object: %+v\n", cegg)

	runEgg(c.done, cegg.Spec)
	//
	//err = c.reconcile(ns, name)
	//if err != nil {
	//	//re-try
	//	fmt.Printf("Reconciling %s\n", err)
	//	return false
	//}
	return true
}

func runEgg(done <-chan struct{}, spec v1alpha1.ClusterEggSpec) {
	clientegg := user.ClientEgg{
		IngressInterface: spec.IngressInterface,
		EgressInterface:  spec.EgressInterface,
		CNs:              spec.CommonNames,
		CIDRs:            spec.CIDRs,
		BPFObjectPath:    "./l7egg.bpf.o",
	}

	go clientegg.Run(done)
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
