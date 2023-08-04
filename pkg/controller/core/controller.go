package core

import (
	"github.com/MaciekLeks/l7egg/pkg/controller"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"time"
)

type CoreController struct {
	eggInfoQueue workqueue.RateLimitingInterface
	podInfoQueue workqueue.RateLimitingInterface
}

type CoreMsg struct {
	PodInfo *controller.PodBox
	EggInfo *EggInfo
}

type CoreEvent struct {
	MsgType string //TODO enum
	Data    CoreMsg
}

////////////

func NewCoreController() *CoreController {
	return &CoreController{
		eggInfoQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "eggInfoQueue"),
		podInfoQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "podInfoQueue"),
	}
}

func (cc *CoreController) RegisterNewPodInfoEvent(podInfo *controller.PodBox) {
	cc.podInfoQueue.Add(CoreEvent{
		MsgType: "newPodInfo",
		Data: CoreMsg{
			PodInfo: podInfo,
		},
	})
}

func (cc *CoreController) Run(stopCh <-chan struct{}) {
	go wait.Until(cc.runEggInfoWorker, time.Second, stopCh)
	go wait.Until(cc.runPodInfoWorker, time.Second, stopCh)
	<-stopCh
}

func (cc *CoreController) runEggInfoWorker() {
	for cc.processNextEggInfo() {
	}
}

func (cc *CoreController) runPodInfoWorker() {
	for cc.processNextPodInfo() {
	}
}

func (cc *CoreController) processNextEggInfo() bool {
	obj, shutdown := cc.eggInfoQueue.Get()
	if shutdown {
		return false
	}
	defer cc.eggInfoQueue.Done(obj)
	return true
}

func (cc *CoreController) processNextPodInfo() bool {
	obj, shutdown := cc.podInfoQueue.Get()
	if shutdown {
		return false
	}
	defer cc.podInfoQueue.Done(obj)
	return true
}
