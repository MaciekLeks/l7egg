package controller

import (
	eggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	egglister "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller struct {
	eggclientset          eggclientset.Interface
	clusterEggCacheSynced cache.InformerSynced
	clusterEggLister      egglister.ClusterEggLister
	queue                 workqueue.RateLimitingInterface
}
