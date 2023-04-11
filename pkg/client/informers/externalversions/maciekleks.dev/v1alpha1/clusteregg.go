/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	time "time"

	maciekleksdevv1alpha1 "github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	versioned "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	internalinterfaces "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/MaciekLeks/l7egg/pkg/client/listers/maciekleks.dev/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// ClusterEggInformer provides access to a shared informer and lister for
// ClusterEggs.
type ClusterEggInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.ClusterEggLister
}

type clusterEggInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewClusterEggInformer constructs a new informer for ClusterEgg type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewClusterEggInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredClusterEggInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredClusterEggInformer constructs a new informer for ClusterEgg type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredClusterEggInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.MaciekleksV1alpha1().ClusterEggs(namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.MaciekleksV1alpha1().ClusterEggs(namespace).Watch(context.TODO(), options)
			},
		},
		&maciekleksdevv1alpha1.ClusterEgg{},
		resyncPeriod,
		indexers,
	)
}

func (f *clusterEggInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredClusterEggInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *clusterEggInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&maciekleksdevv1alpha1.ClusterEgg{}, f.defaultInformer)
}

func (f *clusterEggInformer) Lister() v1alpha1.ClusterEggLister {
	return v1alpha1.NewClusterEggLister(f.Informer().GetIndexer())
}
