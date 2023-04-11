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

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	scheme "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// ClusterEggsGetter has a method to return a ClusterEggInterface.
// A group's client should implement this interface.
type ClusterEggsGetter interface {
	ClusterEggs() ClusterEggInterface
}

// ClusterEggInterface has methods to work with ClusterEgg resources.
type ClusterEggInterface interface {
	Create(ctx context.Context, clusterEgg *v1alpha1.ClusterEgg, opts v1.CreateOptions) (*v1alpha1.ClusterEgg, error)
	Update(ctx context.Context, clusterEgg *v1alpha1.ClusterEgg, opts v1.UpdateOptions) (*v1alpha1.ClusterEgg, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.ClusterEgg, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.ClusterEggList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterEgg, err error)
	ClusterEggExpansion
}

// clusterEggs implements ClusterEggInterface
type clusterEggs struct {
	client rest.Interface
}

// newClusterEggs returns a ClusterEggs
func newClusterEggs(c *MaciekleksV1alpha1Client) *clusterEggs {
	return &clusterEggs{
		client: c.RESTClient(),
	}
}

// Get takes name of the clusterEgg, and returns the corresponding clusterEgg object, and an error if there is any.
func (c *clusterEggs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.ClusterEgg, err error) {
	result = &v1alpha1.ClusterEgg{}
	err = c.client.Get().
		Resource("clustereggs").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of ClusterEggs that match those selectors.
func (c *clusterEggs) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.ClusterEggList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.ClusterEggList{}
	err = c.client.Get().
		Resource("clustereggs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested clusterEggs.
func (c *clusterEggs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("clustereggs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a clusterEgg and creates it.  Returns the server's representation of the clusterEgg, and an error, if there is any.
func (c *clusterEggs) Create(ctx context.Context, clusterEgg *v1alpha1.ClusterEgg, opts v1.CreateOptions) (result *v1alpha1.ClusterEgg, err error) {
	result = &v1alpha1.ClusterEgg{}
	err = c.client.Post().
		Resource("clustereggs").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterEgg).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a clusterEgg and updates it. Returns the server's representation of the clusterEgg, and an error, if there is any.
func (c *clusterEggs) Update(ctx context.Context, clusterEgg *v1alpha1.ClusterEgg, opts v1.UpdateOptions) (result *v1alpha1.ClusterEgg, err error) {
	result = &v1alpha1.ClusterEgg{}
	err = c.client.Put().
		Resource("clustereggs").
		Name(clusterEgg.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(clusterEgg).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the clusterEgg and deletes it. Returns an error if one occurs.
func (c *clusterEggs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("clustereggs").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *clusterEggs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("clustereggs").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched clusterEgg.
func (c *clusterEggs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.ClusterEgg, err error) {
	result = &v1alpha1.ClusterEgg{}
	err = c.client.Patch(pt).
		Resource("clustereggs").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
