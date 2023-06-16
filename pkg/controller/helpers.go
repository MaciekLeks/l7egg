package controller

import (
	"context"
	"fmt"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
)

//--- non-receiver helpers

func splitNamespaceNameFormKey(key string) (string, string, error) {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return "", "", err
	}
	return namespace, name, nil
}

func getCtxAssetValue(ctx context.Context) (ctxAssetValue, error) {
	ctxVal := ctx.Value(ctxAssetKey)
	v, ok := ctxVal.(ctxAssetValue)
	if !ok {
		err := fmt.Errorf("expected string in context %s value but got %#v", ctxAssetKey, ctxVal)
		return v, err
	}
	return v, nil
}

//--- controller helpers

// Get from either ceggs or pods queue
func (c *Controller) queueGet(ctx context.Context) (string, bool, error) {
	cav, err := getCtxAssetValue(ctx)
	var key string
	var obj any
	var quit, ok bool

	if err != nil {
		return key, quit, err
	}
	switch cav {
	case ctxCeggValue:
		obj, quit = c.ceggQueue.Get()
	case ctxPodValue:
		obj, quit = c.podQueue.Get()
	default:
		return key, quit, fmt.Errorf("expected context value but got %#v", cav)
	}

	if quit {
		return key, quit, nil
	}

	if key, ok = obj.(string); !ok {
		// As the item in the ceggQueue is actually invalid, we call
		// Forget here else we'd go into a loop of attempting to
		// process a work item that is invalid.
		if err = c.queueForget(ctx, obj); err != nil {
			return key, quit, err
		}
		return key, quit, fmt.Errorf("expected string in queue but got %#v", obj)
	}

	return key, quit, nil
}

// Get from either ceggs or pods queue
func (c *Controller) queueForget(ctx context.Context, obj any) error {
	cav, err := getCtxAssetValue(ctx)

	if err != nil {
		return err
	}
	switch cav {
	case ctxCeggValue:
		c.ceggQueue.Forget(obj)
	case ctxPodValue:
		c.podQueue.Forget(obj)
	}

	return nil
}

// Get from either ceggs or pods queue
func (c *Controller) queueDone(ctx context.Context, key string) error {
	cav, err := getCtxAssetValue(ctx)

	if err != nil {
		return err
	}
	switch cav {
	case ctxCeggValue:
		c.ceggQueue.Done(key)
	case ctxPodValue:
		c.podQueue.Done(key)
	}

	return nil
}

func (c *Controller) queueAddRateLimited(ctx context.Context, key string) error {
	cav, err := getCtxAssetValue(ctx)

	if err != nil {
		return err
	}
	switch cav {
	case ctxCeggValue:
		c.ceggQueue.AddRateLimited(key)
	case ctxPodValue:
		c.podQueue.AddRateLimited(key)
	}

	return nil
}

// Get from either ceggs or pods queue
func (c *Controller) syncHandler(ctx context.Context, key string) error {
	cav, err := getCtxAssetValue(ctx)

	if err != nil {
		return err
	}
	switch cav {
	case ctxCeggValue:
		return c.syncEggHandler(ctx, key)
	case ctxPodValue:
		return c.syncPodHandler(ctx, key)
	}

	return nil
}
