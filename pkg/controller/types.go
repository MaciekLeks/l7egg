package controller

import (
	"github.com/MaciekLeks/l7egg/pkg/common"
	"k8s.io/apimachinery/pkg/types"
)

const (
	ctxCeggValue common.CtxAssetValue = iota + 1
	ctxPodValue
)

type ContainerName struct {
	types.NamespacedName
	Name string
	Id   string
}

const (
	Separator = '/'
)

// String returns the general purpose string representation
func (pcn ContainerName) String() string {
	return pcn.NamespacedName.String() + string(Separator) + pcn.Name + string(Separator) + pcn.Id
}
