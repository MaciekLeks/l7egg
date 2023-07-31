package controller

import "k8s.io/apimachinery/pkg/types"

type ctxAssetType string
type ctxAssetValue int8

const (
	ctxCeggValue ctxAssetValue = iota + 1
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
