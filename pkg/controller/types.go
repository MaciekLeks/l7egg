package controller

type ctxAssetValue int8
type ctxAssetType string

const (
	ctxCeggValue ctxAssetValue = iota + 1
	ctxPodValue
)
