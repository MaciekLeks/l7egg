package controller

type ctxAssetType string
type ctxAssetValue int8

const (
	ctxCeggValue ctxAssetValue = iota + 1
	ctxPodValue
)
