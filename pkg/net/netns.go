package net

import (
	"fmt"
	cnins "github.com/containernetworking/plugins/pkg/ns"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

// NetNamespaceFileDescriptor returns the file descriptor of the network namespace
func NetNamespace(netNsPath string) (cnins.NetNS, error) {
	var netNs cnins.NetNS
	var err error
	if netNsPath != "" {
		netNs, err = cnins.GetNS(netNsPath)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("can't open network namespace: %v", err))
			return netNs, err
		}
	}
	return netNs, nil
}
