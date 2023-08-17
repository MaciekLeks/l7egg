package core

import (
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/net"
	"github.com/containerd/cgroups/v3/cgroup1"
)

func (eby *ebpfy) runNetClsCgroupStack(netNsPath string, cgroupNetCls cgroup1.Cgroup, pid uint32) error {
	return attachTcCgroupEgressStack(eby.eggy.EgressInterface, cgroupNetCls, eby.eggy.Shaping, netNsPath, pid)
}

func (eby *ebpfy) stopNetClsCgroupStack(netNsPath string) error {
	return net.CleanEgressTcNetStack(netNsPath, eby.eggy.EgressInterface)
}

func (eby *ebpfy) stopTcNetStack(netNsPath string) error {
	if err := net.CleanIngressTcNetStack(netNsPath, eby.eggy.IngressInterface); err != nil {
		return fmt.Errorf("failed to clean ingress tc net stack: %v", err)
	}
	if err := net.CleanEgressTcNetStack(netNsPath, eby.eggy.EgressInterface); err != nil {
		return fmt.Errorf("failed to clean egress tc net stack: %v", err)
	}
	return nil
}

func (eby *ebpfy) addPidToNetClsCgroup(cgroupNetCls cgroup1.Cgroup, pid uint32) error {
	return net.AddPidToNetClsCgroup(cgroupNetCls, pid)
}

// attachTcCgroupEgressStack attaches tc egress stack to the interface in the network namespace and adds pid to the cgroup
func attachTcCgroupEgressStack(iface string, cgroupNetCls cgroup1.Cgroup, shaping *ShapingInfo, netNsPath string, pid uint32) error {
	if err := net.AttachEgressTcCgroupNetStack(netNsPath, cgroupNetCls, iface, net.TcShaping(*shaping), pid); err != nil {
		return err
	}
	return net.AddPidToNetClsCgroup(cgroupNetCls, pid)
}
