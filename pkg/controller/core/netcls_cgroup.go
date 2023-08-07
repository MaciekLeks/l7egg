package core

import (
	"github.com/MaciekLeks/l7egg/pkg/net"
	"github.com/containerd/cgroups/v3/cgroup1"
)

func (ey *ebpfy) runNetClsCgroupStack(netNsPath string, cgroupNetCls cgroup1.Cgroup, pid uint32) error {
	return attachTcCgroupEgressStack(ey.EggInfo.EgressInterface, cgroupNetCls, ey.EggInfo.Shaping, netNsPath, pid)
}

func (ey *ebpfy) stopNetClsCgroupStack(netNsPath string) error {
	return net.CleanEgressTcNetStack(netNsPath, ey.EggInfo.EgressInterface)
}

func attachTcCgroupEgressStack(iface string, cgroupNetCls cgroup1.Cgroup, shaping *ShapingInfo, netNsPath string, pid uint32) error {
	if err := net.AttachEgressTcCgroupNetStack(netNsPath, cgroupNetCls, iface, net.TcShaping(*shaping), pid); err != nil {
		return err
	}
	return nil
}