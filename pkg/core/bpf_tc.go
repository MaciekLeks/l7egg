package core

import (
	"github.com/MaciekLeks/l7egg/pkg/net"
	bpf "github.com/aquasecurity/libbpfgo"
)

func attachTcBpfEgressStack(bpfModule *bpf.Module, iface, netNsPath string, shaping *ShapingInfo) error {
	tcProg, err := bpfModule.GetProgram(BpfEgressProgram)
	if err != nil {
		return err
	}

	if err := net.AttachEgressTcBpfNetStack(netNsPath, iface, tcProg.FileDescriptor(), "./"+BpfObjectFileName, BpfEgressSection, net.TcShaping(*shaping)); err != nil {

		return err
	}

	return nil
}

func attachTcBpfIngressStack(bpfModule *bpf.Module, iface, netNsPath string) error {
	tcProg, err := bpfModule.GetProgram(BpfIngressProgram)
	if err != nil {
		return err
	}

	if err := net.AttachIngressTcBpfNetStack(netNsPath, iface, tcProg.FileDescriptor(), BpfObjectFileName, BpfIngressSection); err != nil {
		return err
	}

	return nil
}
