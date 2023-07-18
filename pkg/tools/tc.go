package tools

import (
	"fmt"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

type TcFacade struct {
	netNs   int
	ifaceID int
	tcm     *tc.Tc
}

func NewTcClient(netNsFd int, iface string) (*TcFacade, error) {

	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("Could not get interface %s: %v\n", iface, err)
	}

	tcm, err := tc.Open(&tc.Config{
		NetNS: netNsFd,
	})
	if err != nil {
		return nil, fmt.Errorf("Opening rtnetlink socket: %v\n", err)
	}

	tcf := &TcFacade{
		netNs:   netNsFd,
		ifaceID: devID.Index,
		tcm:     tcm,
	}

	return tcf, nil
}

func (tcf *TcFacade) Close() {
	if err := tcf.tcm.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Closing rtnetlink socket: %v\n", err)
	}
}

func (tcf *TcFacade) addHtbQdisc(parent, handle uint32) error {
	var qdisc = tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(tcf.ifaceID),
			//Handle:  core.BuildHandle(0x1, 0x0),
			Handle: handle,
			//Parent:  tc.HandleRoot,
			Parent: parent,
			Info:   0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Init: &tc.HtbGlob{
					Version:      0x3,
					Rate2Quantum: 0xa,
				},
			},
		},
	}
	//TODO: Add od replace?
	if err := tcf.tcm.Qdisc().Add(&qdisc); err != nil {
		return fmt.Errorf("could not assign htb to iface: %v\n", err)
	}

	return nil
}

func (tcf *TcFacade) addIngressQdisc(parent, handle uint32) error {
	var qdisc = tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(tcf.ifaceID),
			Parent:  parent,
			Handle:  handle,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "ingress",
		},
	}

	if err := tcf.tcm.Qdisc().Add(&qdisc); err != nil {
		return fmt.Errorf("could not assign ingress to iface: %v\n", err)
	}

	return nil
}

func (tcf *TcFacade) addHtbClass(parent, handle uint32) error {
	var class = tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(tcf.ifaceID),
			Parent:  parent,
			Handle:  handle,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "htb",
			Htb: &tc.Htb{
				Parms: &tc.HtbOpt{
					Rate: tc.RateSpec{
						Rate:      128000,
						Linklayer: 1,
					},
					Ceil: tc.RateSpec{
						Rate:      128000,
						Linklayer: 1,
					},
					Buffer:  125000,
					Cbuffer: 195312,
					Quantum: 12800,
				},
			},
		},
	}
	if err := tcf.tcm.Class().Add(&class); err != nil {
		return fmt.Errorf("could not assign class to iface qdisc: %v\n", err)
	}

	return nil
}

func (tcf *TcFacade) addBpfFilter(parent, handle uint32, flowId *uint32, bpfFd int, bpfFilePath, bpfSec string) error {
	var info uint32
	var pref uint32 = 0
	var protocol uint32 = unix.ETH_P_ALL
	info |= pref << 16
	info |= protocol

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(tcf.ifaceID),
			Parent:  parent,
			Handle:  handle,
			Info:    info,
		},
		tc.Attribute{
			Kind: "bpf",
			//"da obj /tmp/bpf.o sec foo"
			BPF: &tc.Bpf{
				//FD: uint32Ptr(uint32(bpfFD)), Name: stringPtr(fmt.Sprintf("%s:[%s]", bpfFilePath, bpfSec)),
				FD: uint32Ptr(uint32(bpfFd)),
				//Name:  stringPtr("l7egg.bpf.o:[tc]"),
				Name:  stringPtr(fmt.Sprintf("%s:[%s]", bpfFilePath, bpfSec)), //e.g. l7egg.bpf.o:[tc]
				Flags: uint32Ptr(0x1),
				//FlagsGen: uint32Ptr(0x8),
				ClassID: flowId,
				//Tag:      bytesPtr([]byte{228, 2, 93, 253, 249, 172, 145, 52}),
				//	ID:       uint32Ptr(75),
			},
			//BPF: &tc.Bpf{
			//	Ops:     bytesPtr([]byte{0x6, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff}),
			//	OpsLen:  uint16Ptr(0x1),
			//	ClassID: uint32Ptr(0x1000001),
			//	Flags:   uint32Ptr(0x1),
			//},
		},
	}

	//fmt.Printf("filters.BPF: %+v\n", filter.BPF)
	//fmt.Printf("filters.BPF.Name: %s\n", *filter.BPF.Name)
	//fmt.Printf("filters.BPF.FD: %+v\n", *filter.BPF.FD)
	//fmt.Printf("filters.BPF.Flags: %+v\n", *filter.BPF.Flags)
	//fmt.Printf("filters.BPF.FlagsGen: %+v\n", *filter.BPF.FlagsGen)
	//fmt.Printf("filters.BPF.Tag: %+v\n", *filter.BPF.Tag)
	//fmt.Printf("filters.BPF.ID: %+v\n", *filter.BPF.ID)

	if err := tcf.tcm.Filter().Add(&filter); err != nil {
		return fmt.Errorf("could not assign filter to iface qdisc: %v\n", err)
	}

	return nil
}

// uint32Ptr is a helper function that returns a pointer to the uint32 input value.
func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

// stringPtr is a helper function that returns a pointer to the string input value.
func stringPtr(v string) *string {
	return &v
}

func bytesPtr(v []byte) *[]byte {
	return &v
}

func AttachEgressBpfFilter(netNs int, iface string, bpfFd int, bpfFileName, bpfSec string) error {
	tcf, err := NewTcClient(netNs, iface)
	if err != nil {
		return err
	}
	defer tcf.Close()

	qdiscHandle := core.BuildHandle(0x100, 0)
	if err := tcf.addHtbQdisc(tc.HandleRoot, qdiscHandle); err != nil {
		return err
	}

	classHandle := core.BuildHandle(0x100, 0x1)
	if err := tcf.addHtbClass(qdiscHandle, classHandle); err != nil {
		return err
	}

	filterHandle := core.BuildHandle(0x100, 0x11)
	if err := tcf.addBpfFilter(qdiscHandle, filterHandle, &classHandle, bpfFd, bpfFileName, bpfSec); err != nil {
		return err
	}

	return nil
}

func AttachIngressBpfFilter(netNs int, iface string, bpfFd int, bpfFileName, bpfSec string) error {
	fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%% ##0")
	tcf, err := NewTcClient(netNs, iface)
	if err != nil {
		return err
	}
	defer tcf.Close()

	/*
		sudo strace -e trace=sendmsg -v -s 1000 -x tc qdisc add dev enp0s9 ingress
		sendmsg(3, {msg_name={sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, msg_namelen=12,
		msg_iov=[{iov_base=[{nlmsg_len=48, nlmsg_type=RTM_NEWQDISC, nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE,
		nlmsg_seq=1689673373, nlmsg_pid=0}, {tcm_family=AF_UNSPEC, tcm_ifindex=if_nametoindex("enp0s9"),
		tcm_handle=4294901760, tcm_parent=4294967281, tcm_info=0}, [{nla_len=12, nla_type=TCA_KIND}, "\x69\x6e\x67\x72\x65\x73\x73\x00"...]],
		iov_len=48}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, 0) = 48

		where:
		tcm_parent = FFFF:FFF1 = 4294967281
		tcm_handle = FFFF:FFF0 = 4294901760
	*/
	qdiscHandle := core.BuildHandle(0xffff, 0x0000)
	if err := tcf.addIngressQdisc(tc.HandleIngress, qdiscHandle); err != nil {
		return err
	}

	fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%% ##1")
	filterHandle := core.BuildHandle(0x100, 0x12)
	if err := tcf.addBpfFilter(qdiscHandle, filterHandle, nil, bpfFd, bpfFileName, bpfSec); err != nil {
		return err
	}

	fmt.Println("%%%%%%%%%%%%%%%%%%%%%%%% ##2")
	return nil
}
