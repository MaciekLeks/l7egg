package tools

import (
	"fmt"
	cnins "github.com/containernetworking/plugins/pkg/ns"
	"github.com/florianl/go-tc"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

const (
	handleMajMask         uint32 = 0xFFFF0000
	handleMinMask         uint32 = 0x0000FFFF
	TcHandleHtbQdisc      uint32 = 0x1 << 16      //hex:1:0
	TcHandleHtbClass      uint32 = 0x1<<16 | 0x10 //hex:1:10
	TcHandleHtbFilter     uint32 = 0x10<<16 | 0x1 //hex:10:1
	TcHandleIngressQdisc  uint32 = 0xffff << 16   //hex:ffff:0
	TcHandleIngressFilter uint32 = 0x10<<16 | 0x2 //hex:10:2
)

//type tcObjectType uint8
//type tcDirection uint8

//const (
//	tcObjectTypeQdisc  tcObjectType = 1
//	tcObjectTypeClass  tcObjectType = 2
//	tcObjectTypeFilter tcObjectType = 3
//
//	tcDirectionIngress tcDirection = 1
//	tcDirectionEgress  tcDirection = 2
//)
////
//type tcObject struct {
//	tc.Object
//	tcObjectType tcObjectType
//}
//
//type tcObjectKey struct {
//	devId       int
//	tcDirection tcDirection
//}

type TcFacade struct {
	//netNs   cnins.NetNS
	ifaceID int
	tcm     *tc.Tc
	//objects syncx.SafeMap[tcObjectKey, []tcObject] //to easily erase them - no refs needed
}

func NewTcFacade(iface string) (*TcFacade, error) {
	//netNs, err := NetNamespace(netNsPath)
	//if err != nil {
	//	return nil, err
	//}
	//defer netNs.Close()

	//fmt.Printf("[attachTcEgressStack] netnsfd:%+v\n", netNs)
	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("Could not get interface %s: %v\n", iface, err)
	}

	tcm, err := tc.Open(&tc.Config{
		//NetNS: int(netNs.Fd()), //not working in go-tc - error?
	})
	if err != nil {
		return nil, fmt.Errorf("Opening rtnetlink socket: %v\n", err)
	}

	tcf := &TcFacade{
		//netNs:   netNs,
		ifaceID: devID.Index,
		tcm:     tcm,
	}

	return tcf, nil
}

func (tcf *TcFacade) Close() {
	//if err := tcf.netNs.Close(); err != nil {
	//	fmt.Fprintf(os.Stderr, "Closing netns: %v\n", err)
	//}
	if err := tcf.tcm.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Closing rtnetlink socket: %v\n", err)
	}
}

//func (tcf *TcFacade) storeObject(ifaceId int, tcDirection tcDirection, tcObject tcObject) {
//	key := tcObjectKey{ifaceId, tcDirection}
//	if m, ok := tcf.objects.Load(key); ok {
//		m = append(m, tcObject)
//		tcf.objects.Store(key, m)
//	}
//}

func (tcf *TcFacade) buildHtbQdiscSpec(parent, handle uint32) *tc.Object {
	return &tc.Object{
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
}

func (tcf *TcFacade) addHtbQdisc(parent, handle uint32) error {
	var qdisc = tcf.buildHtbQdiscSpec(parent, handle)

	//tcf.storeObject(tcf.ifaceID, tcDirectionEgress, tcObject{
	//	Object:       qdisc,
	//	tcObjectType: tcObjectTypeQdisc,
	//})
	//
	if err := tcf.tcm.Qdisc().Replace(qdisc); err != nil {
		return fmt.Errorf("could not assign htb to iface: %v\n", err)
	}

	return nil
}

// deleteHtbQdisc deletes the htb qdisc from the given interface to clear all child objects, e.g. classes, filters,...
func (tcf *TcFacade) deleteHtbQdisc(parent, handle uint32) error {
	var qdisc = tcf.buildHtbQdiscSpec(parent, handle)

	if err := tcf.tcm.Qdisc().Delete(qdisc); err != nil {
		return fmt.Errorf("could not delete iface qdisc: %v\n", err)
	}

	return nil
}

func (tcf *TcFacade) buildIngressQdiscSpec(parent, handle uint32) *tc.Object {
	return &tc.Object{
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
}

func (tcf *TcFacade) addIngressQdisc(parent, handle uint32) error {
	var qdisc = tcf.buildIngressQdiscSpec(parent, handle)

	if err := tcf.tcm.Qdisc().Replace(qdisc); err != nil {
		return fmt.Errorf("could not assign ingress to iface: %v\n", err)
	}

	//tcf.storeObject(tcf.ifaceID, tcDirectionIngress, tcObject{
	//	Object:       qdisc,
	//	tcObjectType: tcObjectTypeQdisc,
	//})

	return nil
}

// deleteIngressQdisc deletes the ingress qdisc from the given interface to clear its object - filter
func (tcf *TcFacade) deleteIngressQdisc(parent, handle uint32) error {
	var qdisc = tcf.buildIngressQdiscSpec(parent, handle)

	if err := tcf.tcm.Qdisc().Delete(qdisc); err != nil {
		return fmt.Errorf("could not delete iface qdisc: %v\n", err)
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
	//var info uint32
	//var pref uint32 = 49152
	//var protocol uint32 = unix.ETH_P_ALL
	//info |= pref << 16
	//info |= protocol

	//print info with hex format
	//fmt.Printf("info: %x\n", info)

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(tcf.ifaceID),
			Parent:  parent,
			Handle:  handle,
			Info:    0x300, //little endian of unix.ETH_P_ALL
		},
		tc.Attribute{
			Kind: "bpf",
			//"da obj /tmp/bpf.o sec foo"
			BPF: &tc.Bpf{
				//FD: uint32Ptr(uint32(bpfFD)), Name: stringPtr(fmt.Sprintf("%s:[%s]", bpfFilePath, bpfSec)),
				FD: uint32Ptr(uint32(bpfFd)),
				//Name:  stringPtr("l7egg.bpf.o:[tc]"),
				Name: stringPtr(fmt.Sprintf("%s:[%s]", bpfFilePath, bpfSec)), //e.g. l7egg.bpf.o:[tc]
				//Name:  stringPtr(fmt.Sprintf("%s", bpfFilePath)), //e.g. l7egg.bpf.o
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

// CleanInterface cleans up the tc stack (ingress and egress) attached to the given interface; Stops on first error
//func cleanInterface(netNsPath string, iface string, tcDirection tcDirection) error {
//	tcf, err := NewTcFacade(netNsPath, iface)
//	if err != nil {
//		fmt.Printf("cleanInterface netTcFacade error: %+v", err)
//		return err
//	}
//	defer tcf.Close()
//
//	err = tcf.netNs.Do(func(_ns cnins.NetNS) error {
//		netNsFd := int(_ns.Fd())
//
//		fmt.Printf("cleanInterface netNsFd #2: %d\n", netNsFd)
//
//		devId, err := net.InterfaceByName(iface)
//		if err != nil {
//			fmt.Printf("cleanInterface dev error: %d\n", netNsFd)
//			return fmt.Errorf("Could not get interface %s: %v\n", iface, err)
//		}
//
//		fmt.Printf("cleanInterface devId.Index: %d\n", devId.Index)
//
//		// print everything in tcf.objects maps
//		tcf.objects.Range(func(k tcObjectKey, v []tcObject) bool {
//			fmt.Printf("cleanInterface tcf.objects: %+v: %+v\n", k, v)
//			return true
//		})
//
//		if objects, ok := tcf.objects.Load(tcObjectKey{devId.Index, tcDirection}); ok {
//
//			fmt.Printf("cleanInterface objects: %+v\n", objects)
//
//			for i := range objects {
//				switch objects[i].tcObjectType {
//				case tcObjectTypeQdisc:
//					fmt.Printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Deleting Qdisc %+v\n", objects[i])
//					if err := tcf.tcm.Qdisc().Delete(&objects[i].Object); err != nil {
//						return err
//					}
//					fmt.Printf("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Deleted %+v\n", objects[i])
//				case tcObjectTypeClass:
//					// not used - qdisc deletion is enough
//					if err := tcf.tcm.Class().Delete(&objects[i].Object); err != nil {
//						return err
//					}
//				case tcObjectTypeFilter:
//					// not used - qdisc deletion is enough
//					if err := tcf.tcm.Class().Delete(&objects[i].Object); err != nil {
//						return err
//					}
//				default:
//					return fmt.Errorf("unknown object type: %v", objects[i].tcObjectType)
//				}
//			}
//		} else {
//			return fmt.Errorf("could not find objects for interface %s", iface)
//		}
//
//		fmt.Printf("end")
//		return nil
//	})
//
//	fmt.Printf("end2")
//	return err
//}
//
//func CleanIngressStack(netNsPath string, iface string) error {
//	fmt.Printf("CleanIngressStack\n")
//	return cleanInterface(netNsPath, iface, tcDirectionIngress)
//}
//
//func CleanEgressStack(netNsPath string, iface string) error {
//	fmt.Printf("CleanEgressStack\n")
//	return cleanInterface(netNsPath, iface, tcDirectionEgress)
//}

func CleanIngressTcNetStack(netNsPath string, iface string) error {
	fmt.Printf("CleanIngressStack\n")

	netNs, err := NetNamespace(netNsPath)
	if err != nil {
		return err
	}
	defer netNs.Close()

	err = netNs.Do(func(_ns cnins.NetNS) error {
		tcf, err := NewTcFacade(iface)
		//tcf, err := NewTcFacade(netNsFd, iface)
		if err != nil {
			return err
		}
		defer tcf.Close()

		if err := tcf.deleteIngressQdisc(tc.HandleIngress, TcHandleIngressQdisc); err != nil {
			return err
		}
		return nil
	})

	return err
}

func CleanEgressTcNetStack(netNsPath string, iface string) error {
	fmt.Printf("CleanEgressTcNetStack\n")

	netNs, err := NetNamespace(netNsPath)
	if err != nil {
		return err
	}
	defer netNs.Close()

	err = netNs.Do(func(_ns cnins.NetNS) error {
		tcf, err := NewTcFacade(iface)
		//tcf, err := NewTcFacade(netNsFd, iface)
		if err != nil {
			return err
		}
		defer tcf.Close()

		if err := tcf.deleteHtbQdisc(tc.HandleRoot, TcHandleHtbQdisc); err != nil {
			return err
		}
		return nil
	})

	return err
}

// AttachEgressTcNetStack attaches a tc egress stack to the given interface, htb qdisc, htb class and bpf filter
func AttachEgressTcNetStack(netNsPath string, iface string, bpfFd int, bpfFileName, bpfSec string) error {
	netNs, err := NetNamespace(netNsPath)
	if err != nil {
		return err
	}
	defer netNs.Close()

	err = netNs.Do(func(_ns cnins.NetNS) error {
		tcf, err := NewTcFacade(iface)
		//tcf, err := NewTcFacade(netNsFd, iface)
		if err != nil {
			return err
		}
		defer tcf.Close()

		qdiscHandle := TcHandleHtbQdisc
		if err := tcf.addHtbQdisc(tc.HandleRoot, qdiscHandle); err != nil {
			return err
		}

		classHandle := TcHandleHtbClass
		if err := tcf.addHtbClass(qdiscHandle, classHandle); err != nil {
			return err
		}

		filterHandle := TcHandleHtbFilter
		if err := tcf.addBpfFilter(qdiscHandle, filterHandle, &classHandle, bpfFd, bpfFileName, bpfSec); err != nil {
			return err
		}
		return nil
	})

	return err
}

// AttachIngressTcNetStack attaches a tc ingress stack to the given interface, ingress qdisc and bpf filter
func AttachIngressTcNetStack(netNsPath string, iface string, bpfFd int, bpfFileName, bpfSec string) error {
	netNs, err := NetNamespace(netNsPath)
	if err != nil {
		return err
	}
	defer netNs.Close()

	err = netNs.Do(func(_ns cnins.NetNS) error {
		tcf, err := NewTcFacade(iface)
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
		//qdiscHandle := core.BuildHandle(0xffff, 0x0000)
		qdiscHandle := TcHandleIngressQdisc
		if err := tcf.addIngressQdisc(tc.HandleIngress, qdiscHandle); err != nil {
			return err
		}

		//filterHandle := core.BuildHandle(0x100, 0x12)
		filterHandle := TcHandleIngressFilter
		//if err := tcf.addBpfFilter(qdiscHandle, filterHandle, nil, bpfFd, bpfFileName, bpfSec); err != nil {
		if err := tcf.addBpfFilter(qdiscHandle, filterHandle, nil, bpfFd, bpfFileName, bpfSec); err != nil {
			return err
		}

		return nil
	})

	return err
}
