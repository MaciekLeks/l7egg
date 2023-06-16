package tools

import (
	"encoding/json"
	"fmt"
	cnins "github.com/containernetworking/plugins/pkg/ns"
	"github.com/florianl/go-tc"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"net"
	"os"
)

type HandleID uint32

const (
	HandleDefaultFilter HandleID = 0x1
	HandleIngress                = 0xFFFFFFF2
	HandleEgress                 = 0xFFFFFFF3
)

type TCClsActHelper struct {
	netNS   int
	ifaceID int
	clsact  *tc.Object
	tcnl    *tc.Tc
}

func NewOpen(netNSFD int, iface string) (*TCClsActHelper, error) {

	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("Could not get interface %s: %v\n", iface, err)
	}

	tcnl, err := tc.Open(&tc.Config{
		NetNS: netNSFD,
	})
	if err != nil {
		return nil, fmt.Errorf("Opening rtnetlink socket: %v\n", err)
	}

	qdiscs, err := tcnl.Qdisc().Get()
	if err != nil {
		return nil, fmt.Errorf("Getting qdiscs: %v\n", err)
	}

	var clsact *tc.Object
	for _, qdisc := range qdiscs {
		if int(qdisc.Ifindex) == devID.Index {
			if "clsact" == qdisc.Kind {
				tmp := qdisc //copy object
				clsact = &tmp
			}
		}
	}

	helper := &TCClsActHelper{
		netNS:   netNSFD,
		ifaceID: devID.Index,
		clsact:  clsact,
		tcnl:    tcnl,
	}

	return helper, nil
}

func (h *TCClsActHelper) Close() {
	if err := h.tcnl.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Closing rtnetlink socket: %v\n", err)
	}
}

func (h *TCClsActHelper) DeleteClsact() error {
	err := h.tcnl.Qdisc().Delete(h.clsact)
	if err != nil {
		return fmt.Errorf("Deleting clsact qdisc error: %+v\n", err)
	}

	fmt.Printf("Clsact qdisc (handle: %x, parent: %x) deleted.\n", h.clsact.Handle, h.clsact.Parent)

	return nil
}

func (h *TCClsActHelper) ShowFilter(handleID HandleID, parentHandleID HandleID) error {
	info := tc.Msg{
		Ifindex: uint32(h.ifaceID),
		Handle:  uint32(handleID), //TODO not taking  into account
		Parent:  uint32(parentHandleID),
	}
	filters, err := h.tcnl.Filter().Get(&info)

	fmt.Println("Len:", len(filters)) //TODO alwways 2 eventhough using Handle of the filter

	if err != nil {
		fmt.Println("Could not get filters from TC socket %#v", err)
	}
	for _, filter := range filters {
		filterB, _ := json.Marshal(filter)
		fmt.Println(string(filterB))

	}
	return nil
}

func (h *TCClsActHelper) DeleteFilter(handleID HandleID, parentHandleID HandleID) error {
	info := tc.Msg{
		Ifindex: uint32(h.ifaceID),
		Handle:  uint32(handleID), //TODO not taking  into account
		Parent:  uint32(parentHandleID),
	}
	filters, err := h.tcnl.Filter().Get(&info)

	if err != nil {
		fmt.Println("Could not get filters from TC socket for %#v", err)
	}
	for _, filter := range filters {
		if filter.Handle == uint32(handleID) { //TODO because of len(filters)=2
			err := h.tcnl.Filter().Delete(&filter)
			if err != nil {
				fmt.Println("Could not delete filter from TC socket for %#v", err)
				return err
			}
			fmt.Printf("Filter (handle: %x, parent: %x) deleted.\n", handleID, parentHandleID)
		}
	}
	return nil
}

// TODO move to tools
func must(err error, format string, args ...interface{}) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, format+"| %v\n", args, err)
		panic(err)
	}
}

func CleanInterface(netNs int, iface string) {
	h, err := NewOpen(netNs, iface)
	must(err, "Opening RTNETLINK socket")
	defer h.Close()

	err = h.ShowFilter(HandleDefaultFilter, HandleEgress)
	must(err, "Showing egress filter")

	err = h.DeleteFilter(HandleDefaultFilter, HandleEgress)
	must(err, "Deleting egress filter")

	err = h.ShowFilter(HandleDefaultFilter, HandleIngress)
	must(err, "Showing ingress filter")

	err = h.DeleteFilter(HandleDefaultFilter, HandleIngress)
	must(err, "Deleting ingress filter")

	err = h.DeleteClsact()
	must(err, "Deleting clsact qdisc")
}

func CleanInterfaces(netNsPath string, iiface string, eiface string) {
	var netns cnins.NetNS
	var err error
	if netNsPath != "" {
		netns, err = cnins.GetNS(netNsPath)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("can't open network namespace: %v", err))
			return
		}
		defer netns.Close()
		netns.Do(func(_ns cnins.NetNS) error {
			cleanNsInterface(int(netns.Fd()), iiface, eiface)
			//TOOD add error handling
			return nil
		})
	} else {
		cleanNsInterface(int(netns.Fd()), iiface, eiface)
	}
}

func cleanNsInterface(netNsFD int, iiface string, eiface string) {
	hi, err := NewOpen(netNsFD, iiface)
	must(err, "Opening RTNETLINK socket for ingress interface")
	he, err := NewOpen(netNsFD, eiface)
	must(err, "Opening RTNETLINK socket for egress interface")
	defer hi.Close()
	defer he.Close()

	err = he.DeleteFilter(HandleDefaultFilter, HandleEgress)
	must(err, "Deleting egress filter")

	err = hi.DeleteFilter(HandleDefaultFilter, HandleIngress)
	must(err, "Deleting ingress filter")

	if iiface != eiface {
		err = hi.DeleteClsact()
		must(err, "Deleting clsact qdisc")
	}

	err = he.DeleteClsact()
	must(err, "Deleting clsact qdisc")
}

//func GetNsIDFromFD(fd uintptr) (int, error) {
//	//return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERGROUPS)
//	//return syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, 0x3b)
//	nsID, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, fd, syscall.F_GETOWN, 0)
//	if errno != 0 {
//		return -1, errno
//	}
//
//	return int(nsID), nil
//}
