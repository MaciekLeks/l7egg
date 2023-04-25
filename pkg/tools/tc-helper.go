package tools

import (
	"encoding/json"
	"fmt"
	"github.com/florianl/go-tc"

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

func NewOpen(netNS int, iface string) (*TCClsActHelper, error) {

	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("Could not get interface ID: %v\n", err)
	}

	tcnl, err := tc.Open(&tc.Config{
		NetNS: netNS,
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
		netNS:   netNS,
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

	fmt.Printf("Clsact qdisc (Handle: %x Parent: %x) deleted.", h.clsact.Handle, h.clsact.Parent)

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
			fmt.Printf("Filter (Handle: %x Parent: %x) deleted.\n", handleID, parentHandleID)
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

func CleanInterface(netNS int, iface string) {
	h, err := NewOpen(netNS, iface)
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

func CleanInterfaces(netNS int, iiface string, eiface string) {
	hi, err := NewOpen(0, iiface)
	must(err, "Opening RTNETLINK socket for ingress interface")
	he, err := NewOpen(0, eiface)
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
