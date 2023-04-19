package tools

import (
	"fmt"
	"github.com/florianl/go-tc"
	"net"
	"os"
)

func DeleteClsactByNetNS(netNS int, iface string) error {
	devID, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("Could not get interface ID: %v\n", err)
	}

	tcnl, err := tc.Open(&tc.Config{
		NetNS: netNS,
	})
	if err != nil {
		return fmt.Errorf("Opening rtnetlink socket: %v\n", err)
	}
	defer func() {
		if err := tcnl.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Closing rtnetlink socket: %v\n", err)
		}
	}()

	//Get all qdisc in netNS
	qdiscs, err := tcnl.Qdisc().Get()
	if err != nil {
		return fmt.Errorf("Getting qdiscs: %v\n", err)
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

	if clsact != nil {
		err = tcnl.Qdisc().Delete(clsact)
		if err != nil {
			return fmt.Errorf("Deleting clsact qdisc error: %+v\n", err)
		}
	} else {
		return fmt.Errorf("No clsact found.")
	}

	return nil
}

func DeleteClsact(iface string) error {
	return DeleteClsactByNetNS(0, iface)
}
