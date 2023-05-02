package user

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/tools"
	"net"
	"sync"
)

type IClientEggManager interface {
	Start(context.Context, string, *ClientEgg)
	Stop(string)
	Wait()
	UpdateCIDRs([]string)
	Exists(string)
}

type ClientEgg struct {
	CNs              *tools.SafeSlice[CN]
	CIDRs            []*CIDR
	IngressInterface string
	EgressInterface  string
	BPFObjectPath    string
}

// clientEggManager holds ClientEgg and steering variables (stopFunc to stop it from the controller witout stopping the controller iself).
// waitGroup synchronize bpf main groutine starting from user.run function
type clientEggBox struct {
	stopFunc  context.CancelFunc
	waitGroup *sync.WaitGroup //TODO: only ene goroutine (in run(...)) - changing to channel?
	egg       *egg
}

type clientEggManager struct {
	boxes    map[string]clientEggBox
	seqIdGen tools.ISeqId[uint16]
}

type assetStatus byte

const (
	assetSynced assetStatus = iota
	assetStale              //could be removed
	assetNew                //new to add to the ebpf map
)

type CIDR struct {
	//TODO ipv6 needed
	cidr string
	id   uint16
	ipv4LPMKey
	status assetStatus
}

type CN struct {
	cn     string
	id     uint16
	status assetStatus
}

var (
	instance *clientEggManager
	once     sync.Once
)

// parseCIDR TODO: only ipv4
func (m *clientEggManager) parseCIDR(cidrS string) (*CIDR, error) {
	_, ipv4Net, err := net.ParseCIDR(cidrS)
	must(err, "Can't parse ipv4 Net.")
	if err != nil {
		return nil, fmt.Errorf("Can't parse IPv4 CIDR")
	}

	prefix, _ := ipv4Net.Mask.Size()
	ip := ipv4Net.IP.To4()
	return &CIDR{cidrS, m.seqIdGen.Next(), ipv4LPMKey{uint32(prefix), ip2Uint32(ip)}, assetNew}, nil
}

// ParseCIDRs TODO: only ipv4
func (m *clientEggManager) parseCIDRs(cidrsS []string) ([]*CIDR, error) {
	var cidrs []*CIDR
	for _, cidrS := range cidrsS {
		cidr, err := m.parseCIDR(cidrS)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, cidr)
	}

	return cidrs, nil
}

// ParseCN returns CN object from string
func (m *clientEggManager) parseCN(cnS string) (CN, error) {
	//TODO add some validation before returning CN
	//we are sync - due to we do not have to update kernel side
	return CN{cnS, m.seqIdGen.Next(), assetNew}, nil
}

func (m *clientEggManager) parseCNs(cnsS []string) ([]CN, error) {
	var cns []CN
	for _, cnS := range cnsS {
		cn, err := m.parseCN(cnS)
		if err != nil {
			return nil, err
		}
		cns = append(cns, cn)
	}

	return cns, nil
}

func BpfManagerInstance() *clientEggManager {
	once.Do(func() {
		instance = &clientEggManager{
			boxes:    map[string]clientEggBox{},
			seqIdGen: tools.New[uint16](),
		}
	})
	return instance
}

func parseClientEgg(clientegg *ClientEgg) {

}

func (m *clientEggManager) Exists(key string) bool {
	if _, found := m.boxes[key]; found {
		return true
	}
	return false
}

func (m *clientEggManager) NewClientEgg(iiface string, eiface string, cnsS []string, cidrsS []string) (*ClientEgg, error) {
	cidrs, err := m.parseCIDRs(cidrsS)
	if err != nil {
		fmt.Errorf("Parsing input data %#v", err)
		return nil, err
	}

	cns, err := m.parseCNs(cnsS)
	if err != nil {
		fmt.Errorf("Parsing input data %#v", err)
		return nil, err
	}
	safeCNs := tools.SafeSlice[CN]{}
	safeCNs.Append(cns...)

	clientegg := &ClientEgg{ //TODO make a function to wrap this up (parsing, building the object)
		IngressInterface: iiface,
		EgressInterface:  eiface,
		CNs:              &safeCNs,
		CIDRs:            cidrs,
		BPFObjectPath:    "./l7egg.bpf.o",
	}
	return clientegg, nil
}

func (m *clientEggManager) Start(ctx context.Context, key string, clientegg *ClientEgg) {
	subCtx, stopFunc := context.WithCancel(ctx)
	var subWaitGroup sync.WaitGroup

	egg := newEgg(clientegg)
	m.boxes[key] = clientEggBox{
		stopFunc:  stopFunc,
		waitGroup: &subWaitGroup,
		egg:       egg,
	}

	egg.run(subCtx, &subWaitGroup) //TODO add some error handling
}

// Stop Stops one box
func (m *clientEggManager) Stop(key string) {
	box, found := m.boxes[key]
	if !found {
		fmt.Printf("Checking key in map %s\n", key)
		return
	}
	fmt.Println("$$$>>>deleteEgg: stopping")
	box.stopFunc()
	fmt.Println("$$$>>>deleteEgg: waiting")
	box.waitGroup.Wait()
	fmt.Println("$$$>>>deleteEgg: done")
	delete(m.boxes, key)
}

// Wait Waits for root context cancel (e.g. SIGTERM),
// that's why we do not use m.stopFunc because cancelling comes from the root context
func (m *clientEggManager) Wait() {
	var stopWaitGroup sync.WaitGroup
	for key, box := range m.boxes {
		stopWaitGroup.Add(1)
		go func() {
			defer stopWaitGroup.Done()
			fmt.Printf("Waiting - %s\n", key)
			box.waitGroup.Wait()
		}()
	}
	stopWaitGroup.Wait()
}

func (m *clientEggManager) UpdateCIDRs(boxKey string, newCIDRsS []string) error {

	cidrs, err := m.parseCIDRs(newCIDRsS)
	if err != nil {
		return fmt.Errorf("Parsing input data %#v", err)
	}

	box, found := m.boxes[boxKey]
	if !found {
		return fmt.Errorf("Checking key in map %s\n", boxKey)
	}

	fmt.Printf("box.egg %#v\n", box.egg)
	if err := box.egg.updateCIDRs(cidrs); err != nil {
		return err
	}

	return nil
}

func (m *clientEggManager) UpdateCNs(boxKey string, newCNsS []string) error {

	//TODO: parsing needed!!!
	cns, err := m.parseCNs(newCNsS)
	if err != nil {
		return fmt.Errorf("Parsing input data %#v", err)
	}

	box, found := m.boxes[boxKey]
	if !found {
		return fmt.Errorf("Checking key in map %s\n", boxKey)
	}

	fmt.Printf("box.egg %#v\n", box.egg)
	if err := box.egg.updateCNs(cns); err != nil {
		return err
	}

	return nil
}

func (m *clientEggManager) UpdateClientEgg(boxKey string, newCIDRsS []string, newCNsS []string) error {
	err := m.UpdateCIDRs(boxKey, newCIDRsS)
	if err != nil {
		return err
	}

	err = m.UpdateCNs(boxKey, newCNsS)
	if err != nil {
		return err
	}

	return nil
}

//
//func findAndDelete(s []string, item string) []string {
//	index := 0
//	for _, i := range s {
//		if i != item {
//			s[index] = i
//			index++
//		}
//	}
//	return s[:index]
//}
