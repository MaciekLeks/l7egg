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
	podLabels        map[string]string
}

// clientEggManager holds ClientEgg and steering variables (stopFunc to stop it from the controller witout stopping the controller iself).
// waitGroup synchronize bpf main groutine starting from user.run function
type clientEggBox struct {
	stopFunc  context.CancelFunc
	waitGroup *sync.WaitGroup //TODO: only ene goroutine (in run(...)) - changing to channel?
	egg       *egg
	used      bool
}

type clientEggManager struct {
	//boxes    map[string]clientEggBox
	boxes    sync.Map
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
	cidr   string
	id     uint16
	lpmKey ILPMKey
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
	ip, ipNet, err := net.ParseCIDR(cidrS)
	must(err, "Can't parse ipv4 Net.")
	if err != nil {
		return nil, fmt.Errorf("can't parse CIDR %s", cidrS)
	}

	fmt.Println("#### parseCID ", ip, " ipNEt", ipNet)

	prefix, _ := ipNet.Mask.Size()
	if ipv4 := ip.To4(); ipv4 != nil {
		return &CIDR{cidrS, m.seqIdGen.Next(), ipv4LPMKey{uint32(prefix), [4]uint8(ipv4)}, assetNew}, nil
	} else if ipv6 := ip.To16(); ipv6 != nil {
		return &CIDR{cidrS, m.seqIdGen.Next(), ipv6LPMKey{uint32(prefix), [16]uint8(ipv6)}, assetNew}, nil
	}

	return nil, fmt.Errorf("can't converts CIDR to IPv4/IPv6 %s", cidrS)
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
			boxes:    sync.Map{},
			seqIdGen: tools.New[uint16](),
		}
	})
	return instance
}

func parseClientEgg(clientegg *ClientEgg) {

}

func (m *clientEggManager) Exists(key string) bool {
	if _, found := m.getBox(key); found {
		return true
	}
	return false
}

func (m *clientEggManager) NewClientEgg(iiface string, eiface string, cnsS []string, cidrsS []string, podLabels map[string]string) (*ClientEgg, error) {
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
		podLabels:        podLabels,
	}
	return clientegg, nil
}

// Save box but not run it
func (m *clientEggManager) Store(boxKey string, clientegg *ClientEgg) {
	egg := newEgg(clientegg)
	var box clientEggBox
	box.egg = egg
	m.boxes.Store(boxKey, &box)
}

// Run box
func (m *clientEggManager) Start(ctx context.Context, boxKey string) error {
	box, found := m.getBox(boxKey)
	if !found {
		return fmt.Errorf("box '%s' not found\n", boxKey)
	}

	subCtx, stopFunc := context.WithCancel(ctx)
	var subWaitGroup sync.WaitGroup

	box.stopFunc = stopFunc
	box.waitGroup = &subWaitGroup
	box.used = true

	m.boxes.Store(boxKey, box)

	return box.egg.run(subCtx, &subWaitGroup)
}

// Stop Stops one box
func (m *clientEggManager) Stop(key string) error {
	box, found := m.getBox(key)
	if !found {
		return fmt.Errorf("box '%s' not found\n", key)
	}
	fmt.Println("$$$>>>deleteEgg: stopping")
	box.stopFunc()
	fmt.Println("$$$>>>deleteEgg: waiting")
	box.waitGroup.Wait()
	fmt.Println("$$$>>>deleteEgg: done")
	m.boxes.Delete(key)

	return nil
}

// Wait Waits for root context cancel (e.g. SIGTERM),
// that's why we do not use m.stopFunc because cancelling comes from the root context
func (m *clientEggManager) Wait() {
	var stopWaitGroup sync.WaitGroup
	//for key, box := range m.boxes. {
	//	stopWaitGroup.Add(1)
	//	go func() {
	//		defer stopWaitGroup.Done()
	//		fmt.Printf("Waiting - %s\n", key)
	//		box.waitGroup.Wait()
	//	}()
	//}
	m.boxes.Range(func(key interface{}, value interface{}) bool {
		stopWaitGroup.Add(1)
		go func() {
			defer stopWaitGroup.Done()
			fmt.Printf("Waiting - %s\n", key)
			box, ok := value.(*clientEggBox)
			if !ok {
				//do as runtimeutill error
				fmt.Printf("Cant' do type assertion - %s\n", key)
				return
			}
			box.waitGroup.Wait()
		}()
		return true
	})

	stopWaitGroup.Wait()
}

func (m *clientEggManager) getBox(key string) (*clientEggBox, bool) {
	var box *clientEggBox

	value, found := m.boxes.Load(key)
	if !found {
		return nil, false
	}
	box, ok := value.(*clientEggBox)
	if !ok {
		return nil, false
	}

	return box, true
}

func (m *clientEggManager) UpdateCIDRs(boxKey string, newCIDRsS []string) error {

	cidrs, err := m.parseCIDRs(newCIDRsS)
	if err != nil {
		return fmt.Errorf("Parsing input data %#v", err)
	}

	box, found := m.getBox(boxKey)
	if !found {
		return fmt.Errorf("can't find box")
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

	box, found := m.getBox(boxKey)
	if !found {
		return fmt.Errorf("can't find box")
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
