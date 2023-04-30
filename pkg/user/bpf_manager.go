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
	CNs              []string
	CIDRs            *tools.SafeSlice[*CIDR]
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
	boxes map[string]clientEggBox
}

type cidrStatus byte

const (
	cidrSynced cidrStatus = iota
	cidrNew               //new to add to the ebpf map
	cidrStale  = 2        //could removed

)

type CIDR struct {
	//TODO ipv6 needed
	ipv4LPMKey
	status cidrStatus
}

var (
	instance *clientEggManager
	once     sync.Once
)

// ParseCIDR TODO: only ipv4
func ParseCIDR(cidrS string) (*CIDR, error) {
	_, ipv4Net, err := net.ParseCIDR(cidrS)
	must(err, "Can't parse ipv4 Net.")
	if err != nil {
		return nil, fmt.Errorf("Can't parse IPv4 CIDR")
	}

	prefix, _ := ipv4Net.Mask.Size()
	ip := ipv4Net.IP.To4()
	return &CIDR{ipv4LPMKey{uint32(prefix), ip2Uint32(ip)}, cidrNew}, nil
}

// ParseCIDRs TODO: only ipv4
func ParseCIDRs(cidrsS []string) ([]*CIDR, error) {
	var cidrs []*CIDR
	for _, cidrS := range cidrsS {
		cidr, err := ParseCIDR(cidrS)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, cidr)
	}

	return cidrs, nil
}

func BpfManagerInstance() *clientEggManager {
	once.Do(func() {
		instance = &clientEggManager{
			boxes: map[string]clientEggBox{},
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

func (m *clientEggManager) UpdateCIDRs(key string, newCIDRsS []string) error {

	cidrs, err := ParseCIDRs(newCIDRsS)
	if err != nil {
		return fmt.Errorf("Parsing input data %#v", err)
	}

	box, found := m.boxes[key]
	if !found {
		return fmt.Errorf("Checking key in map %s\n", key)
	}

	fmt.Printf("box.egg %#v\n", box.egg)
	if err := box.egg.updateCIDRs(cidrs); err != nil {
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
