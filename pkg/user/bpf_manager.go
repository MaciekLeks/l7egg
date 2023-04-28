package user

import (
	"context"
	"fmt"
	"sync"
)

type IClientEggManager interface {
	Start(context.Context, string, *ClientEgg)
	Stop(string)
	Wait()
	UpdateCIDRs([]string)
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

var (
	instance *clientEggManager
	once     sync.Once
)

func BpfManagerInstance() *clientEggManager {
	once.Do(func() {
		instance = &clientEggManager{
			boxes: map[string]clientEggBox{},
		}
	})
	return instance
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

func (m *clientEggManager) UpdateCIDRs(key string, newCIDRs []string) {
	//box, found := m.boxes[key]
	//if !found {
	//	fmt.Printf("Checking key in map %s\n", key)
	//	return
	//}
	//
	//currentCIDRs := box.egg.CIDRs
	//
	//for ccidr := range currentCIDRs {
	//
	//}
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
