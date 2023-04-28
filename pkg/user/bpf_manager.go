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
}

type clientEggBox struct {
	stopFunc  context.CancelFunc
	waitGroup *sync.WaitGroup
	clientegg *ClientEgg
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

	m.boxes[key] = clientEggBox{
		stopFunc:  stopFunc,
		waitGroup: &subWaitGroup,
		clientegg: clientegg,
	}

	clientegg.run(subCtx, &subWaitGroup) //TODO add some error handling
}

// Stops one box
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

// Waits for root context cancel (e.g. SIGTERM), that's why we do not use m.stopFunc because cancelling already comes from the root context
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
