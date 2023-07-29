package core

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/net"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sync"
)

type IEggManager interface {
	Start(context.Context, string, *EggInfo)
	Stop(string)
	Wait()
	UpdateCIDRs([]string)
	Exists(string)
}

// EggBox holds EggInfo and steering variables (stopFunc to stop it from the controller witout stopping the controller iself).
// waitGroup synchronize bpf main groutine starting from user.run function
type EggBox struct {
	stopFunc    context.CancelFunc
	waitGroup   *sync.WaitGroup //TODO: only ene goroutine (in run(...)) - changing to channel?
	egg         *egg
	programInfo common.ProgramInfo
	//netNsPath string
	// active if box with bpf is running
	active bool
}

type IEggBox interface {
	Egg() *egg
}

type BoxKey struct {
	Egg types.NamespacedName
	Pod types.NamespacedName
}

func (bk BoxKey) String() string {
	return fmt.Sprintf("%s-%s", bk.Egg.String(), bk.Pod.String())
}

type eggManager struct {
	//boxes    map[string]EggBox
	Boxes syncx.SafeMap[BoxKey, *EggBox]
	//seqIdGen syncx.ISeqId[uint16] //tbd: moved to syncx.Sequencer
}

var (
	instance *eggManager
	once     sync.Once
)

func (box *EggBox) Egg() *egg {
	return box.egg
}

func (box *EggBox) Boxes() *egg {
	return box.egg
}

func BpfManagerInstance() *eggManager {
	once.Do(func() {
		instance = &eggManager{
			Boxes: syncx.SafeMap[BoxKey, *EggBox]{},
			//seqIdGen: syncx.New[uint16](),
		}
	})
	return instance
}

func (m *eggManager) BoxExists(boxKey BoxKey) bool {
	if _, found := m.getBox(boxKey); found {
		return true
	}
	return false
}

// BoxAny returns box that satisfies the f function
func (m *eggManager) BoxAny(f func(boxKey BoxKey, ibox IEggBox) bool) (*EggBox, bool) {
	var foundBox *EggBox
	var found bool
	//TODO if during this iteration m.boxes changes we will not know it, see sync map Range doc
	m.Boxes.Range(func(boxKey BoxKey, box *EggBox) bool {
		if ok := f(boxKey, box); ok {
			return false
		}

		return true
	})

	return foundBox, found
}

// BoxStore stores a box but not run it
func (m *eggManager) BoxStore(ctx context.Context, boxKey BoxKey, ceggi *EggInfo) error {
	logger := klog.FromContext(ctx)
	logger.Info("Storing box for boxKey%s'\n", boxKey)
	egg := newEmptyEgg(ceggi)
	if ceggi.ProgramType == common.ProgramTypeCgroup { //TODO needed only if shaping
		cgroup, err := net.CreateCgroupNetCls(net.CgroupFsName, net.TcHandleHtbClass) //TODO classid: 10:10 always?
		if err != nil {
			return err
		}
		egg.cgroupNetCls = cgroup
	}
	var box EggBox
	box.egg = egg
	m.Boxes.Store(boxKey, &box)

	return nil
}

// BoxStart box
func (m *eggManager) BoxStart(ctx context.Context, boxKey BoxKey, netNsPath string, cgroupPath string, pids ...uint32) error {

	box, found := m.getBox(boxKey)
	if !found {
		return fmt.Errorf("box '%s' not found\n", boxKey)
	}

	subCtx, stopFunc := context.WithCancel(ctx)
	var subWaitGroup sync.WaitGroup
	box.stopFunc = stopFunc
	box.waitGroup = &subWaitGroup
	//box.netNsPath = netNsPath
	box.programInfo = common.ProgramInfo{
		box.egg.ProgramType,
		netNsPath,
		cgroupPath,
	}

	box.active = true

	m.Boxes.Store(boxKey, box)

	return box.egg.run(subCtx, &subWaitGroup, box.programInfo /*netNsPath, cgroupPath*/, pids...)
}

// Stop Stops one box
func (m *eggManager) Stop(boxKey BoxKey) error {
	box, found := m.getBox(boxKey)
	if !found {
		return fmt.Errorf("box '%s' not found\n", boxKey)
	}
	fmt.Println("$$$>>>deleteEgg: stopping")

	box.stopFunc()
	fmt.Println("$$$>>>deleteEgg: waiting")
	box.waitGroup.Wait()
	fmt.Println("$$$>>>deleteEgg: done")
	m.Boxes.Delete(boxKey)

	return nil
}

// Wait Waits for root context cancel (e.g. SIGTERM),
// that's why we do not use m.stopFunc because cancelling comes from the root context
func (m *eggManager) Wait() {
	var stopWaitGroup sync.WaitGroup
	//for key, box := range m.boxes. {
	//	stopWaitGroup.Add(1)
	//	go func() {
	//		defer stopWaitGroup.Done()
	//		fmt.Printf("Waiting - %s\n", key)
	//		box.waitGroup.Wait()
	//	}()
	//}
	m.Boxes.Range(func(boxKey BoxKey, box *EggBox) bool {
		stopWaitGroup.Add(1)
		go func() {
			defer stopWaitGroup.Done()
			fmt.Printf("Waiting - %s\n", boxKey)
			if box.waitGroup != nil {
				box.waitGroup.Wait()
			}
		}()
		return true
	})

	stopWaitGroup.Wait()
}

func (m *eggManager) getBox(boxKey BoxKey) (*EggBox, bool) {
	return m.Boxes.Load(boxKey)
}

func (m *eggManager) UpdateCIDRs(boxKey BoxKey, newCIDRsS []string) error {

	cidrs, err := parseCIDRs(newCIDRsS)
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

func (m *eggManager) UpdateCNs(boxKey BoxKey, newCNsS []string) error {
	cns, err := parseCNs(newCNsS)
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

func (m *eggManager) UpdateEgg(boxKey BoxKey, newSpec v1alpha1.ClusterEggSpec) error {
	fmt.Printf("+++++++++++++++ 1")
	err := m.UpdateCIDRs(boxKey, newSpec.Egress.CIDRs)
	if err != nil {
		return err
	}

	fmt.Printf("+++++++++++++++ 2")
	err = m.UpdateCNs(boxKey, newSpec.Egress.CommonNames)
	if err != nil {
		return err
	}

	fmt.Printf("+++++++++++++++ 3")
	return nil
}
