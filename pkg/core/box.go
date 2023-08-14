package core

//
//import (
//	"context"
//	"github.com/MaciekLeks/l7egg/pkg/controller/common"
//	cgroupsv2 "github.com/containerd/cgroups/v2"
//	"sync"
//)
//
//type IEggManager interface {
//	Start(context.Context, string, *Eggy)
//	Stop(string)
//	Wait()
//	UpdateCIDRs([]string)
//	Exists(string)
//}
//
//// EggBox holds Eggy and steering variables (stopFunc to stop it from the controller witout stopping the controller iself).
//// waitGroup synchronize bpf main groutine starting from user.run function
//type EggBox struct {
//	stopFunc    context.CancelFunc
//	waitGroup   *sync.WaitGroup //TODO: only ene goroutine (in run(...)) - changing to channel?
//	ebpfy         *ebpfy
//	programInfo common.ProgramInfo
//	//netNsPath string
//	// active if box with bpf is running
//	active bool
//}
//
//type IEggBox interface {
//	Egg() *ebpfy
//}
//
////type eggManager struct {
////	//boxes    map[string]EggBox
////	Boxes syncx.SafeMap[common.BoxKey, *EggBox]
////	//seqIdGen syncx.ISeqId[uint16] //tbd: moved to syncx.Sequencer
////}
////
////var (
////	instance *eggManager
////	once     sync.Once
////)
//
//func (box *EggBox) Egg() *ebpfy {
//	return box.ebpfy
//}
//
//func (box *EggBox) Boxes() *ebpfy {
//	return box.ebpfy
//}

//func BpfManagerInstance() *eggManager {
//	once.Do(func() {
//		instance = &eggManager{
//			Boxes: syncx.SafeMap[common.BoxKey, *EggBox]{},
//			//seqIdGen: syncx.New[uint16](),
//		}
//	})
//	return instance
//}
//
//func (m *eggManager) BoxExists(boxKey common.BoxKey) bool {
//	if _, found := m.getBox(boxKey); found {
//		return true
//	}
//	return false
//}
//
//// BoxAny returns box that satisfies the f function
//func (m *eggManager) BoxAny(f func(boxKey common.BoxKey, ibox IEggBox) bool) (*EggBox, bool) {
//	var foundBox *EggBox
//	var found bool
//	//TODO if during this iteration m.boxes changes we will not know it, see sync map Range doc
//	m.Boxes.Range(func(boxKey common.BoxKey, box *EggBox) bool {
//		if ok := f(boxKey, box); ok {
//			return false
//		}
//
//		return true
//	})
//
//	return foundBox, found
//}

// BoxStore stores a box but not run it
//func (m *eggManager) BoxStore(ctx context.Context, boxKey common.BoxKey, ceggi *Eggy) error {
//	logger := klog.FromContext(ctx)
//	logger.Info("Storing box for boxKey%s'\n", boxKey)
//	ebpfy := newEbpfy(ceggi)
//	if ceggi.ProgramType == common.ProgramTypeCgroup { //TODO needed only if shaping
//		cgroup, err := net.CreateCgroupNetCls(net.CgroupFsName, net.TcHandleHtbClass) //TODO classid: 10:10 always?
//		if err != nil {
//			return err
//		}
//		ebpfy.cgroupNetCls = cgroup
//	}
//	var box EggBox
//	box.ebpfy = ebpfy
//	m.Boxes.Store(boxKey, &box)
//
//	return nil
//}
//
//// BoxStart box
//func (m *eggManager) BoxStart(ctx context.Context, boxKey common.BoxKey, netNsPath string, cgroupPath string, pid uint32) error {
//
//	box, found := m.getBox(boxKey)
//	if !found {
//		return fmt.Errorf("box '%s' not found\n", boxKey)
//	}
//
//	subCtx, stopFunc := context.WithCancel(ctx)
//	var subWaitGroup sync.WaitGroup
//	box.stopFunc = stopFunc
//	box.waitGroup = &subWaitGroup
//	//box.netNsPath = netNsPath
//	box.programInfo = common.ProgramInfo{
//		box.ebpfy.Eggy.ProgramType,
//		netNsPath,
//		cgroupPath,
//	}
//
//	box.active = true
//
//	m.Boxes.Store(boxKey, box)
//
//	return box.ebpfy.run(subCtx, &subWaitGroup, box.programInfo /*netNsPath, cgroupPath*/, pid)
//}

// Stop Stops one box
//func (m *eggManager) Stop(boxKey common.BoxKey) error {
//	box, found := m.getBox(boxKey)
//	if !found {
//		return fmt.Errorf("box '%s' not found\n", boxKey)
//	}
//	fmt.Println("$$$>>>deleteEgg: stopping")
//
//	box.stopFunc()
//	fmt.Println("$$$>>>deleteEgg: waiting")
//	box.waitGroup.Wait()
//	fmt.Println("$$$>>>deleteEgg: done")
//	m.Boxes.Delete(boxKey)
//
//	return nil
//}

// Wait Waits for root context cancel (e.g. SIGTERM),
// that's why we do not use m.stopFunc because cancelling comes from the root context
//func (m *eggManager) Wait() {
//	var stopWaitGroup sync.WaitGroup
//	//for key, box := range m.boxes. {
//	//	stopWaitGroup.Add(1)
//	//	go func() {
//	//		defer stopWaitGroup.Done()
//	//		fmt.Printf("Waiting - %s\n", key)
//	//		box.waitGroup.Wait()
//	//	}()
//	//}
//	m.Boxes.Range(func(boxKey common.BoxKey, box *EggBox) bool {
//		stopWaitGroup.Add(1)
//		go func() {
//			defer stopWaitGroup.Done()
//			fmt.Printf("Waiting - %s\n", boxKey)
//			if box.waitGroup != nil {
//				box.waitGroup.Wait()
//			}
//		}()
//		return true
//	})
//
//	stopWaitGroup.Wait()
//}

//func (m *eggManager) getBox(boxKey common.BoxKey) (*EggBox, bool) {
//	return m.Boxes.Load(boxKey)
//}

//func getContainerdCgroupPath(pid uint32) (string, error) {
//	return cgroupsv2.PidGroupPath(int(pid))
//}

//	func (m *eggManager) RunBoxWithContainer(ctx context.Context, boxKey common.BoxKey, containerId string) error {
//		logger := klog.FromContext(ctx)
//
//		pid, err := controller.GetContainerPid(ctx, containerId)
//		if err != nil {
//			utilruntime.HandleError(fmt.Errorf("can't get container pid: %v", err))
//			return fmt.Errorf("can't get container pid: %v", err)
//		}
//
//		logger.V(2).Info("runEgg-5")
//
//		box, ok := m.Boxes.Load(boxKey)
//		if !ok {
//			utilruntime.HandleError(fmt.Errorf("Box %s not found", boxKey))
//			return fmt.Errorf("Box %s not found", boxKey)
//		}
//		logger.V(2).Info("runEgg-6")
//
//		var cgroupPath string
//		netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
//
//		if box.Egg().Eggy.ProgramType == common.ProgramTypeCgroup {
//			logger.V(2).Info("runEgg-7-cgroup")
//			cgroupPath, err = getContainerdCgroupPath(pid)
//			if err != nil {
//				return fmt.Errorf("cgroup path error: %v", err)
//			}
//		} else {
//			logger.V(2).Info("runEgg-7-tc")
//		}
//
//		return m.BoxStart(ctx, boxKey, netNsPath, cgroupPath, pid)
//	}
//
//	func (m *eggManager) RunBoxWithPid(ctx context.Context, boxKey common.BoxKey, pid uint32) error {
//		logger := klog.FromContext(ctx)
//		var err error
//
//		box, ok := m.Boxes.Load(boxKey)
//		if !ok {
//			utilruntime.HandleError(fmt.Errorf("Box %s not found", boxKey))
//			return fmt.Errorf("Box %s not found", boxKey)
//		}
//		logger.V(2).Info("runEgg-6")
//
//		var cgroupPath string
//		netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
//
//		if box.Egg().Eggy.ProgramType == common.ProgramTypeCgroup {
//			logger.V(2).Info("runEgg-7-cgroup")
//			cgroupPath, err = getContainerdCgroupPath(pid)
//			if err != nil {
//				return fmt.Errorf("cgroup path error: %v", err)
//			}
//		} else {
//			logger.V(2).Info("runEgg-7-tc")
//		}
//
//		return m.BoxStart(ctx, boxKey, netNsPath, cgroupPath, pid)
//	}
//func (m *eggManager) UpdateCIDRs(boxKey common.BoxKey, newCIDRsS []string) error {
//
//	cidrs, err := parseCIDRs(newCIDRsS)
//	if err != nil {
//		return fmt.Errorf("Parsing input data %#v", err)
//	}
//
//	box, found := m.getBox(boxKey)
//	if !found {
//		return fmt.Errorf("can't find box")
//	}
//
//	fmt.Printf("box.ebpfy %#v\n", box.ebpfy)
//	if err := box.ebpfy.updateCIDRs(cidrs); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (m *eggManager) UpdateCNs(boxKey common.BoxKey, newCNsS []string) error {
//	cns, err := parseCNs(newCNsS)
//	if err != nil {
//		return fmt.Errorf("Parsing input data %#v", err)
//	}
//
//	box, found := m.getBox(boxKey)
//	if !found {
//		return fmt.Errorf("can't find box")
//	}
//
//	fmt.Printf("box.ebpfy %#v\n", box.ebpfy)
//	if err := box.ebpfy.updateCNs(cns); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (m *eggManager) UpdateEgg(boxKey common.BoxKey, newSpec v1alpha1.ClusterEggSpec) error {
//	fmt.Printf("+++++++++++++++ 1")
//	err := m.UpdateCIDRs(boxKey, newSpec.Egress.Cidrs)
//	if err != nil {
//		return err
//	}
//
//	fmt.Printf("+++++++++++++++ 2")
//	err = m.UpdateCNs(boxKey, newSpec.Egress.CommonNames)
//	if err != nil {
//		return err
//	}
//
//	fmt.Printf("+++++++++++++++ 3")
//	return nil
//}

//func (m *eggManager) StoreBoxKeys(ctx context.Context, eggi *Eggy, pi *controller.PodBox) ([]common.BoxKey, error) {
//	var matchedKeyBoxes []common.BoxKey
//	var err error
//	if eggi.ProgramType == common.ProgramTypeCgroup {
//		matchedKeyBoxes = make([]common.BoxKey, len(pi.Containers))
//		for i := 0; i < len(pi.Containers); i++ {
//			boxKey := common.BoxKey{Pod: pi.NamespaceName(), Egg: eggi.NamespaceName(), ContainerId: pi.Containers[i].ContainerID}
//			err = m.BoxStore(ctx, boxKey, eggi)
//			if err != nil {
//				break
//			}
//			matchedKeyBoxes[i] = boxKey
//		}
//	} else {
//		matchedKeyBoxes = make([]common.BoxKey, 1)
//		boxKey := common.BoxKey{Pod: pi.NamespaceName(), Egg: eggi.NamespaceName(), ContainerId: "*"}
//		err = m.BoxStore(ctx, boxKey, eggi)
//		if err != nil {
//			return matchedKeyBoxes, err
//		}
//		matchedKeyBoxes[0] = boxKey
//	}
//
//	return matchedKeyBoxes, err
//}
//
//func (m *eggManager) RunBoxySet(ctx context.Context, eggi *Eggy, pi *controller.PodBox) (err error) {
//	if eggi.ProgramType == common.ProgramTypeCgroup {
//		for i := 0; i < len(pi.Containers); i++ {
//			if pi.Containers[i].AssetStatus == common.AssetNew {
//				err = m.RunBoxWithPid(ctx, pi.MatchedKeyBoxes[i], pi.Containers[i].Pid)
//				if err != nil {
//					return err
//				}
//			}
//		}
//	} else {
//		if pi.Containers[0].AssetStatus == common.AssetNew {
//			err = m.RunBoxWithPid(ctx, pi.MatchedKeyBoxes[0], pi.Containers[0].Pid) //TODO: could be initial - test it
//			if err != nil {
//				return err
//			}
//		}
//	}
//
//	// whatever ProgramType is, we set all containers to synced
//	for i := 0; i < len(pi.Containers); i++ {
//		pi.Containers[i].AssetStatus = common.AssetSynced
//	}
//
//	return nil
//}
