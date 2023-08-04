package core

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/containerd/cgroups/v3/cgroup1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sync"
)

type Boxy struct {
	stopFunc  context.CancelFunc
	waitGroup *sync.WaitGroup //TODO: only ene goroutine (in run(...)) - changing to channel?
	egg       *egg
	//programInfo common.ProgramInfo
	netNsPath string
}

func (b *Boxy) RunBoxWithPid(ctx context.Context, pid uint32) error {
	//TODO implement me
	panic("implement me")
}

type Boxer interface {
	Stop() error
	Wait()
	RunWithContainer(ctx context.Context, cb *controller.ContainerBox) error
	RunWithPid(ctx context.Context, pid uint32) error
	EggNamespaceName() types.NamespacedName
}

type TcBoxy struct {
	*Boxy
}

type CgroupBoxy struct {
	*Boxy
	cgroupPath   string
	cgroupNetCls *cgroup1.Cgroup //references to egg cgroup net_cls for cgroup programs
}

//type CgroupNetClsBoxy struct {
//	*Boxy
//	cgroupNetCls cgroup1.Cgroup //cgroup net_cls for cgroup programs
//}

func NewBoxy(eggi *EggInfo) Boxer {
	// returns CgroupBoxy or TcBoxy based on EggInfo.ProgramType
	switch eggi.ProgramType {
	case common.ProgramTypeTC:
		return NewTcBoxy(eggi)
	case common.ProgramTypeCgroup:
		return NewCgroupBoxy(eggi)
	default:
		klog.Fatalf("unknown program type: %s", eggi.ProgramType)
	}
	return nil
}

func NewTcBoxy(eggi *EggInfo) *TcBoxy {
	return &TcBoxy{
		Boxy: &Boxy{
			egg: newEmptyEgg(eggi),
		},
	}
}

func NewCgroupBoxy(eggi *EggInfo) *CgroupBoxy {
	return &CgroupBoxy{
		Boxy: &Boxy{
			egg: newEmptyEgg(eggi),
		},
	}
}

func (b *Boxy) Stop() error {
	b.stopFunc()
	b.waitGroup.Wait()
	return nil
}

func (b *Boxy) EggNamespaceName() types.NamespacedName {
	return b.egg.EggInfo.NamespaceName()
}

func (b *CgroupBoxy) Stop() error {
	//_ = b.cgroupNetCls.Delete() //egg should Delete net class cgroup
	return b.Stop()
}

func (b *Boxy) Wait() {
	b.waitGroup.Wait()
}

func (b *Boxy) start(ctx context.Context, fn func(ctx context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	b.stopFunc = cancel
	b.waitGroup.Add(1)
	var err error
	go func() {
		defer b.waitGroup.Done()
		err = fn(ctx)
	}()

	return err
}

func (b *CgroupBoxy) RunWithPid(ctx context.Context, pid uint32) error {
	logger := klog.FromContext(ctx)
	var err error
	fmt.Println("CgroupBoxy:runBoxWithPid")

	var cgroupPath string
	logger.V(2).Info("runBoxWithPid: getting network space path")
	netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)

	logger.V(2).Info("runBoxWithPid: getting cgroup path")
	cgroupPath, err = getContainerdCgroupPath(pid)
	if err != nil {
		return fmt.Errorf("cgroup path error: %v", err)
	}

	b.cgroupPath = cgroupPath
	b.netNsPath = netNsPath

	if b.egg.EggInfo.Shaping != nil && b.egg.cgroupNetCls != nil {
		//b.egg.addCgroupNetClsProgram(b.egg.cgroupNetCls, b.egg.EggInfo.Shaping)
		// build stack
		// add filter
		b.cgroupNetCls = &b.egg.cgroupNetCls
	}

	return b.start(ctx, func(ctx context.Context) error {
		return b.egg.run(ctx, b.waitGroup, common.ProgramTypeCgroup, netNsPath, cgroupPath, pid)
	})
}

func (b *TcBoxy) RunWithPid(ctx context.Context, pid uint32) error {
	logger := klog.FromContext(ctx)
	fmt.Println("TcBoxy:runBoxWithPid")

	logger.V(2).Info("runBoxWithPid: getting network space path")
	netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	b.netNsPath = netNsPath

	return b.start(ctx, func(ctx context.Context) error {
		return b.egg.run(ctx, b.waitGroup, common.ProgramTypeTC, netNsPath, "", pid)
	})
}

func (b *Boxy) RunWithContainer(ctx context.Context, cb *controller.ContainerBox) (err error) {
	panic("implement me")
}

func (b *TcBoxy) RunWithContainer(ctx context.Context, cb *controller.ContainerBox) error {
	if cb.AssetStatus == common.AssetNew {
		err := b.RunWithPid(ctx, cb.Pid)
		if err != nil {
			return err
		}
	}
	// whatever ProgramType is, we set all containers to synced
	cb.AssetStatus = common.AssetSynced

	return nil
}

func (b *CgroupBoxy) RunWithContainer(ctx context.Context, cb *controller.ContainerBox) error {
	if cb.AssetStatus == common.AssetNew {
		err := b.RunWithPid(ctx, cb.Pid)
		if err != nil {
			return err
		}
	}
	// whatever ProgramType is, we set all containers to synced
	cb.AssetStatus = common.AssetSynced

	return nil
}
