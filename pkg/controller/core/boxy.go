package core

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/net"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/containerd/cgroups/v3/cgroup1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sync"
)

type BoxyOptions struct {
	//Pid uint32
	//NetClsCgroup *cgroup1.Cgroup
	useNetCls bool
	pid       uint32
}

type Boxy struct {
	stopFunc  context.CancelFunc
	waitGroup *sync.WaitGroup //TODO: only ene goroutine (in run(...)) - changing to channel?
	ebpfy     *ebpfy
	//programInfo common.ProgramInfo
	netNsPath string
	options   BoxyOptions
}

func WithNetCls() func(*BoxyOptions) {
	return func(b *BoxyOptions) {
		b.useNetCls = true
	}
}

func WithPid(pid uint32) func(*BoxyOptions) {
	return func(b *BoxyOptions) {
		b.pid = pid
	}
}

func (b *Boxy) RunBoxWithPid(ctx context.Context, pid uint32) error {
	//TODO implement me
	panic("implement me")
}

type Boxer interface {
	Stop() error
	Wait()
	//RunWithContainer(ctx context.Context, cb *controller.ContainerBox) error
	Run(ctx context.Context) error
	UpdateRunning(ctx context.Context) error
	EggNamespaceName() types.NamespacedName
}

type TcBoxy struct {
	*Boxy
}

type CgroupBoxy struct {
	*Boxy
	cgroupPath string
	//cgroupNetCls *cgroup1.Cgroup //references to ebpfy cgroup net_cls for cgroup programs
}

type CgroupNetClsBoxy struct {
	*Boxy
	cgroupNetCls cgroup1.Cgroup //cgroup net_cls for cgroup programs
}

func NewBoxy(eggi *EggInfo, options ...func(*BoxyOptions)) (Boxer, error) {
	// returns CgroupBoxy or TcBoxy based on EggInfo.ProgramType

	opts := BoxyOptions{}
	for i := range options {
		options[i](&opts)
	}

	if opts.pid == 0 {
		return nil, fmt.Errorf("pid cannot be 0")
	}

	boxy := &Boxy{
		ebpfy:     newEbpfy(eggi),
		options:   opts,
		waitGroup: &sync.WaitGroup{},
	}

	switch eggi.ProgramType {
	case common.ProgramTypeTC:
		return newTcBoxy(boxy), nil
	case common.ProgramTypeCgroup:
		if opts.useNetCls {
			fmt.Println("deep[NewBoxy->newCgroupNetClsBoxy][0]", opts.useNetCls)
			return newCgroupNetClsBoxy(boxy)
		} else {
			fmt.Println("deep[NewBoxy->newCgroupBoxy][0]", opts.useNetCls)
			return newCgroupBoxy(boxy), nil
		}
	default:
		klog.Fatalf("unknown program type: %s", eggi.ProgramType)
	}

	return nil, nil
}

func newTcBoxy(boxy *Boxy) *TcBoxy {
	return &TcBoxy{
		Boxy: boxy,
	}
}

func newCgroupBoxy(boxy *Boxy) *CgroupBoxy {
	return &CgroupBoxy{
		Boxy: boxy,
	}
}

func newCgroupNetClsBoxy(boxy *Boxy) (*CgroupNetClsBoxy, error) {
	var b *CgroupNetClsBoxy
	cgroupNetCls, err := net.CreateCgroupNetCls(net.CgroupFsName, net.TcHandleHtbClass) //TODO classid: 10:10 always?
	if err != nil {
		return b, fmt.Errorf("failed to create cgroup net_cls: %v", err)
	}
	return &CgroupNetClsBoxy{
		Boxy:         boxy,
		cgroupNetCls: cgroupNetCls,
	}, nil
}

func (b *Boxy) Stop() error {
	b.stopFunc()
	b.waitGroup.Wait()
	return nil
}

func (b *Boxy) EggNamespaceName() types.NamespacedName {
	return b.ebpfy.EggInfo.NamespaceName()
}

func (b *CgroupBoxy) Stop() error {
	//_ = b.cgroupNetCls.Delete() //ebpfy should Delete net class cgroup
	return b.Stop()
}

func (b *Boxy) Wait() {
	b.waitGroup.Wait()
}

func (b *Boxy) start(ctx context.Context, fn func(ctx context.Context) error) error {
	fmt.Println("deep[Boxy:start][0]")
	ctxWithCancel, cancelFunc := context.WithCancel(ctx)
	fmt.Println("deep[Boxy:start][1]")
	b.stopFunc = cancelFunc
	b.waitGroup.Add(1)
	fmt.Println("deep[Boxy:start][3]")
	var err error
	go func() {
		defer b.waitGroup.Done()
		fmt.Println("deep[Boxy:start][4]")
		err = fn(ctxWithCancel)
	}()

	return err
}

func containerdCgroupPath(pid uint32) (string, error) {
	return cgroupsv2.PidGroupPath(int(pid))
}

func (b *CgroupBoxy) Run(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	var err error
	fmt.Println("deep[CgroupBoxy:Run][0]")

	var cgroupPath string
	logger.V(2).Info("runBoxWithPid: getting network space path")
	netNsPath := fmt.Sprintf("/proc/%d/ns/net", b.options.pid)

	logger.V(2).Info("runBoxWithPid: getting cgroup path")
	cgroupPath, err = containerdCgroupPath(b.options.pid)
	if err != nil {
		return fmt.Errorf("cgroup path error: %v", err)
	}

	b.cgroupPath = cgroupPath
	b.netNsPath = netNsPath

	return b.start(ctx, func(ctx context.Context) error {
		fmt.Println("deep[CgroupBoxy:Run][2]", b.cgroupPath, b.netNsPath)
		return b.ebpfy.run(ctx, b.waitGroup, common.ProgramTypeCgroup, b.netNsPath, b.cgroupPath, b.options.pid)
	})
}

func (b *TcBoxy) Run(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	fmt.Println("TcBoxy:runBoxWithPid")

	logger.V(2).Info("runBoxWithPid: getting network space path")
	netNsPath := fmt.Sprintf("/proc/%d/ns/net", b.options.pid)
	b.netNsPath = netNsPath

	return b.start(ctx, func(ctx context.Context) error {
		return b.ebpfy.run(ctx, b.waitGroup, common.ProgramTypeTC, netNsPath, "", b.options.pid)
	})
}

func (b *CgroupNetClsBoxy) Run(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	fmt.Println("deep[CgroupNetClsBoxy:Run][0]")

	logger.V(2).Info("runBoxWithPid: getting network space path")
	netNsPath := fmt.Sprintf("/proc/%d/ns/net", b.options.pid)
	b.netNsPath = netNsPath

	fmt.Println("deep[CgroupNetClsBoxy:Run][1]", netNsPath, b.cgroupNetCls, b.options.pid)
	return b.ebpfy.runNetClsCgroupStack(netNsPath, b.cgroupNetCls, b.options.pid)
}

func (b *CgroupNetClsBoxy) UpdateRunning(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	fmt.Println("deep[CgroupNetClsBoxy:UpdateRunning][0]")

	logger.V(2).Info("container process pid added to net_cls cgroup")
	return b.ebpfy.AddPidToNetClsCgroup(b.cgroupNetCls, b.options.pid)

}

func (b *CgroupNetClsBoxy) Stop() error {
	err := b.ebpfy.stopNetClsCgroupStack(b.netNsPath)
	if err != nil {
		return err
	}
	err = b.cgroupNetCls.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete net cls cgroup: %v", err)
	}
	return b.Boxy.Stop()
}

func (b *Boxy) UpdateRunning(ctx context.Context) error {
	if err := b.ebpfy.updateCIDRs(b.ebpfy.EggInfo.CIDRs); err != nil {
		return err
	}

	if err := b.ebpfy.updateCNs(b.ebpfy.EggInfo.CNs); err != nil {
		return err
	}

	return nil
}
