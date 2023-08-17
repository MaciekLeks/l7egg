package core

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/net"
	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/containerd/cgroups/v3/cgroup1"
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
	Install(context.Context) error
	// Upgrade modify Boxy internals, e.g. net namespaces, not business data
	Upgrade(context.Context, ...func(*BoxyOptions)) error
	// Reconcile reconfigure Boxy, e.g. ebpf programs data to reconcile it with a new state of the Egg
	Reconcile(context.Context) error
	// Do some actions on the Boxy based on temprorary options (these options are not updated in Boxy internals)
	DoAction(context.Context, ...func(actionOptions *BoxyOptions)) error
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

func NewBoxy(eggi *Eggy, options ...func(*BoxyOptions)) (Boxer, error) {
	// returns CgroupBoxy or TcBoxy based on Eggy.ProgramType

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
	fmt.Println("deep[Boxy:Stop][0]")
	b.stopFunc()
	fmt.Println("deep[Boxy:Stop][1]")
	b.waitGroup.Wait()
	fmt.Println("deep[Boxy:Stop][3]")
	return nil
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
	return nil
}

func (b *TcBoxy) Stop() error {
	_ = b.Boxy.Stop()
	return b.ebpfy.stopTcNetStack(b.netNsPath)
}

func (b *Boxy) Wait() {
	fmt.Println("deep[Boxy:Wait][0]")
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

func containerNetNsPath(pid uint32) string {
	fmt.Printf("deep[containerNetNsPath] pid: %d", pid)
	return fmt.Sprintf("/proc/%d/ns/net", pid)
}

func (b *CgroupBoxy) Install(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	var err error
	fmt.Println("deep[CgroupBoxy:Install][0]")

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
		fmt.Println("deep[CgroupBoxy:Install][2]", b.cgroupPath, b.netNsPath)
		return b.ebpfy.run(ctx, b.waitGroup, common.ProgramTypeCgroup, b.netNsPath, b.cgroupPath, b.options.pid)
	})
}

func (b *TcBoxy) Install(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	fmt.Println("TcBoxy:runBoxWithPid")

	logger.V(2).Info("runBoxWithPid: getting network space path")
	b.netNsPath = containerNetNsPath(b.options.pid)

	return b.start(ctx, func(ctx context.Context) error {
		return b.ebpfy.run(ctx, b.waitGroup, common.ProgramTypeTC, b.netNsPath, "", b.options.pid)
	})
}

func (b *CgroupNetClsBoxy) Install(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	fmt.Println("deep[CgroupNetClsBoxy:Install][0]")

	logger.V(2).Info("runBoxWithPid: getting network space path")
	b.netNsPath = containerNetNsPath(b.options.pid)

	fmt.Println("deep[CgroupNetClsBoxy:Install][1]", b.netNsPath, b.cgroupNetCls, b.options.pid)
	return b.ebpfy.runNetClsCgroupStack(b.netNsPath, b.cgroupNetCls, b.options.pid)
}

func (b *Boxy) Upgrade(ctx context.Context, options ...func(*BoxyOptions)) error {

	// modify the options
	for i := range options {
		options[i](&b.options)
	}

	// Reconcile the netNsPath to the container's net namespace path
	if b.options.pid != 0 {
		b.netNsPath = containerNetNsPath(b.options.pid)
	}
	return nil
}

func (b *Boxy) Reconcile(ctx context.Context) error {
	if err := b.ebpfy.updateCIDRs(); err != nil {
		return err
	}

	if err := b.ebpfy.updateCNs(); err != nil {
		return err
	}

	return nil
}

// Reconcile does nothing
func (b *CgroupNetClsBoxy) Reconcile(ctx context.Context) error {
	// We do nothing here
	return nil
}

// DoAction adds the pid to the net cls cgroup
func (b *CgroupNetClsBoxy) DoAction(ctx context.Context, actionOptions ...func(actionOptions *BoxyOptions)) error {

	actionOpts := BoxyOptions{}
	for i := range actionOptions {
		actionOptions[i](&actionOpts)
	}

	// we implement only one action
	if actionOpts.pid == 0 {
		return fmt.Errorf("pid is required")
	}

	logger := klog.FromContext(ctx)
	err := b.ebpfy.addPidToNetClsCgroup(b.cgroupNetCls, b.options.pid)
	if err != nil {
		return fmt.Errorf("failed to add pid to net cls cgroup: %v", err)
	}
	logger.V(2).Info("pid to net cls cgroup", "pid", actionOpts.pid)

	return nil
}

func (b *Boxy) DoAction(ctx context.Context, actionOptions ...func(actionOptions *BoxyOptions)) error {
	// No action to do
	return nil
}
