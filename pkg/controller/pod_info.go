package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/controller/core"
	"github.com/containerd/containerd"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	"sync"
)

// PodInfo holds POD crucial metadata.
type PodInfo struct {
	sync.RWMutex
	//UID       string
	name          string
	namespace     string
	labels        map[string]string
	nodeName      string
	containerIDs  []string
	matchedKeyBox core.BoxKey
}

// set sets in a safe manner PodInfo fields.
func (pi *PodInfo) set(fn func(v *PodInfo)) {
	pi.Lock()
	defer pi.Unlock()
	fn(pi)
}

func (pi *PodInfo) runEgg(ctx context.Context, boxKey core.BoxKey) error {
	logger := klog.FromContext(ctx)
	fmt.Printf("**********************runEgg-0:\n")

	logger.V(2).Info("runEgg-1")
	client, err := containerd.New("/var/snap/microk8s/common/run/containerd.sock", containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		return fmt.Errorf("Can't connect to containerd socket", err)
	}
	defer client.Close()

	fmt.Printf("**********************runEgg-1:\n")
	logger.V(2).Info("runEgg-2")
	// Ustaw nazwę przestrzeni nazw kontenera.
	//namespace := namespaces.Default

	fmt.Printf("**********************runEgg-2:\n")
	// Pobierz kontener.
	//fmt.Printf("///////////////:)1")
	container, err := client.LoadContainer(ctx, pi.containerIDs[0]) //TODO not only 0 ;)
	//fmt.Printf("///////////////:)2")
	if err != nil {
		return fmt.Errorf("Can't load container", err)
	}

	fmt.Printf("**********************runEgg-3:\n")
	logger.V(2).Info("runEgg-3")
	// Pobierz informacje o procesie init kontenera.
	task, err := container.Task(ctx, nil)
	if err != nil {
		return fmt.Errorf("Can't get container task", err)
	}

	fmt.Printf("**********************runEgg-4:\n")
	logger.V(2).Info("runEgg-4")
	// Pobierz PID procesu init kontenera.
	pid := task.Pid()
	if err != nil {
		return fmt.Errorf("Can't get container task PID", err)
	}

	fmt.Printf("**********************runEgg-5:\n")
	logger.V(2).Info("runEgg-5")
	// attaching
	manager := core.BpfManagerInstance()
	box, ok := manager.Boxes.Load(boxKey)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("Box %s not found", boxKey))
		return fmt.Errorf("Box %s not found", boxKey)
	}
	fmt.Printf("**********************runEgg-6:\n")
	logger.V(2).Info("runEgg-6")
	var cgroupPath string

	if box.Egg().ProgramType == common.ProgramTypeCgroup {
		logger.V(2).Info("runEgg-7-cgroup")
		cgroupPath, err = getContainerdCgroupPath(pid) //cgroup over tc programs
		if err != nil {
			return fmt.Errorf("cgroup path error: %v", err)
		}
		fmt.Printf("**********************runEgg-8-cgroup:\n")
		logger.V(2).Info("runEgg-8 - cgroup!!!")
		netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid) //needed by cgroup tc filters
		err = manager.BoxStart(ctx, boxKey, netNsPath, cgroupPath, pid)
	} else {
		//cgroupPath, err = "", nil //tc only}
		//path := fmt.Sprintf("/proc/%d/ns/net", pid)
		//var netns cnins.NetNS
		//netns, err = cnins.GetNS(path)
		//defer netns.Close()
		//
		//fmt.Printf("**********************runEgg-7-tc: %+v netns.Path:%s  path:%s\n", netns, netns.Path(), path)
		//logger.V(2).Info("runEgg-7-tc")
		//if err != nil {
		//	fmt.Printf("**********************runEgg-7.0-tc: %s\n", err)
		//	return fmt.Errorf("failed to get netns: %v", err)
		//}
		//
		//fmt.Printf("**********************runEgg-7.1-tc:\n")
		//err = netns.Do(func(_ns cnins.NetNS) error {
		//	fmt.Printf("**********************runEgg-8-tc:\n")
		//	logger.V(2).Info("runEgg-8 - tc!!!")
		//	netns.Fd()
		//	err := manager.BoxStart(ctx, boxKey, netns.Path(), cgroupPath)
		//	fmt.Printf("**********************runEgg-8.1-tc:\n")
		//	return err
		//})
		//fmt.Printf("**********************runEgg-7.2-tc:\n")

		cgroupPath, err = "", nil //tc only}
		netNsPath := fmt.Sprintf("/proc/%d/ns/net", pid)

		fmt.Printf("**********************runEgg-7.1-tc:\n")
		err = manager.BoxStart(ctx, boxKey, netNsPath, cgroupPath)
	}

	/*{containerd/pkg/ns
	ns := netns.LoadNetNS(path)
	defer ns.Remove() //TOOD Remove?


	// Listuj interfejsy sieciowe w tej przestrzeni sieciowej
	err = ns.Do(func(_ns cnins.NetNS) error {
		ifaces, _ := net.Interfaces()

		fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Interfaces: %v\n", ifaces)

		fmt.Println("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ {{{{{{{{ ns:", ns.GetPath())
		manager := user.BpfManagerInstance()
		err = manager.BoxStart(ctx, boxKey, int(netns.Fd())
		fmt.Println("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ }}}}}}}}")

		return nil
	})
	}
	logger.V(2).Info("runEgg-9")

	if err != nil {
		fmt.Println("Error listing interfaces:", err)
		os.Exit(1)
	}

	*/
	return err
}

func (pi *PodInfo) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: pi.namespace, Name: pi.name}
}
