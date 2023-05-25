package controller

import (
	"context"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/tools"
	"github.com/MaciekLeks/l7egg/pkg/user"
	"github.com/containerd/containerd"
	cnins "github.com/containernetworking/plugins/pkg/ns"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	"net"
	"os"
	"strings"
	"sync"
)

// PodInfo holds POD crucial metadata.
type PodInfo struct {
	//UID       string
	name          string
	namespace     string
	labels        map[string]string
	nodeName      string
	containerIDs  []string
	matchedKeyBox string
}

// PodInfoMap maps Pod namespace name to PodInfo
type PodInfoMap sync.Map

func (c *Controller) handlePodAdd(obj interface{}) {
	c.enqueuePod(obj)
}

func (c *Controller) handlePodDelete(obj interface{}) {
	c.enqueuePod(obj)
}

func (c *Controller) handlePodUpdate(prev interface{}, obj interface{}) {
	podPrev := prev.(*corev1.Pod)
	pod := obj.(*corev1.Pod)
	if podPrev.GetResourceVersion() != pod.GetResourceVersion() {
		//handle only update not sync event
		c.enqueuePod(obj)
	}
}

// enqueue pod takes a Pod resource and converts it into a namespace/name
// string which is then put onto the work queue. This method should *not* be
// passed resources of any type other than Foo.
func (c *Controller) enqueuePod(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.podQueue.Add(key)
}

// syncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Foo resource
// with the current status of the resource.
func (c *Controller) syncPodHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	namespace, name, err := splitNamespaceNameFormKey(key)
	if err != nil {
		return err
	}

	// Get pod with this namespace/name
	pod, err := c.podLister.Pods(namespace).Get(name)
	if err != nil {
		// processing.
		if apierrors.IsNotFound(err) {
			//utilruntime.HandleError(fmt.Errorf("clusteregg '%s' in work queue no longer exists", key))
			err = c.forgetPod(ctx, name) //TODO
			if err != nil {
				return fmt.Errorf("delete clusteregg '%s':%s failed", name, err)
			}
			return nil
		}
		return err
	}

	logger.Info("Update pod info.")
	err = c.updatePodInfo(ctx, pod) //TODO
	if err != nil {
		return fmt.Errorf("update clusteregg '%s':%s failed", name, err)
	}

	c.recorder.Event(pod, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)

	return nil
}

func getContainerdIDs(css []corev1.ContainerStatus) ([]string, error) {
	cids := make([]string, len(css))
	var err error
	const crn = "containerd://"
	for i := range css {
		//TODO check status of the container, e.g. status, is init container, ...
		if !strings.Contains(css[i].ContainerID, crn) {
			return cids, fmt.Errorf("only containerd supported")
		}
		cid := strings.TrimPrefix(css[i].ContainerID, crn)
		cids[i] = cid
	}
	return cids, err
}

func (c *Controller) updatePodInfo(ctx context.Context, pod *corev1.Pod) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "namespace", pod.Namespace, "name", pod.Name)
	logger.Info("Update pod info.")

	key := types.NamespacedName{pod.Namespace, pod.Name}
	if pi, ok := c.podInfoMap.Load(key); ok {
		fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!Update not add")

		boxKey, _ := c.checkEggMach(pod)
		if pi.matchedKeyBox != boxKey {
			if pi.matchedKeyBox != "" {
				if boxKey == "" {
					fmt.Println("-----Update Egg to remove to from the egg")
				} else {
					fmt.Println("-----Update Egg to be changed or only policy has changed")
				}
			} else {
				fmt.Println("-----Update: A new egg to be applied on the pod")
			}

		} else {
			fmt.Println("-----Update: Do nothing keyBox and pi.matchedKeyBox equals (-,-) or (x,x)")
		}

		containerdIDs, err := getContainerdIDs(pod.Status.ContainerStatuses)
		if err != nil {
			return err
		}

		c.podInfoMap.Store(key, PodInfo{
			name:          pod.Name,
			namespace:     pod.Namespace,
			labels:        pod.Labels,
			nodeName:      pod.Spec.NodeName,
			containerIDs:  containerdIDs,
			matchedKeyBox: boxKey,
		})

		tbd, _ := c.podInfoMap.Load(key) //test only
		fmt.Printf("!!!!!!!!!!!!!!Update Done: %+v\n", tbd)

	} else { //ADD
		boxKey, matched := c.checkEggMach(pod)
		if matched {
			fmt.Println("!!!!!!!!!Found key box matching new pod")
		}

		containerdIDs, err := getContainerdIDs(pod.Status.ContainerStatuses)
		if err != nil {
			return err
		}

		c.podInfoMap.Store(key, PodInfo{
			name:          pod.Name,
			namespace:     pod.Namespace,
			labels:        pod.Labels,
			nodeName:      pod.Spec.NodeName,
			containerIDs:  containerdIDs,
			matchedKeyBox: boxKey,
		})

		tbd, _ := c.podInfoMap.Load(key) //test only
		fmt.Printf("!!!!!!!!!!!!!!Add Done: %+v\n", tbd)

		if matched {
			hostname, err := tools.GetHostname()
			if err != nil {
				return err
			}
			fmt.Printf("\n!!!!!!!!!!!!!!{ hostname:%s, pod node:%s\n\n", hostname, pod.Spec.NodeName)
			if hostname == pod.Spec.NodeName {
				tbd.runEgg(ctx, boxKey)
			} else {

				fmt.Printf("\n!!!!!!!!!!!!!!{ not running in this node\n")
			}
			fmt.Println("!!!!!!!!!!!!!!}")

		}
	}

	return nil
}

func (c *Controller) forgetPod(ctx context.Context, key string) error {
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)
	logger.Info("Delete pod info.")
	return nil
}

//--

func (c *Controller) handleObject(obj interface{}) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}

	logger := klog.FromContext(context.Background())

	logger.Info("POD", "name", pod.Name, "namespace", pod.Namespace)
	for i := range pod.Status.ContainerStatuses {
		logger.Info("Container", "containerID", pod.Status.ContainerStatuses[i].ContainerID)
	}

	//Check if egg should be applied
	fmt.Println("+++++ before checking ")
	keyBox, ok := c.checkEggMach(pod)
	fmt.Println("+++++ after checking ", ok, keyBox)

}

// CheckAny searches for first matching between cegg PodSelector and the pod. Returns keyBox name
func (c *Controller) checkEggMach(pod *corev1.Pod) (string, bool) {
	var found bool
	var keyBox string

	manager := user.BpfManagerInstance()
	podLabels := labels.Set(pod.Labels)

	manager.BoxAny(func(key string, box user.IClientEggBox) bool {
		eggPodLabels := box.GetEgg().ClientEgg.PodLabels
		fmt.Println("+++++ eggPodLabels:", eggPodLabels)
		if len(eggPodLabels) > 0 {
			selector := labels.Set(eggPodLabels).AsSelectorPreValidated()
			fmt.Printf("\n\nSelector: %s; podLabels:%s\n\n", selector, podLabels)

			if selector.Matches(podLabels) {
				found = true
				keyBox = key
				return true
			}
		}
		return false
	})

	if !found {
		fmt.Println("+++++ found no matching pod to egg ")
	} else {

		fmt.Println("+++++ found matching pod to policy ")
	}

	return keyBox, found
}

func (pi *PodInfo) runEgg(ctx context.Context, boxKey string) {
	client, err := containerd.New("/var/snap/microk8s/common/run/containerd.sock", containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		fmt.Printf("Blad podczas tworzenia klienta containerd: %v", err)
		return
	}
	defer client.Close()

	// Ustaw nazwę przestrzeni nazw kontenera.
	//namespace := namespaces.Default

	// Pobierz kontener.
	container, err := client.LoadContainer(ctx, pi.containerIDs[0]) //TODO not only 0 ;)
	if err != nil {
		fmt.Printf("Błąd podczas ładowania kontenera: %v", err)
		return
	}

	// Pobierz informacje o procesie init kontenera.
	task, err := container.Task(ctx, nil)
	if err != nil {
		fmt.Printf("Błąd podczas pobierania informacji o zadaniu kontenera: %v", err)
		return
	}

	// Pobierz PID procesu init kontenera.
	pid := task.Pid()
	if err != nil {
		fmt.Printf("Błąd podczas pobierania PID procesu init: %v", err)
		return
	}

	// Wyświetl PID procesu init kontenera.
	fmt.Println("@@@@@@@@@@@ Container PID: %d", pid)

	path := fmt.Sprintf("/proc/%d/ns/net", pid)
	netns, err := cnins.GetNS(path)
	defer netns.Close()

	//{1
	//ns, err := nns.GetFromPath(path)
	//defer ns.Close()
	//fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ {{{{{{{{ currrns: %v", ns)
	//1}
	//nsid, err := tools.GetNsIDFromFD(netns.Fd())

	fmt.Printf("@@@@@@@@@@@ netns ID: %d", netns.Fd())

	netns.Do(func(_ns cnins.NetNS) error {
		ifaces, _ := net.Interfaces()

		fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ Interfaces: %v\n", ifaces)

		fmt.Println("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ {{{{{{{{ ns:", _ns.Path(), int(_ns.Fd()))

		//ns, err = nns.GetFromPath(_ns.Path())
		//defer ns.Close()
		//fmt.Printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ {{{{{{{{ currrns2: %v", ns)

		manager := user.BpfManagerInstance()
		//err = manager.BoxStart(ctx, boxKey, int(netns.Fd()))
		err = manager.BoxStart(ctx, boxKey, netns.Path())
		fmt.Println("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ }}}}}}}}")

		return nil
	})

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
	*/

	if err != nil {
		fmt.Println("Error listing interfaces:", err)
		os.Exit(1)
	}

}

//func (pim *PodInfoMap) Load(pod *corev1.Pod) (PodInfo, bool) {
//	var pi PodInfo
//	sm := (*sync.Map)(pim)
//	smv, ok := sm.Load(types.NamespacedName{pod.Namespace, pod.Name})
//	if !ok {
//		return pi, false
//	}
//	return smv.(PodInfo), true
//}
