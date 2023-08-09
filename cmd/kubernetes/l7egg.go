package main

import (
	"context"
	"flag"
	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	"github.com/MaciekLeks/l7egg/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"time"

	cegginformerfactory "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions"
	ceggcontroller "github.com/MaciekLeks/l7egg/pkg/controller"
)

var (
	masterURL  string
	kubeconfig string
)

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx := utils.SetupSignalHandler()
	logger := klog.FromContext(ctx)

	config, err := rest.InClusterConfig()
	if err != nil {
		logger.Info("Not in cluster config")
		// fallback to kubeconfig
		//var kubeconfig *string
		//if home := homedir.HomeDir(); home != "" {
		//	kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "kubeconfig absolute file path") //st
		//} else {
		//	kubeconfig = flag.String("kubeconfig", "", "kubeconfig absolute file path") //stg
		//}
		//flag.Parse()
		//if envvar := os.Getenv("KUBECONFIG"); len(envvar) > 0 {
		//	kubeconfig = &envvar
		//}
		config, err = clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
		if err != nil {
			//log.Printf("The kubeconfig cannot be loaded: %v\n", err)
			//os.Exit(1)
			logger.Error(err, "Error building kubeconfig")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	}
	kubeClientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error(err, "Error building kubernetes clientset.")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	ceggClientset, err := ceggclientset.NewForConfig(config)
	if err != nil {
		//log.Printf("Getting client set %v\n", err)
		logger.Error(err, "Error building kubernetes ceggClientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	logger.V(2).Info("eggclientset %v\n", ceggClientset)

	ceggs, err := ceggClientset.MaciekleksV1alpha1().ClusterEggs().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		//log.Printf("Geting clustereggs %v/n", err)
		logger.Error(err, "\"Geting clustereggs")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	logger.V(2).Info("Length of clustereggs", "len", len(ceggs.Items))

	ceggInformerFactory := cegginformerfactory.NewSharedInformerFactory(ceggClientset, 30*time.Second)
	kubeInformerFactory := informers.NewSharedInformerFactory(kubeClientset, 30*time.Second)
	c := ceggcontroller.NewController(ctx,
		kubeClientset,
		ceggClientset,
		ceggInformerFactory.Maciekleks().V1alpha1().ClusterEggs(),
		kubeInformerFactory.Core().V1().Pods())

	ceggInformerFactory.Start(ctx.Done())
	kubeInformerFactory.Start(ctx.Done())

	if err = c.Run(ctx, 1, 1); err != nil {
		logger.Error(err, "Error running controller.")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	c.Wait(ctx)
}
