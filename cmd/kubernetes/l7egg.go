package main

import (
	"context"
	"flag"
	"fmt"
	ceggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"log"
	"os"
	"path/filepath"
	"time"

	cegginformerfactory "github.com/MaciekLeks/l7egg/pkg/client/informers/externalversions"
	ceggcontroller "github.com/MaciekLeks/l7egg/pkg/controller"
)

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println("Not in cluster config")
		// fallback to kubeconfig
		var kubeconfig *string
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "kubeconfig absolute file path") //st
		} else {
			kubeconfig = flag.String("kubeconfig", "", "kubeconfig absolute file path") //stg
		}
		flag.Parse()
		if envvar := os.Getenv("KUBECONFIG"); len(envvar) > 0 {
			kubeconfig = &envvar
		}
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			log.Printf("The kubeconfig cannot be loaded: %v\n", err)
			os.Exit(1)
		}
	}

	ceggClientset, err := ceggclientset.NewForConfig(config)
	if err != nil {
		log.Printf("Getting client set %v\n", err)
	}

	fmt.Printf("eggclientset %v\n", ceggClientset)

	ceggs, err := ceggClientset.MaciekleksV1alpha1().ClusterEggs().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Geting clustereggs %v/n", err)
	}

	fmt.Printf("Length of clustereggs: %d\n", len(ceggs.Items))

	informerFactory := cegginformerfactory.NewSharedInformerFactory(ceggClientset, 10*time.Minute)
	c := ceggcontroller.NewController(ceggClientset, informerFactory.Maciekleks().V1alpha1().ClusterEggs())

	fmt.Printf("ceggController %v\n", c)

	stopper := make(chan struct{})
	defer close(stopper)

	informerFactory.Start(stopper)
	//if err := c.Run(); err != nil {
	//	log.Printf("Error running controller %v", err)
	//}
	c.Run(stopper)

}
