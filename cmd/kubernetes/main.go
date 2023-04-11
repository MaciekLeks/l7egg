package main

import (
	"flag"
	"fmt"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"

	eggclient "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
)

func main() {
	config, err := rest.InClusterConfig()
	if err != nil {
		fmt.Println("Not in cluster config")
		// fallback to kubeconfig
		kubeconfig := flag.String("kubeconfig", "/home/mlk/.kube/config", "kubeconfig file") //stg
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

	eggclientset, err := eggclient.NewForConfig(config)
	if err != nil {
		log.Printf("Getting client set %v\n", err)
	}

	fmt.Printf("eggclientset %v", eggclientset)
}
