package main

import (
	"context"
	"flag"
	"fmt"
	eggclientset "github.com/MaciekLeks/l7egg/pkg/client/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"log"
	"os"
	"path/filepath"
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

	egs, err := eggclientset.NewForConfig(config)
	if err != nil {
		log.Printf("Getting client set %v\n", err)
	}

	fmt.Printf("eggclientset %v\n", egs)

	clustereggs, err := egs.MaciekleksV1alpha1().ClusterEggs().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Geting clustereggs %v/n", err)
	}

	fmt.Printf("Length of clustereggs: %d and names of the first one is %s\n", len(clustereggs.Items), clustereggs.Items[0].Name)

}
