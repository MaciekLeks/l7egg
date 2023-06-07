package main

import (
	"flag"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller"
	"github.com/MaciekLeks/l7egg/pkg/tools"
	"k8s.io/apimachinery/pkg/types"
	"os"
)

type argList []string

func (i *argList) String() string {
	return fmt.Sprint(*i)
}

func (i *argList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	var cnList argList
	var cidrList argList
	iface := flag.String("iface", "", "Ingress interface to bind TC program to.")
	eface := flag.String("eface", "", "Egress interface to bind TC program to.")
	//bpfObjectPath := flag.String("bpfobj", "l7egg.bpf.o", "Kernel module file path to load.")
	flag.Var(&cidrList, "cidr", "Add net address (CIDR format) to add to the white list.")
	flag.Var(&cnList, "cn", "Add Common Name to add to the white list.")
	flag.Parse()
	if *iface == "" || *eface == "" {
		fmt.Println("-iface and -eface are required.\n-cidr and -cn are optional.")
		return
	}

	manager := controller.BpfManagerInstance()
	clientegg, err := manager.NewEggInfo(*iface, *eface, cnList, cidrList, nil)

	var defaultBoxKey controller.BoxKey
	defaultBoxKey.Egg = types.NamespacedName{Name: "default"}
	manager.BoxStore(defaultBoxKey, clientegg)

	if err != nil {
		fmt.Errorf("Creating client egg.", err)
		os.Exit(1)
	}
	ctx := tools.SetupSignalHandler()

	manager.BoxStart(ctx, defaultBoxKey, "", "")
	manager.Wait()

}
