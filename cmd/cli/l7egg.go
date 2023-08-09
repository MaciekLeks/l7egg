package main

import (
	"flag"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/controller"
	"github.com/MaciekLeks/l7egg/pkg/core"
	"github.com/MaciekLeks/l7egg/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	clientegg, err := core.NewEggy(
		v1alpha1.ClusterEgg{
			TypeMeta: metav1.TypeMeta{},
			ObjectMeta: metav1.ObjectMeta{
				Name: "default",
			},
			Spec: v1alpha1.ClusterEggSpec{
				ProgramType: string(common.ProgramTypeTC),
				Egress: v1alpha1.EgressSpec{
					InterfaceName: *eface,
					CommonNames:   cnList,
					CIDRs:         cidrList,
					Shaping:       &v1alpha1.ShapingSpec{},
					PodSelector:   nil,
				},
				Ingress: v1alpha1.IngressSpec{
					InterfaceName: *iface,
				},
			},
		})

	ctx := utils.SetupSignalHandler()
	nodePod, err := controller.NewNodePody("fake-node")

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := nodePod.RunBoxySet(ctx, clientegg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	nodePod.WaitBoxes()
}
