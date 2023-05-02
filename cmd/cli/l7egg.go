package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/user"
	"os"
	"os/signal"
	"syscall"
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

	manager := user.BpfManagerInstance()
	clientegg, err := manager.NewClientEgg(*iface, *eface, cnList, cidrList)

	if err != nil {
		fmt.Errorf("Creating client egg.", err)
		os.Exit(1)
	}

	rootCtx := context.Background()
	ctx, cancelFunc := context.WithCancel(rootCtx)
	sig := make(chan os.Signal, 0)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-sig
		cancelFunc()
	}()

	manager.Start(ctx, "default", clientegg)
	manager.Wait()

}
