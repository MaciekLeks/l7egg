package main

import (
	"flag"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/user"
	"os"
	"os/signal"
	"sync"
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
	var cns argList
	var cidrs argList
	iface := flag.String("iface", "", "Ingress interface to bind TC program to.")
	eface := flag.String("eface", "", "Egress interface to bind TC program to.")
	bpfObjectPath := flag.String("bpfobj", "l7egg.bpf.o", "Kernel module file path to load.")
	flag.Var(&cidrs, "cidr", "Add net address (CIDR format) to add to the white list.")
	flag.Var(&cns, "cn", "Add Common Name to add to the white list.")
	flag.Parse()
	if *iface == "" || *eface == "" {
		fmt.Println("-iface and -eface are required.\n-cidr and -cn are optional.")
		return
	}

	clientegg := user.ClientEgg{
		IngressInterface: *iface,
		EgressInterface:  *eface,
		CNs:              cns,
		CIDRs:            cidrs,
		BPFObjectPath:    *bpfObjectPath,
	}

	done := make(chan struct{})
	sig := make(chan os.Signal, 0)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-sig
		close(done)
	}()

	var wg sync.WaitGroup
	clientegg.Run(&wg, done)
	wg.Wait()
}
