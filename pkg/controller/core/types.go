package core

type assetStatus byte

const (
	assetSynced assetStatus = iota
	assetStale              //could be removed
	assetNew                //new to add to the ebpf map

	BpfIngressSection = "tc"
	BpfEgressSection  = "classifier"
	BpfObjectFileName = "l7egg.bpf.o"
	BpfIngressProgram = "tc_ingress"
	BpfEgressProgram  = "tc_egress"
)
