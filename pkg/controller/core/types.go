package core

const (
	BpfIngressSection = "tc"
	BpfEgressSection  = "classifier"
	BpfObjectFileName = "l7egg.bpf.o"
	BpfIngressProgram = "tc_ingress"
	BpfEgressProgram  = "tc_egress"
)
