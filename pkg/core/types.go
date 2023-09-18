package core

const (
	BpfIngressSection       = "tc"
	BpfEgressSection        = "classifier"
	BpfObjectFileName       = "l7egg.bpf.o"
	BpfTcIngressProgram     = "tc_ingress"
	BpfTcEgressProgram      = "tc_egress"
	BpfCgroupIngressProgram = "cgroup__skb_ingress"
	BpfCgroupEgressProgram  = "cgroup__skb_egress"
)
