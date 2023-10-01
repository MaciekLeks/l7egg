package core

import (
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	bpf "github.com/aquasecurity/libbpfgo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"net"
	"regexp"
	"strconv"
	"sync"
)

const (
	IfaceDefault = "eth0"
)

type CidrWithProtoPort struct {
	//TODO ipv6 needed
	cidr   string
	id     uint16 //test
	pp     protoport
	lpmKey ILPMKey
}

func (c CidrWithProtoPort) String() string {
	// return cidr with id (siince ports we need compount key)
	return fmt.Sprintf("cidr:%s;pp:%s", c.cidr, c.pp)
}

type protocol uint8

const (
	ProtocolTCP  protocol = 6
	ProtocolUDP  protocol = 17
	ProtocolSCTP protocol = 132
)

type protoport struct {
	port  uint16
	proto protocol
}

func (p protoport) String() string {
	return fmt.Sprintf("port:%d:proto:%d", p.port, p.proto)
}

type CommonNameWithProtoPort struct {
	cn string
	id uint16
	pp protoport
}

func (c CommonNameWithProtoPort) String() string {
	return fmt.Sprintf("cn:%s;pp:%s", c.cn, c.pp)
}

type ShapingInfo struct {
	// Rate in bytes per second
	Rate uint32
	// Ceil in bytes per second
	Ceil uint32
}

type Eggy struct {
	sync.RWMutex
	Name             string
	ProgramType      common.ProgramType
	CommonNames      common.AssetList[CommonNameWithProtoPort]
	Cidrs            common.AssetList[CidrWithProtoPort]
	ProtoPorts       common.AssetList[protoport]
	IngressInterface string
	EgressInterface  string
	//BPFObjectPath    string
	PodLabels map[string]string
	Shaping   *ShapingInfo
	bpfModule *bpf.Module
}

func (ey *Eggy) Set(fn func(v *Eggy) error) error {
	ey.Lock()
	defer ey.Unlock()
	return fn(ey)
}

func (ey *Eggy) NamespaceName() types.NamespacedName {
	return types.NamespacedName{Namespace: "", Name: ey.Name}
}

// parseValueUnit parses input string and returns value and unit.
func parseValueUnit(input string, baseUnit string) (value uint32, unit string, err error) {
	regexpr := fmt.Sprintf(`(\d+)([m|k]%s)`, baseUnit)
	re := regexp.MustCompile(regexpr)
	matches := re.FindStringSubmatch(input)

	if len(matches) == 3 {
		var value64 uint64
		value64, err = strconv.ParseUint(matches[1], 10, 32)
		if err != nil {
			return
		}
		value = uint32(value64)
		unit = matches[2]
	} else {
		err = fmt.Errorf("unable to parse input string: %s and convert it to bps", input)
	}

	return
}

// parserBytes parses input bits value and unit and returns value in bytes.
// 1 bit = 0.125 byte
// 1mbit = ~125000 bytes = 1 * 0.125 * 1000 * 1000
func parseBytes(value uint32, unit string) (uint32, error) {
	fmt.Printf("(((((((((((((((((((((((((((((((((((( value: %d, unit: %s\n", value, unit)
	switch unit {
	case "mbit":
		return value * 125 * 1000, nil
	case "kbit":
		return value * 125 * 1000, nil
	case "bit":
		return value * 125, nil
	default:
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}
}

func parseAttribute(attrVal string, unitBase string) (retVal uint32, err error) {
	var unit string
	var val uint32
	if attrVal == "" {
		return
	}
	val, unit, err = parseValueUnit(attrVal, unitBase)
	if err != nil {
		return
	}
	retVal, err = parseBytes(val, unit)
	return
}

// parseShapingInfo parses input ShapingSpec and returns ShapingInfo using parseBytes for rates.
func parseShapingInfo(shaping *v1alpha1.ShapingSpec) (shapingInfo *ShapingInfo, err error) {
	shapingInfo = &ShapingInfo{}
	if shapingInfo.Rate, err = parseAttribute(shaping.Rate, "bit"); err != nil {
		return
	}
	if shapingInfo.Ceil, err = parseAttribute(shaping.Rate, "bit"); err != nil {
		return
	}

	return
}

func NewEggy(cegg v1alpha1.ClusterEgg) (*Eggy, error) {

	pps, err := parseProtoPorts(cegg.Spec.Egress.Ports)
	if err != nil {
		fmt.Errorf("parsing protocols and ports data %#v", err)
		return nil, err
	}

	cidrs, err := parseCIDRs(cegg.Spec.Egress.CIDRs, pps)
	if err != nil {
		fmt.Errorf("parsing input data %#v", err)
		return nil, err
	}

	cns, err := parseCNs(cegg.Spec.Egress.CommonNames, pps)
	if err != nil {
		fmt.Errorf("parsing input data %#v", err)
		return nil, err
	}

	var shapingInfo *ShapingInfo
	if cegg.Spec.Egress.Shaping != nil {
		shapingInfo, err = parseShapingInfo(cegg.Spec.Egress.Shaping)
		if err != nil {
			return nil, err
		}
	}

	var podLabels map[string]string
	if cegg.Spec.Egress.PodSelector.Size() != 0 {
		podLabels, err = metav1.LabelSelectorAsMap(cegg.Spec.Egress.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("bad label selector for cegg [%+v]: %w", cegg.Spec, err)
		}
	}

	iiface := cegg.Spec.Ingress.InterfaceName
	eiface := cegg.Spec.Egress.InterfaceName
	if len(podLabels) != 0 {
		iiface = "eth0"
		eiface = "eth0"
	}

	var ey = &Eggy{ //TODO make a function to wrap this up (parsing, building the object)
		Name:             cegg.Name,
		ProgramType:      common.ProgramType(cegg.Spec.ProgramType),
		IngressInterface: iiface,
		EgressInterface:  eiface,
		CommonNames:      cns,
		Cidrs:            cidrs,
		ProtoPorts:       pps,
		//BPFObjectPath:    "./l7egg.bpf.o",
		PodLabels: podLabels,
		Shaping:   shapingInfo,
	}
	return ey, nil
}

// parseProtoPorts parses input ports and returns protoport list.
func parseProtoPorts(ports []v1alpha1.PortSpec) (common.AssetList[protoport], error) {
	var retPorts common.AssetList[protoport]
	for _, port := range ports {
		switch port.Protocol {
		case corev1.ProtocolTCP:
			retPorts.Add(&protoport{port.Port, ProtocolTCP})
		case corev1.ProtocolUDP:
			retPorts.Add(&protoport{port.Port, ProtocolUDP})
		case corev1.ProtocolSCTP:
			retPorts.Add(&protoport{port.Port, ProtocolSCTP})
		}
	}
	if len(retPorts) == 0 {
		retPorts.Add(&protoport{0, 0})
	}
	return retPorts, nil
}

func (ey *Eggy) UpdateSpec(ney *Eggy) error {
	ey.Lock()
	defer ey.Unlock()

	ey.ProtoPorts.Update(ney.ProtoPorts)
	ey.CommonNames.Update(ney.CommonNames)
	ey.Cidrs.Update(ney.Cidrs)
	ey.PodLabels = ney.PodLabels

	return nil
}

func (ey *Eggy) UpdateDone() {
	ey.Lock()
	defer ey.Unlock()

	ey.ProtoPorts.RemoveStale()
	ey.ProtoPorts.SetStatus(common.AssetSynced)

	ey.Cidrs.RemoveStale()
	ey.Cidrs.SetStatus(common.AssetSynced)

	ey.CommonNames.RemoveStale()
	ey.CommonNames.SetStatus(common.AssetSynced)
}

// Stop stops and destroys any external resource
func (ey *Eggy) Stop() {
	ey.Lock()
	defer ey.Unlock()

	if ey.bpfModule != nil {
		ey.bpfModule.Close()
		ey.bpfModule = nil //we
	} // need to set it to nil
}

func parseCIDR(cidrS string, pps common.AssetList[protoport]) ([]CidrWithProtoPort, error) {
	ip, ipNet, err := net.ParseCIDR(cidrS)
	if err != nil {
		return nil, fmt.Errorf("can't parse CidrWithProtoPort %s", cidrS)
	}
	prefix, _ := ipNet.Mask.Size()
	retCidrs := make([]CidrWithProtoPort, len(pps))

	//iterate over pps and create lpmKey for each port, or add port 0 if pps is empty
	for i, pp := range pps {

		if ipv4 := ip.To4(); ipv4 != nil {
			retCidrs[i] = CidrWithProtoPort{cidrS, syncx.Sequencer().Next(), *pp.Value, ipv4LPMKey{uint32(prefix), pp.Value.port, uint8(pp.Value.proto), [4]uint8(ipv4)}}
		} else if ipv6 := ip.To16(); ipv6 != nil {
			retCidrs[i] = CidrWithProtoPort{cidrS, syncx.Sequencer().Next(), *pp.Value, ipv6LPMKey{uint32(prefix), pp.Value.port, uint8(pp.Value.proto), [16]uint8(ipv6)}}
		}
	}

	return retCidrs, nil
}

// ParseCIDRs TODO: only ipv4
func parseCIDRs(cidrsS []string, ports common.AssetList[protoport]) (common.AssetList[CidrWithProtoPort], error) {
	var cidrs common.AssetList[CidrWithProtoPort]
	for _, cidrS := range cidrsS {
		cidrPps, err := parseCIDR(cidrS, ports)
		if err != nil {
			return cidrs, err
		}
		for i := range cidrPps {
			_ = cidrs.Add(&cidrPps[i])
		}
	}

	return cidrs, nil
}

// ParseCN returns CommonNameWithProtoPort object from string
func parseCN(cnS string, pps common.AssetList[protoport]) ([]CommonNameWithProtoPort, error) {
	retCns := make([]CommonNameWithProtoPort, len(pps))

	for i, pp := range pps {
		retCns[i] = CommonNameWithProtoPort{cnS, syncx.Sequencer().Next(), *pp.Value}
	}
	return retCns, nil
}

func parseCNs(cnsS []string, pps common.AssetList[protoport]) (common.AssetList[CommonNameWithProtoPort], error) {
	var cns common.AssetList[CommonNameWithProtoPort]
	for _, cnS := range cnsS {
		cnPps, err := parseCN(cnS, pps)
		if err != nil {
			return cns, err
		}
		for i := range cnPps {
			_ = cns.Add(&cnPps[i])
		}
	}

	return cns, nil
}
