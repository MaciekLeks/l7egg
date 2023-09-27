package core

import (
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/common"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	bpf "github.com/aquasecurity/libbpfgo"
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

type Cidr struct {
	//TODO ipv6 needed
	cidr   string
	id     uint16 //test
	lpmKey ILPMKey
}

func (c Cidr) String() string {
	return c.cidr
}

type CommonName struct {
	cn string
	id uint16 //test
}

func (c CommonName) String() string {
	return c.cn
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
	CommonNames      common.AssetList[CommonName]
	Cidrs            common.AssetList[Cidr]
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
	cidrs, err := parseCIDRs(cegg.Spec.Egress.CIDRs)
	if err != nil {
		fmt.Errorf("Parsing input data %#v", err)
		return nil, err
	}

	cns, err := parseCNs(cegg.Spec.Egress.CommonNames)
	if err != nil {
		fmt.Errorf("Parsing input data %#v", err)
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
		//BPFObjectPath:    "./l7egg.bpf.o",
		PodLabels: podLabels,
		Shaping:   shapingInfo,
	}
	return ey, nil
}

func (ey *Eggy) UpdateSpec(ney *Eggy) error {
	ey.Lock()
	defer ey.Unlock()

	ey.CommonNames.Update(ney.CommonNames)
	ey.Cidrs.Update(ney.Cidrs)
	ey.PodLabels = ney.PodLabels

	return nil
}

func (ey *Eggy) UpdateDone() {
	ey.Lock()
	defer ey.Unlock()

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

func parseCIDR(cidrS string) (Cidr, error) {
	ip, ipNet, err := net.ParseCIDR(cidrS)
	must(err, "Can't parse ipv4 Net.")
	if err != nil {
		return Cidr{}, fmt.Errorf("can't parse Cidr %s", cidrS)
	}

	fmt.Println("#### parseCID ", ip, " ipNEt", ipNet)

	prefix, _ := ipNet.Mask.Size()
	if ipv4 := ip.To4(); ipv4 != nil {
		return Cidr{cidrS, syncx.Sequencer().Next(), ipv4LPMKey{uint32(prefix), 443, [4]uint8(ipv4)}}, nil
	} else if ipv6 := ip.To16(); ipv6 != nil {
		return Cidr{cidrS, syncx.Sequencer().Next(), ipv6LPMKey{uint32(prefix), 443, [16]uint8(ipv6)}}, nil
	}

	return Cidr{}, fmt.Errorf("can't converts Cidr to IPv4/IPv6 %s", cidrS)
}

// ParseCIDRs TODO: only ipv4
func parseCIDRs(cidrsS []string) (common.AssetList[Cidr], error) {
	var cidrs common.AssetList[Cidr]
	for _, cidrS := range cidrsS {
		cidr, err := parseCIDR(cidrS)
		if err != nil {
			return cidrs, err
		}
		_ = cidrs.Add(&cidr)
	}

	return cidrs, nil
}

// ParseCN returns CommonName object from string
func parseCN(cnS string) (CommonName, error) {
	//TODO add some validation before returning CommonName
	//we are sync - due to we do not have to update kernel side
	//we can use simple Id generator

	return CommonName{cnS, syncx.Sequencer().Next()}, nil
}

func parseCNs(cnsS []string) (common.AssetList[CommonName], error) {
	var cns common.AssetList[CommonName]
	for _, cnS := range cnsS {
		cn, err := parseCN(cnS)
		if err != nil {
			return cns, err
		}
		_ = cns.Add(&cn)
	}

	return cns, nil
}
