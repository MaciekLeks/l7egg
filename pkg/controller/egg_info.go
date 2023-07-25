package controller

import (
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/apis/maciekleks.dev/v1alpha1"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net"
	"regexp"
	"strconv"
	"sync"
)

const (
	IfaceDefault = "eth0"
)

type CIDR struct {
	//TODO ipv6 needed
	cidr   string
	id     uint16 //test
	lpmKey ILPMKey
	status assetStatus
}

type CN struct {
	cn     string
	id     uint16 //test
	status assetStatus
}

type ShapingInfo struct {
	// Rate in bits per second
	Rate uint32
}

type EggInfo struct {
	sync.RWMutex
	programType      ProgramType
	CNs              *syncx.SafeSlice[CN]
	CIDRs            *syncx.SafeSlice[CIDR]
	IngressInterface string
	EgressInterface  string
	BPFObjectPath    string
	PodLabels        map[string]string
	Shaping          ShapingInfo
}

func (eggi *EggInfo) set(fn func(v *EggInfo) error) error {
	eggi.Lock()
	defer eggi.Unlock()
	return fn(eggi)
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

// parserBytes parses input value and unit and returns value in bytes.
func parseBytes(value uint32, unit string) (uint32, error) {
	switch unit {
	case "mbps":
		return value * 1024 * 1024, nil
	case "kbps":
		return value * 1024, nil
	case "bps":
		return value, nil
	default:
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}
}

// ParseShapingInfo parses input ShapingSpec and returns ShapingInfo using parseBytes for rates.
func ParseShapingInfo(shaping v1alpha1.ShapingSpec) (ShapingInfo, error) {
	var shapingInfo ShapingInfo
	if shaping.Rate != "" {
		value, unit, err := parseValueUnit(shaping.Rate, "bps")
		if err != nil {
			return shapingInfo, err
		}
		shapingInfo.Rate, err = parseBytes(value, unit)
		if err != nil {
			return shapingInfo, err
		}
	}

	return shapingInfo, nil
}

func NewEggInfo(ceggSpec v1alpha1.ClusterEggSpec) (*EggInfo, error) {
	cidrs, err := parseCIDRs(ceggSpec.Egress.CIDRs)
	if err != nil {
		fmt.Errorf("Parsing input data %#v", err)
		return nil, err
	}

	cns, err := parseCNs(ceggSpec.Egress.CommonNames)
	if err != nil {
		fmt.Errorf("Parsing input data %#v", err)
		return nil, err
	}
	safeCNs := syncx.SafeSlice[CN]{}
	safeCNs.Append(cns...)

	safeCIDRs := syncx.SafeSlice[CIDR]{}
	safeCIDRs.Append(cidrs...)

	fmt.Printf("((((((((((((((((((((((((((((((((((((((((((((((", ceggSpec.Egress.Shaping)
	shapingInfo, err := ParseShapingInfo(ceggSpec.Egress.Shaping)
	if err != nil {
		return nil, err
	}
	fmt.Printf("))))))))))))))))))))))))))))))))))))))))))))))), ", shapingInfo)

	var podLabels map[string]string
	if ceggSpec.Egress.PodSelector.Size() != 0 {
		podLabels, err = metav1.LabelSelectorAsMap(ceggSpec.Egress.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("bad label selector for cegg [%+v]: %w", ceggSpec, err)
		}
	}

	iiface := ceggSpec.Ingress.InterfaceName
	eiface := ceggSpec.Egress.InterfaceName
	if len(podLabels) != 0 {
		iiface = "eth0"
		eiface = "eth0"
	}

	var cggi = &EggInfo{ //TODO make a function to wrap this up (parsing, building the object)
		programType:      ProgramType(ceggSpec.ProgramType),
		IngressInterface: iiface,
		EgressInterface:  eiface,
		CNs:              &safeCNs,
		CIDRs:            &safeCIDRs,
		BPFObjectPath:    "./l7egg.bpf.o",
		PodLabels:        podLabels,
		Shaping:          shapingInfo,
	}
	return cggi, nil
}

func parseCIDR(cidrS string) (CIDR, error) {
	ip, ipNet, err := net.ParseCIDR(cidrS)
	must(err, "Can't parse ipv4 Net.")
	if err != nil {
		return CIDR{}, fmt.Errorf("can't parse CIDR %s", cidrS)
	}

	fmt.Println("#### parseCID ", ip, " ipNEt", ipNet)

	prefix, _ := ipNet.Mask.Size()
	if ipv4 := ip.To4(); ipv4 != nil {
		return CIDR{cidrS, syncx.Sequencer().Next(), ipv4LPMKey{uint32(prefix), [4]uint8(ipv4)}, assetNew}, nil
	} else if ipv6 := ip.To16(); ipv6 != nil {
		return CIDR{cidrS, syncx.Sequencer().Next(), ipv6LPMKey{uint32(prefix), [16]uint8(ipv6)}, assetNew}, nil
	}

	return CIDR{}, fmt.Errorf("can't converts CIDR to IPv4/IPv6 %s", cidrS)
}

// ParseCIDRs TODO: only ipv4
func parseCIDRs(cidrsS []string) ([]CIDR, error) {
	var cidrs []CIDR
	for _, cidrS := range cidrsS {
		cidr, err := parseCIDR(cidrS)
		if err != nil {
			return nil, err
		}
		cidrs = append(cidrs, cidr)
	}

	return cidrs, nil
}

// ParseCN returns CN object from string
func parseCN(cnS string) (CN, error) {
	//TODO add some validation before returning CN
	//we are sync - due to we do not have to update kernel side
	//we can use simple id generator

	return CN{cnS, syncx.Sequencer().Next(), assetNew}, nil
}

func parseCNs(cnsS []string) ([]CN, error) {
	var cns []CN
	for _, cnS := range cnsS {
		cn, err := parseCN(cnS)
		if err != nil {
			return nil, err
		}
		cns = append(cns, cn)
	}

	return cns, nil
}
