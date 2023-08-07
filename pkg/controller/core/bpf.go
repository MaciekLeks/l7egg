package core

/*
   #include <time.h>
   static unsigned long long get_nsecs(void)
   {
       struct timespec ts;
       clock_gettime(CLOCK_MONOTONIC, &ts);
       return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
   }
*/
import "C"
import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/MaciekLeks/l7egg/pkg/controller/common"
	"github.com/MaciekLeks/l7egg/pkg/net"
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"k8s.io/klog/v2"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// ebpfy holds EggInfo (extracted from ClusterEggSpec) and ebpf related structures, e.g. maps, channels operating on that maps
type ebpfy struct {
	// Depreciated: should all part of ebpfy struct
	EggInfo   *EggInfo //TOOD remove from here
	bpfModule *bpf.Module
	ipv4ACL   *bpf.BPFMap
	ipv6ACL   *bpf.BPFMap
	packets   chan []byte
	//cgroupNetCls cgroup1.Cgroup //cgroup net_cls for cgroup programs
	//aclLoock  sync.RWMutex
}

func newEbpfy(eggi *EggInfo) *ebpfy {
	var egg ebpfy
	egg.EggInfo = eggi
	return &egg
}

// run runs the ebpfy, and if neither nsNetPath nor cgroupPath is Set, it will run the ebpfy in the current network netspace (tc over cgroup
func (ey *ebpfy) run(ctx context.Context, wg *sync.WaitGroup, programType common.ProgramType, netNsPath string, cgroupPath string, pid uint32) error {
	var err error

	ey.bpfModule, err = bpf.NewModuleFromFile(BpfObjectFileName)
	if err != nil {
		return err
	}

	err = ey.bpfModule.BPFLoadObject()
	if err != nil {
		return err
	}

	logger := klog.FromContext(ctx)

	logger.Info("Attaching eBPF program having", programType)
	if /*len(cgroupPath) == 0*/ programType == common.ProgramTypeTC {
		time.Sleep(4 * time.Second)

		//err = attachTcProg(ebpfy.bpfModule, ebpfy.EggInfo.IngressInterface, bpf.BPFTcIngress, "tc_ingress")
		err = attachTcBpfIngressStack(ey.bpfModule, ey.EggInfo.EgressInterface, netNsPath)
		must(err, "Can't attach TC hook.")
		//err = attachTcProg(ebpfy.bpfModule, ebpfy.EggInfo.EgressInterface, bpf.BPFTcEgress, "tc_egress")
		err = attachTcBpfEgressStack(ey.bpfModule, ey.EggInfo.EgressInterface, netNsPath, ey.EggInfo.Shaping)
		must(err, "Can't attach TC hook.")
		logger.Info("Attached eBPF program to tc hooks")

		//tools.ShapeEgressInterface(netNsPath, ebpfy.EgressInterface)

	} else {
		//err = attachTcCgroupEgressStack(ey.EggInfo.EgressInterface, ey.cgroupNetCls, ey.EggInfo.Shaping, netNsPath, pid)
		//must(err, "can't attach tc cgroup stack")
		err = attachCgroupProg(ey.bpfModule, "cgroup__skb_egress", bpf.BPFAttachTypeCgroupInetEgress, cgroupPath)
		must(err, "can't attach cgroup hook")
		err = attachCgroupProg(ey.bpfModule, "cgroup__skb_ingress", bpf.BPFAttachTypeCgroupInetIngress, cgroupPath)
		must(err, "can't attach cgroup hook")
		logger.Info("Attached eBPF program to cgroup hooks")
		//err = attachCgroupProg(ebpfy.bpfModule, "cgroup__sock", bpf.BPFAttachTypeCgroupSockOps)
		//must(err, "can't attach cgroup hook")

	}

	ey.packets = make(chan []byte) //TODO need Close() on this channel

	rb, err := ey.bpfModule.InitRingBuf("packets", ey.packets)
	must(err, "Can't initialize ring buffer map.")

	//rb.Start()
	rb.Poll(300)
	//TODO: remove this:
	//go func() {
	//	time.Sleep(3 * time.Second)
	//	//_, err := exec.Command("curl", "https://www.onet.pl").Output()
	//	//_, err := exec.Command("curl", "-g", "-6", "https://bbc.com").Output()
	//	_, err := exec.Command("curl", "-g", "https://bbc.com").Output()
	//	if err != nil {
	//		fmt.Fprintln(os.Stderr, err)
	//		os.Exit(-1)
	//	}
	//}()

	ey.ipv4ACL, err = ey.bpfModule.GetMap("ipv4_lpm_map")
	ey.ipv6ACL, err = ey.bpfModule.GetMap("ipv6_lpm_map")
	must(err, "Can't get map") //TODO remove Must

	ey.initCIDRs()
	ey.initCNs()

	wg.Add(1)
	go func() {
		//LIFO
		defer wg.Done() //added with new tc filter approach via go-tc
		defer ey.bpfModule.Close()
		defer func() {
			if /*len(cgroupPath) == 0*/ programType == common.ProgramTypeTC {
				//tools.CleanInterfaces(netNsPath, ebpfy.IngressInterface, ebpfy.EgressInterface)
				if err := net.CleanIngressTcNetStack(netNsPath, ey.EggInfo.IngressInterface); err != nil {
					fmt.Println(err)
				}
				if err := net.CleanEgressTcNetStack(netNsPath, ey.EggInfo.EgressInterface); err != nil {
					fmt.Println(err)
				}
			} else {
				// TODO add condition on shaping
				if err := net.CleanEgressTcNetStack(netNsPath, ey.EggInfo.EgressInterface); err != nil {
					fmt.Println(err)
				}
			}
		}()

		var lwg sync.WaitGroup
		//runMapLooper(ctx, ebpfy.ipv4ACL, ebpfy.CNs, ipv4, &lwg, netNsPath, cgroupPath)
		//runMapLooper(ctx, ebpfy.ipv6ACL, ebpfy.CNs, ipv6, &lwg, netNsPath, cgroupPath)
		ey.runPacketsLooper(ctx, &lwg, netNsPath, cgroupPath)
		lwg.Wait()

		fmt.Println("///Stopping recvLoop.")
		rb.Stop()
		rb.Close()
		fmt.Println("recvLoop stopped.")
	}()

	return nil
}

func (ey *ebpfy) initCIDRs() {
	//{cidrs
	fmt.Println("[ACL]: Init")
	for i := 0; i < len(ey.EggInfo.CIDRs); i++ {
		cidr := ey.EggInfo.CIDRs[i]
		val := ipLPMVal{
			ttl:     0,
			counter: 0,
			//id:      cidr.id, //test
			status: uint8(common.AssetSynced),
		}

		var err error
		switch ip := cidr.lpmKey.(type) {
		case ipv4LPMKey:
			err = updateACLValueNew(ey.ipv4ACL, ip, val)
		case ipv6LPMKey:
			err = updateACLValueNew(ey.ipv6ACL, ip, val)
		}
		must(err, "Can't update ACL.")

		cidr.status = common.AssetSynced
	}
}

// initCNs
func (ey *ebpfy) initCNs() {
	for i := 0; i < len(ey.EggInfo.CNs); i++ {
		//to have simmilar approach only with CIDRs
		current := ey.EggInfo.CNs[i]
		current.status = common.AssetSynced
	}
}

func (ey *ebpfy) updateCIDRs(cidrs []*CIDR) error {

	for i := 0; i < len(ey.EggInfo.CIDRs); i++ {
		current := ey.EggInfo.CIDRs[i]
		current.status = common.AssetStale

		for _, newone := range cidrs {
			if current.cidr == newone.cidr {
				current.status = common.AssetSynced
				newone.status = common.AssetSynced
			}
		}
	}

	// ipv4: Set stale
	i := ey.ipv4ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	for i.Next() {
		fmt.Println("%%%>>>4.2")
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(ey.ipv4ACL, key)

		//we control CIDR with ttl=0 only
		if val.ttl == 0 {
			for i := 0; i < len(ey.EggInfo.CIDRs); i++ {
				cidr := ey.EggInfo.CIDRs[i]
				ipv4Key, ok := cidr.lpmKey.(ipv4LPMKey)
				if ok {
					if key.prefixLen == ipv4Key.prefixLen && key.data == ipv4Key.data {
						if cidr.status == common.AssetStale {
							val.status = uint8(common.AssetStale)
							err := updateACLValueNew(ey.ipv4ACL, key, val)
							if err != nil {
								return fmt.Errorf("Updating value status", ey)
							}
						}
					}
				}
			}
		}
	}
	// ipv6: Set stale
	i = ey.ipv6ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	for i.Next() {
		fmt.Println("%%%>>>4.2")
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv6ACLKey(keyBytes)
		val := getACLValue(ey.ipv6ACL, key)

		//we control CIDR with ttl=0 only
		if val.ttl == 0 {
			for i := 0; i < len(ey.EggInfo.CIDRs); i++ {
				cidr := ey.EggInfo.CIDRs[i]
				ipv6Key, ok := cidr.lpmKey.(ipv6LPMKey)
				if ok {
					if key.prefixLen == ipv6Key.prefixLen && key.data == ipv6Key.data {
						if cidr.status == common.AssetStale {

							val.status = uint8(common.AssetStale)
							err := updateACLValueNew(ey.ipv6ACL, key, val)
							if err != nil {
								return fmt.Errorf("Updating value status", ey)
							}
						}
					}
				}
			}
		}
	}

	//add
	for _, cidr := range cidrs {
		if cidr.status == common.AssetNew {
			val := ipLPMVal{
				ttl:     0,
				counter: 0,
				status:  uint8(common.AssetSynced),
			}

			err := updateACLValueNew(ey.ipv4ACL, cidr.lpmKey, val)
			if err != nil {
				return fmt.Errorf("Can't update ACL %#v", err)
			}
			cidr.status = common.AssetSynced
			ey.EggInfo.CIDRs = append(ey.EggInfo.CIDRs, cidr)
		}
	}

	for i := 0; i < len(ey.EggInfo.CIDRs); i++ {
		cidr := ey.EggInfo.CIDRs[i]
		if cidr.status != common.AssetSynced {
			fmt.Printf("Stale keys %#v\n", cidr)

		}
	}

	return nil
}

func (ey *ebpfy) updateCNs(cns []*CN) error {
	for i := 0; i < len(ey.EggInfo.CNs); i++ {
		current := ey.EggInfo.CNs[i]
		current.status = common.AssetStale

		for _, newone := range cns {
			if current.cn == newone.cn {
				current.status = common.AssetSynced
				newone.status = common.AssetSynced
			}
		}
	}

	// delete
	i := ey.ipv4ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	for i.Next() {
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(ey.ipv4ACL, key)

		//we control CNs with ttl!=0 only
		if val.ttl != 0 {
			fmt.Println("%%%>>> Found ttl!=0")
			for i := 0; i < len(ey.EggInfo.CNs); i++ {
				current := ey.EggInfo.CNs[i]
				if val.id == current.id {
					if current.status == common.AssetStale {
						fmt.Println("%%%>>> current.Status is Stale")
						val.status = uint8(common.AssetStale)
						err := updateACLValueNew(ey.ipv4ACL, key, val) //invalidate all IPs for stale CNs
						if err != nil {
							return fmt.Errorf("Updating value status", ey)
						}
					}
				}
			}
		}

		//we control CNs with ttl!=0 only
		if val.ttl != 0 {
			fmt.Println("%%%>>> Found ttl!=0")
			for i := 0; i < len(ey.EggInfo.CNs); i++ {
				current := ey.EggInfo.CNs[i]
				if val.id == current.id {
					if current.status == common.AssetStale {
						fmt.Println("%%%>>> current.Status is Stale")
						val.status = uint8(common.AssetStale)
						err := updateACLValueNew(ey.ipv4ACL, key, val) //invalidate all IPs for stale CNs
						if err != nil {
							return fmt.Errorf("Updating value status", ey)
						}
					}
				}
			}
		}
	}
	//add
	for _, cn := range cns {
		fmt.Println("%%%>>> adding new cn %v", cn)
		if cn.status == common.AssetNew {
			cn.status = common.AssetSynced
			ey.EggInfo.CNs = append(ey.EggInfo.CNs, cn)
		}
	}

	for i := 0; i < len(ey.EggInfo.CNs); i++ {
		current := ey.EggInfo.CNs[i]
		if current.status != common.AssetSynced {
			fmt.Printf("CN: Stale key %#v\n", current)
		}
	}

	return nil
}

func (ey *ebpfy) runPacketsLooper(ctx context.Context, lwg *sync.WaitGroup, netNsPath string, cgroupPath string) {
	lwg.Add(1)
	go func() {
		defer lwg.Done()
		defer fmt.Println("runPacketsLooper terminated")
		fmt.Println("??????[1]")
	recvLoop:

		for {
			select {
			case <-ctx.Done():
				fmt.Println("[recvLoop]: stopCh closed.")
				break recvLoop
			case b, ok := <-ey.packets:
				fmt.Println("??????[2]")
				if ok == false {
					fmt.Println("[recvLoop]: Channel not OK!")
					break recvLoop
				}

				skbLen := binary.LittleEndian.Uint32(b[0:4])

				//fmt.Printf("\n\nskb.len:%d, skb.", skbLen)
				data := b[4:(skbLen + 4)]
				//fmt.Println("Encoded packet:", insertNth(hex.EncodeToString(data), 2))

				packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
				// BpfManagerInstance the TCP layer from this packet

				for _, l := range packet.Layers() {
					fmt.Println("Layer:", l.LayerType())
				}

				fmt.Printf("packet:%s\n", hex.EncodeToString(packet.Data()))

				var payload []byte
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					fmt.Println("This is a TCP packet!")
					// BpfManagerInstance actual TCP data from this layer
					tcp, _ := tcpLayer.(*layers.TCP)
					fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)

					payload = tcp.Payload
				} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
					fmt.Println("This is a UDP packet!")
					// BpfManagerInstance actual TCP data from this layer
					udp, _ := udpLayer.(*layers.UDP)
					fmt.Printf("From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)

					payload = udp.Payload
				} else {
					fmt.Println("This is not a TCP or UDP packet!")
				}

				dnsPacket := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
				if dnsLayer := dnsPacket.Layer(layers.LayerTypeDNS); dnsLayer != nil {
					fmt.Println("This is a DNS packet!")
					// BpfManagerInstance actual TCP data from this layer

					dns := dnsLayer.(*layers.DNS)

					fmt.Printf("Type: IsResponse:%t\n", dns.QR)
					questions := dns.Questions
					for _, q := range questions {
						fmt.Printf("Question: Name:%s Type:%s Class:%s\n", string(q.Name), q.Type, q.Class)
					}
					answers := dns.Answers
					for _, a := range answers {
						fmt.Printf("@@@@Type: %s, Answer: IP:%s Name:%s CName:%s\n", a.Type, a.IP, string(a.Name), string(a.CNAME))
						if a.Type == layers.DNSTypeA || a.Type == layers.DNSTypeAAAA {

							cn := string(a.Name)
							ip := a.IP
							ttlSec := a.TTL //!!! remove * 5
							var key ILPMKey

							if a.Type == layers.DNSTypeA {
								key = ipv4LPMKey{32, [4]uint8(ip[0:4])}
							} else {
								key = ipv6LPMKey{128, [16]uint8(ip[0:16])}
							}
							//val := time.Now().Unix() + int64(ttl) //Now + ttl
							ttlNs := uint64(ttlSec) * 1000000000
							bootTtlNs := uint64(C.get_nsecs()) + ttlNs //boot time[ns] + ttl[ns]
							//fmt.Println("key size:", unsafe.Sizeof(key))
							//fmt.Println("key data:", key.data)

							if cn, found := containsCN(ey.EggInfo.CNs, cn); found {
								val := ipLPMVal{
									ttl:     bootTtlNs,
									counter: 0, //zero existsing elements :/ //TODO why 0?
									id:      cn.id,
									status:  uint8(common.AssetSynced),
								}
								var err error
								if a.Type == layers.DNSTypeA {
									err = updateACLValueNew(ey.ipv4ACL, key, val)
								} else {
									err = updateACLValueNew(ey.ipv6ACL, key, val)
								}
								must(err, "Can't update ACL.")
								fmt.Printf("ebpfy-ref: %p, netNsPath: %s cgroupPath: %s - updated for %s ip:%s DNS ttl:%d, ttlNs:%d, bootTtlNs:%d\n", ey, netNsPath, cgroupPath, cn, ip, ttlSec, ttlNs, bootTtlNs)

							} else {
								fmt.Println("DROP")
							}
						}
						//} else if a.Type == layers.DNSTypeAAAA {
						//	fmt.Println("!!!Answer.Type:", a.Type)
						//	cn := string(a.Name)
						//	ip := a.IP
						//	ttlSec := a.TTL //!!! remove * 5
						//
						//	key := ipv6LPMKey{128, [16]uint8(ip[0:16])}
						//	//val := time.Now().Unix() + int64(ttl) //Now + ttl
						//	ttlNs := uint64(ttlSec) * 1000000000
						//	bootTtlNs := uint64(C.get_nsecs()) + ttlNs //boot time[ns] + ttl[ns]
						//	//fmt.Println("key size:", unsafe.Sizeof(key))
						//	//fmt.Println("key data:", key.data)
						//
						//	if cn, found := containsCN(ebpfy.CNs, cn); found {
						//		val := ipLPMVal{
						//			ttl:     bootTtlNs,
						//			counter: 0, //zero existsing elements :/
						//			id:      cn.id,
						//			status:  uint8(assetSynced),
						//		}
						//		err := updateACLValueNew(ebpfy.ipv6ACL, key, val)
						//		must(err, "Can't update ACL.")
						//		fmt.Printf("Updated for %s ip:%s DNS ttl:%d, ttlNs:%d, bootTtlNs:%d\n", cn, ip, ttlSec, ttlNs, bootTtlNs)
						//
						//	} else {
						//		fmt.Println("DROP")
						//	}
						//
						//}

					}
				} else {
					fmt.Println("This is not a DNS packet!:/")
				}

				//numberOfEventsReceived++
				//
				//fmt.Println("[10]")
				//if numberOfEventsReceived > 3 {
				//	break recvLoop
				//}
			}
		}
	}()
}

func runMapLooper(ctx context.Context, bpfM *bpf.BPFMap, cns *syncx.SafeSlice[CN], ipv ipProtocolVersion, lwg *sync.WaitGroup, netNsPath string, cgroupPath string) {
	lwg.Add(1)
	go func() {
		defer lwg.Done()
		defer fmt.Printf("runMapLooper terminated")
	mapLoop:
		for {
			select {
			case <-ctx.Done():
				fmt.Println("[mapLoop]: stopCh closed.")
				break mapLoop
			default:
				time.Sleep(5 * time.Second)
				fmt.Printf("\n\n----bpfM: %p\n", bpfM)
				i := bpfM.Iterator() //determineHost Endian search by Itertaot in libbfpgo
				for i.Next() {
					if i.Err() != nil {
						fatal("Iterator error", i.Err())
					}
					keyBytes := i.Key()
					prefixLen := binary.LittleEndian.Uint32(keyBytes[0:4])

					var key ILPMKey
					var ipB []byte
					if ipv == ipv4 {
						ipB = keyBytes[4:8]
						//ip := bytes2ip(ipBytes)
						key = ipv4LPMKey{prefixLen, [4]uint8((ipB))}
					} else {
						ipB = keyBytes[4:20]
						//ip := bytes2ip(ipBytes)
						key = ipv6LPMKey{prefixLen, [16]uint8((ipB))}
					}

					val := getACLValue(bpfM, key)
					bootNs := uint64(C.get_nsecs())
					//var expired string = fmt.Sprintf("%d-%d", bootNs, ttl)
					var expired string
					if val.ttl != 0 && val.ttl < bootNs {
						//fmt.Printf("\nttl(%d)<bootNs(%d)=%t | ", ttl, bootNs, ttl < bootNs)
						expired = "x"
					}

					//test only
					var cn string
					if val.ttl != 0 {
						for i := 0; i < cns.Len(); i++ {
							current := cns.Get(i)
							if current.id == val.id {
								cn = current.cn
							}
						}
					}

					//valBytes := ipv4ACL[ipv4LPMKey{1,1}]
					//fmt.Printf(" [bootTtlNs:%d,bootNs:%d][%s]%s/%d[%d]", ttl, bootNs, expired, ip, prefixLen, val.counter)
					fmt.Printf("netNsPath:%s cgroupPath:%s id: %d cn:%s expired:%s ip: %v/%d counter:%d status:%d\n", netNsPath, cgroupPath, val.id, cn, expired, ipB, prefixLen, val.counter, val.status)

				}
			}
		}
	}()
}

func unmarshalIpv4ACLKey(bytes []byte) ipv4LPMKey {
	prefixLen := binary.LittleEndian.Uint32(bytes[0:4])
	ipB := bytes[4:8]

	return ipv4LPMKey{prefixLen, [4]uint8(ipB)}
}

func unmarshalIpv6ACLKey(bytes []byte) ipv6LPMKey {
	prefixLen := binary.LittleEndian.Uint32(bytes[0:4])
	ipBytes := bytes[4:20]

	return ipv6LPMKey{prefixLen, [16]uint8(ipBytes)}
}

func getACLValue(acl *bpf.BPFMap, ikey ILPMKey) ipLPMVal {
	upKey := ikey.GetPointer()
	valBytes, err := acl.GetValue(upKey)
	must(err, "Can't get value.")
	return unmarshalValue(valBytes)
}

func unmarshalValue(bytes []byte) ipLPMVal {
	return ipLPMVal{
		ttl:     binary.LittleEndian.Uint64(bytes[0:8]),
		counter: binary.LittleEndian.Uint64(bytes[8:16]),
		id:      binary.LittleEndian.Uint16(bytes[16:18]),
		status:  bytes[18:19][0],
	}
}

func updateACLValueNew(acl *bpf.BPFMap, ikey ILPMKey, val ipLPMVal) error {
	//check if not exists first
	upKey := ikey.GetPointer()
	oldValBytes, err := acl.GetValue(upKey)
	var oldVal ipLPMVal
	if err == nil { //update in any cases
		//fmt.Println("Key/Value exists.", ikey, oldValBytes)
		oldVal = unmarshalValue(oldValBytes)
		val.counter += oldVal.counter
		fmt.Println("Counters:", oldVal.counter, val.counter)
	}

	upVal := unsafe.Pointer(&val)

	err = acl.Update(upKey, upVal)
	if err != nil {
		fmt.Println("[updatACL] Can't upate ACLP, err:", err)
		return err
	} else {
		fmt.Printf("[updateACLValue-acl-map-ref:%p] ACL updated for, key:%v, val:%v\n", acl, ikey, val)
	}
	//!!} else {
	//!!	fmt.Printf("[updateACLValue] Key already exists in ACL, key:%v val:%v\n", key, binary.LittleEndian.Uint64(v))
	//!!}
	return nil
}

func removeACLKey(acl *bpf.BPFMap, key ipv4LPMKey) error {
	upKey := unsafe.Pointer(&key)
	//check if not exists first
	err := acl.DeleteKey(upKey)
	if err != nil { //update in any cases
		fmt.Printf("Key not exists %v", key)
	}

	return nil
}

func attachTcBpfEgressStack(bpfModule *bpf.Module, iface, netNsPath string, shaping *ShapingInfo) error {
	tcProg, err := bpfModule.GetProgram(BpfEgressProgram)
	if err != nil {
		return err
	}

	if err := net.AttachEgressTcBpfNetStack(netNsPath, iface, tcProg.FileDescriptor(), "./"+BpfObjectFileName, BpfEgressSection, net.TcShaping(*shaping)); err != nil {

		return err
	}

	return nil
}

func attachTcBpfIngressStack(bpfModule *bpf.Module, iface, netNsPath string) error {
	tcProg, err := bpfModule.GetProgram(BpfIngressProgram)
	if err != nil {
		return err
	}

	if err := net.AttachIngressTcBpfNetStack(netNsPath, iface, tcProg.FileDescriptor(), BpfObjectFileName, BpfIngressSection); err != nil {
		return err
	}

	return nil
}

func must(err error, format string, args ...interface{}) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, format+"| %v\n", args, err)
		panic(err)
	}
}

func fatal(format string, args ...interface{}) {
	err := fmt.Errorf(format+"\n", args...)
	_, _ = fmt.Fprintf(os.Stderr, err.Error())
	panic(err)
}

func containsCN(cns *syncx.SafeSlice[CN], cnS string) (CN, bool) {
	var current CN
	for i := 0; i < cns.Len(); i++ {
		current = cns.Get(i)
		fmt.Printf("))) current=%#v cnS=%s\n", current, cnS)
		if current.status == common.AssetSynced && strings.Contains(cnS, current.cn) { //e.g. DNS returns cnS="abc.example.com" and current.cn=".example.com"
			fmt.Printf(" ^ found\n")
			return current, true
		}
	}
	fmt.Printf(" ^ not-found\n")
	return current, false
}
