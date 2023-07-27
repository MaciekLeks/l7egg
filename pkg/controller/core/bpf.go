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
	"github.com/containerd/cgroups/v3/cgroup1"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"k8s.io/klog/v2"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// egg holds EggInfo (extracted from ClusterEggSpec) and ebpf related structures, e.g. maps, channels operating on that maps
type egg struct {
	// Depreciated: should all part of egg struct
	EggInfo      //TOOD remove from here
	bpfModule    *bpf.Module
	ipv4ACL      *bpf.BPFMap
	ipv6ACL      *bpf.BPFMap
	packets      chan []byte
	cgroupNetCls cgroup1.Cgroup //cgroup net_cls for cgroup programs
	//aclLoock  sync.RWMutex
}

func newEmptyEgg(eggi *EggInfo) *egg {
	var egg egg
	egg.EggInfo = *eggi
	return &egg
}

// run runs the egg, and if neither nsNetPath nor cgroupPath is Set, it will run the egg in the current network netspace (tc over cgroup
func (egg *egg) run(ctx context.Context, wg *sync.WaitGroup, programInfo common.ProgramInfo /*netNsPath string, cgroupPath string*/, pids ...uint32) error {
	var err error

	egg.bpfModule, err = bpf.NewModuleFromFile(BpfObjectFileName)
	if err != nil {
		return err
	}

	err = egg.bpfModule.BPFLoadObject()
	if err != nil {
		return err
	}

	logger := klog.FromContext(ctx)

	logger.Info("Attaching eBPF program having", "programInfo", programInfo)
	if /*len(cgroupPath) == 0*/ programInfo.ProgramType == common.ProgramTypeTC {
		time.Sleep(4 * time.Second)
		fmt.Printf("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

		//err = attachTcProg(egg.bpfModule, egg.EggInfo.IngressInterface, bpf.BPFTcIngress, "tc_ingress")
		err = attachTcBpfIngressStack(egg.bpfModule, egg.EggInfo.EgressInterface, programInfo.NetNsPath)
		must(err, "Can't attach TC hook.")
		//err = attachTcProg(egg.bpfModule, egg.EggInfo.EgressInterface, bpf.BPFTcEgress, "tc_egress")
		err = attachTcBpfEgressStack(egg.bpfModule, egg.EggInfo.EgressInterface, programInfo.NetNsPath, egg.Shaping)
		must(err, "Can't attach TC hook.")
		logger.Info("Attached eBPF program to tc hooks")

		//tools.ShapeEgressInterface(netNsPath, egg.EgressInterface)

	} else {
		err = attachTcCgroupEgressStack(egg.EgressInterface, egg.cgroupNetCls, egg.Shaping, programInfo.NetNsPath, pids...)
		must(err, "can't attach tc cgroup stack")
		err = attachCgroupProg(egg.bpfModule, "cgroup__skb_egress", bpf.BPFAttachTypeCgroupInetEgress, programInfo.CgroupPath)
		must(err, "can't attach cgroup hook")
		err = attachCgroupProg(egg.bpfModule, "cgroup__skb_ingress", bpf.BPFAttachTypeCgroupInetIngress, programInfo.CgroupPath)
		must(err, "can't attach cgroup hook")
		logger.Info("Attached eBPF program to cgroup hooks")
		//err = attachCgroupProg(egg.bpfModule, "cgroup__sock", bpf.BPFAttachTypeCgroupSockOps)
		//must(err, "can't attach cgroup hook")

	}

	egg.packets = make(chan []byte) //TODO need Close() on this channel

	rb, err := egg.bpfModule.InitRingBuf("packets", egg.packets)
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

	egg.ipv4ACL, err = egg.bpfModule.GetMap("ipv4_lpm_map")
	egg.ipv6ACL, err = egg.bpfModule.GetMap("ipv6_lpm_map")
	must(err, "Can't get map") //TODO remove Must

	egg.initCIDRs()
	egg.initCNs()

	wg.Add(1)
	go func() {
		//LIFO
		defer wg.Done() //added with new tc filter approach via go-tc
		defer egg.bpfModule.Close()
		defer func() {
			if /*len(cgroupPath) == 0*/ programInfo.ProgramType == common.ProgramTypeTC {
				//tools.CleanInterfaces(netNsPath, egg.IngressInterface, egg.EgressInterface)
				if err := net.CleanIngressTcNetStack(programInfo.NetNsPath, egg.IngressInterface); err != nil {
					fmt.Println(err)
				}
				if err := net.CleanEgressTcNetStack(programInfo.NetNsPath, egg.EgressInterface); err != nil {
					fmt.Println(err)
				}
			} else {
				// TODO add condition on shaping
				if err := net.CleanEgressTcNetStack(programInfo.NetNsPath, egg.EgressInterface); err != nil {
					fmt.Println(err)
				}
			}
		}()

		var lwg sync.WaitGroup
		//runMapLooper(ctx, egg.ipv4ACL, egg.CNs, ipv4, &lwg, netNsPath, cgroupPath)
		//runMapLooper(ctx, egg.ipv6ACL, egg.CNs, ipv6, &lwg, netNsPath, cgroupPath)
		egg.runPacketsLooper(ctx, &lwg, programInfo.NetNsPath, programInfo.CgroupPath)
		lwg.Wait()

		fmt.Println("///Stopping recvLoop.")
		rb.Stop()
		rb.Close()
		fmt.Println("recvLoop stopped.")
	}()

	return nil
}

func (egg *egg) initCIDRs() {
	//{cidrs
	fmt.Println("[ACL]: Init")
	for i := 0; i < egg.CIDRs.Len(); i++ {
		cidr := egg.CIDRs.Get(i)
		val := ipLPMVal{
			ttl:     0,
			counter: 0,
			//id:      cidr.id, //test
			status: uint8(assetSynced),
		}

		var err error
		switch ip := cidr.lpmKey.(type) {
		case ipv4LPMKey:
			err = updateACLValueNew(egg.ipv4ACL, ip, val)
		case ipv6LPMKey:
			err = updateACLValueNew(egg.ipv6ACL, ip, val)
		}
		must(err, "Can't update ACL.")
		egg.CIDRs.Update(i, func(current *CIDR) {
			current.status = assetSynced
		})
	}
}

// initCNs
func (egg *egg) initCNs() {
	for i := 0; i < egg.CNs.Len(); i++ {
		egg.CNs.Update(i, func(current *CN) {
			//to have simmilar approach only with CIDRs
			current.status = assetSynced
		})
	}
}

func (egg *egg) updateCIDRs(cidrs []CIDR) error {

	for i := 0; i < egg.CIDRs.Len(); i++ {
		egg.CIDRs.Update(i, func(current *CIDR) {
			current.status = assetStale
		})

		current := egg.CIDRs.Get(i)
		for _, newone := range cidrs {
			if current.cidr == newone.cidr {
				egg.CIDRs.Update(i, func(current *CIDR) {
					current.status = assetSynced
				})
				newone.status = assetSynced
			}
		}
	}

	// ipv4: Set stale
	i := egg.ipv4ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	for i.Next() {
		fmt.Println("%%%>>>4.2")
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(egg.ipv4ACL, key)

		//we control CIDR with ttl=0 only
		if val.ttl == 0 {
			for i := 0; i < egg.CIDRs.Len(); i++ {
				cidr := egg.CIDRs.Get(i)
				ipv4Key, ok := cidr.lpmKey.(ipv4LPMKey)
				if ok {
					if key.prefixLen == ipv4Key.prefixLen && key.data == ipv4Key.data {
						if cidr.status == assetStale {
							val.status = uint8(assetStale)
							err := updateACLValueNew(egg.ipv4ACL, key, val)
							if err != nil {
								return fmt.Errorf("Updating value status", egg)
							}
						}
					}
				}
			}
		}
	}
	// ipv6: Set stale
	i = egg.ipv6ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	for i.Next() {
		fmt.Println("%%%>>>4.2")
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv6ACLKey(keyBytes)
		val := getACLValue(egg.ipv6ACL, key)

		//we control CIDR with ttl=0 only
		if val.ttl == 0 {
			for i := 0; i < egg.CIDRs.Len(); i++ {
				cidr := egg.CIDRs.Get(i)
				ipv6Key, ok := cidr.lpmKey.(ipv6LPMKey)
				if ok {
					if key.prefixLen == ipv6Key.prefixLen && key.data == ipv6Key.data {
						if cidr.status == assetStale {

							val.status = uint8(assetStale)
							err := updateACLValueNew(egg.ipv6ACL, key, val)
							if err != nil {
								return fmt.Errorf("Updating value status", egg)
							}
						}
					}
				}
			}
		}
	}

	//add
	for _, cidr := range cidrs {
		if cidr.status == assetNew {
			val := ipLPMVal{
				ttl:     0,
				counter: 0,
				status:  uint8(assetSynced),
			}

			err := updateACLValueNew(egg.ipv4ACL, cidr.lpmKey, val)
			if err != nil {
				return fmt.Errorf("Can't update ACL %#v", err)
			}
			cidr.status = assetSynced
			egg.CIDRs.Append(cidr)
		}
	}

	for i := 0; i < egg.CIDRs.Len(); i++ {
		cidr := egg.CIDRs.Get(i)
		if cidr.status != assetSynced {
			fmt.Printf("Stale keys %#v\n", cidr)

		}
	}

	return nil
}

func (egg *egg) updateCNs(cns []CN) error {
	for i := 0; i < egg.CNs.Len(); i++ {
		egg.CNs.Update(i, func(current *CN) {
			current.status = assetStale
		})

		current := egg.CNs.Get(i)
		for _, newone := range cns {
			if current.cn == newone.cn {
				egg.CNs.Update(i, func(current *CN) {
					fmt.Println("%%%>>> egg.CNs.UpdateEgg")
					current.status = assetSynced
				})
				newone.status = assetSynced
			}
		}
	}

	// delete
	i := egg.ipv4ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	for i.Next() {
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(egg.ipv4ACL, key)

		//we control CNs with ttl!=0 only
		if val.ttl != 0 {
			fmt.Println("%%%>>> Found ttl!=0")
			for i := 0; i < egg.CNs.Len(); i++ {
				current := egg.CNs.Get(i)
				if val.id == current.id {
					if current.status == assetStale {
						fmt.Println("%%%>>> current.Status is Stale")
						val.status = uint8(assetStale)
						err := updateACLValueNew(egg.ipv4ACL, key, val) //invalidate all IPs for stale CNs
						if err != nil {
							return fmt.Errorf("Updating value status", egg)
						}
					}
				}
			}
		}

		//we control CNs with ttl!=0 only
		if val.ttl != 0 {
			fmt.Println("%%%>>> Found ttl!=0")
			for i := 0; i < egg.CNs.Len(); i++ {
				current := egg.CNs.Get(i)
				if val.id == current.id {
					if current.status == assetStale {
						fmt.Println("%%%>>> current.Status is Stale")
						val.status = uint8(assetStale)
						err := updateACLValueNew(egg.ipv4ACL, key, val) //invalidate all IPs for stale CNs
						if err != nil {
							return fmt.Errorf("Updating value status", egg)
						}
					}
				}
			}
		}
	}
	//add
	for _, cn := range cns {
		fmt.Println("%%%>>> adding new cn %v", cn)
		if cn.status == assetNew {
			cn.status = assetSynced
			egg.CNs.Append(cn)
		}
	}

	for i := 0; i < egg.CNs.Len(); i++ {
		current := egg.CNs.Get(i)
		if current.status != assetSynced {
			fmt.Printf("CN: Stale key %#v\n", current)
		}
	}

	return nil
}

func (egg *egg) runPacketsLooper(ctx context.Context, lwg *sync.WaitGroup, netNsPath string, cgroupPath string) {
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
			case b, ok := <-egg.packets:
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

							if cn, found := containsCN(egg.CNs, cn); found {
								val := ipLPMVal{
									ttl:     bootTtlNs,
									counter: 0, //zero existsing elements :/ //TODO why 0?
									id:      cn.id,
									status:  uint8(assetSynced),
								}
								var err error
								if a.Type == layers.DNSTypeA {
									err = updateACLValueNew(egg.ipv4ACL, key, val)
								} else {
									err = updateACLValueNew(egg.ipv6ACL, key, val)
								}
								must(err, "Can't update ACL.")
								fmt.Printf("egg-ref: %p, netNsPath: %s cgroupPath: %s - updated for %s ip:%s DNS ttl:%d, ttlNs:%d, bootTtlNs:%d\n", egg, netNsPath, cgroupPath, cn, ip, ttlSec, ttlNs, bootTtlNs)

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
						//	if cn, found := containsCN(egg.CNs, cn); found {
						//		val := ipLPMVal{
						//			ttl:     bootTtlNs,
						//			counter: 0, //zero existsing elements :/
						//			id:      cn.id,
						//			status:  uint8(assetSynced),
						//		}
						//		err := updateACLValueNew(egg.ipv6ACL, key, val)
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

func attachTcBpfEgressStack(bpfModule *bpf.Module, iface, netNsPath string, shaping ShapingInfo) error {
	tcProg, err := bpfModule.GetProgram(BpfEgressProgram)
	if err != nil {
		return err
	}

	if err := net.AttachEgressTcBpfNetStack(netNsPath, iface, tcProg.FileDescriptor(), "./"+BpfObjectFileName, BpfEgressSection, net.TcShaping(shaping)); err != nil {

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

func attachTcCgroupEgressStack(iface string, cgroupNetCls cgroup1.Cgroup, shaping ShapingInfo, netNsPath string, pids ...uint32) error {
	if err := net.AttachEgressTcCgroupNetStack(netNsPath, cgroupNetCls, iface, net.TcShaping(shaping), pids...); err != nil {
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
		if current.status == assetSynced && strings.Contains(cnS, current.cn) { //e.g. DNS returns cnS="abc.example.com" and current.cn=".example.com"
			fmt.Printf(" ^ found\n")
			return current, true
		}
	}
	fmt.Printf(" ^ not-found\n")
	return current, false
}
