package user

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
	"github.com/MaciekLeks/l7egg/pkg/syncx"
	"github.com/MaciekLeks/l7egg/pkg/tools"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type egg struct {
	// Depreciated: should all part of egg struct
	ClientEgg //TOOD remove from here
	bpfModule *bpf.Module
	ipv4ACL   *bpf.BPFMap
	ipv6ACL   *bpf.BPFMap
	packets   chan []byte
	//aclLoock  sync.RWMutex
}

// depreciated
func newEgg(clientegg *ClientEgg) *egg {
	var egg egg
	var err error

	egg.ClientEgg = *clientegg //TOOD no needed
	egg.bpfModule, err = bpf.NewModuleFromFile(clientegg.BPFObjectPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = egg.bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = attachProg(egg.bpfModule, clientegg.IngressInterface, bpf.BPFTcIngress, "tc_ingress")
	must(err, "Can't attach TC hook.")
	err = attachProg(egg.bpfModule, clientegg.EgressInterface, bpf.BPFTcEgress, "tc_egress")
	must(err, "Can't attach TC hook.")

	egg.packets = make(chan []byte) //TODO need Close() on this channel

	return &egg
}

func newEmptyEgg(clientegg *ClientEgg) *egg {
	var egg egg

	egg.ClientEgg = *clientegg

	return &egg
}

// run runs the egg, and if neither nsNetPath nor cgroupPath is set, it will run the egg in the current network netspace (tc over cgroup
func (egg *egg) run(ctx context.Context, wg *sync.WaitGroup, netNSPath string, cgroupPath string) error {
	var err error

	egg.bpfModule, err = bpf.NewModuleFromFile(egg.ClientEgg.BPFObjectPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = egg.bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if len(cgroupPath) == 0 {
		fmt.Println("---------------Attaching TC programs to interfaces.")
		err = attachProg(egg.bpfModule, egg.ClientEgg.IngressInterface, bpf.BPFTcIngress, "tc_ingress")
		must(err, "Can't attach TC hook.")
		err = attachProg(egg.bpfModule, egg.ClientEgg.EgressInterface, bpf.BPFTcEgress, "tc_egress")
		must(err, "Can't attach TC hook.")
	} else {
		fmt.Println("---------------Attaching cgroup programs.")
		err = attachCgroupProg(egg.bpfModule, "cgroup__skb_egress", bpf.BPFAttachTypeCgroupInetEgress, cgroupPath)
		must(err, "can't attach cgroup hook")
		err = attachCgroupProg(egg.bpfModule, "cgroup__skb_ingress", bpf.BPFAttachTypeCgroupInetIngress, cgroupPath)
		must(err, "can't attach cgroup hook")
		//err = attachCgroupProg(egg.bpfModule, "cgroup__sock", bpf.BPFAttachTypeCgroupSockOps)
		//must(err, "can't attach cgroup hook")
	}

	egg.packets = make(chan []byte) //TODO need Close() on this channel

	rb, err := egg.bpfModule.InitRingBuf("packets", egg.packets)
	must(err, "Can't initialize ring buffer map.")

	rb.Start()
	//TODO: remove this:
	go func() {
		time.Sleep(3 * time.Second)
		//_, err := exec.Command("curl", "https://www.onet.pl").Output()
		//_, err := exec.Command("curl", "-g", "-6", "https://bbc.com").Output()
		_, err := exec.Command("curl", "-g", "https://bbc.com").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()

	egg.ipv4ACL, err = egg.bpfModule.GetMap("ipv4_lpm_map")
	egg.ipv6ACL, err = egg.bpfModule.GetMap("ipv6_lpm_map")
	must(err, "Can't get map") //TODO remove Must

	egg.initCIDRs()
	egg.initCNs()

	wg.Add(1)
	go func() {
		//LIFO
		defer wg.Done()
		defer func() {
			if len(cgroupPath) == 0 {
				tools.CleanInterfaces(netNSPath, egg.IngressInterface, egg.EgressInterface)
			}
		}()
		//only egress needed
		defer egg.bpfModule.Close()

		var lwg sync.WaitGroup
		runMapLooper(ctx, egg.ipv4ACL, egg.CNs, ipv4, &lwg, netNSPath, cgroupPath)
		runMapLooper(ctx, egg.ipv6ACL, egg.CNs, ipv6, &lwg, netNSPath, cgroupPath)
		egg.runPacketsLooper(ctx, &lwg, egg.packets, netNSPath, cgroupPath)
		lwg.Wait()

		fmt.Println("///Stopping recvLoop.")
		rb.Stop()
		rb.Close()
	}()

	return nil
}

func (egg *egg) initCIDRs() {
	//{cidrs
	fmt.Println("[ACL]: Init")
	for _, cidr := range egg.CIDRs {
		val := ipLPMVal{
			ttl:     0,
			counter: 0,
			id:      cidr.id,
			status:  uint8(assetSynced),
		}

		var err error
		switch ip := cidr.lpmKey.(type) {
		case ipv4LPMKey:
			err = updateACLValueNew(egg.ipv4ACL, ip, val)
		case ipv6LPMKey:
			err = updateACLValueNew(egg.ipv6ACL, ip, val)
		}
		must(err, "Can't update ACL.")
		cidr.status = assetSynced
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

func (egg *egg) updateCIDRs(cidrs []*CIDR) error {

	for _, current := range egg.CIDRs {
		current.status = assetStale

		for _, newone := range cidrs {
			if current.cidr == newone.cidr {
				current.status = assetSynced
				newone.status = assetSynced
			}
		}
	}

	// ipv4: set stale
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
			for _, cidr := range egg.CIDRs {
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
	// ipv6: set stale
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
			for _, cidr := range egg.CIDRs {
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
			//shallow copy of cidr
			newOne := *cidr
			egg.CIDRs = append(egg.CIDRs, &newOne)
		}
	}

	for _, cidr := range egg.CIDRs {
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
					fmt.Println("%%%>>> egg.CNs.UpdateClientEgg")
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

func (egg *egg) runPacketsLooper(ctx context.Context, lwg *sync.WaitGroup, packets chan []byte, netNsPath string, cgroupPath string) {
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
			case b, ok := <-packets:
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
								fmt.Printf("netNsPath: %s cgroupPath: %s - updated for %s ip:%s DNS ttl:%d, ttlNs:%d, bootTtlNs:%d\n", netNsPath, cgroupPath, cn, ip, ttlSec, ttlNs, bootTtlNs)

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
				fmt.Printf("\n\n----\n")
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

//func updateACLValue(acl *bpf.BPFMap, key ipv4LPMKey, val ipLPMVal) error {
//	//alyternative way
//	//aclKeyEnc := bytes.NewBuffer(encodeUint32(32))
//	//aclKeyEnc.Write(encodeUint32(ip2Uint32(ip)))
//	//aclValEnc := encodeUint32(1)
//	//fmt.Printf("IP:%s val:%d, hex:%x\n", ip, ip2Uint32(ip), ip2Uint32(ip))
//	//fmt.Printf("Key:%s val:%s\n", insertNth(hex.EncodeToString(aclKeyEnc.Bytes()), 2), insertNth(hex.EncodeToString(aclValEnc), 2))
//	//ipv4ACL.UpdateClientEgg(&aclKeyEnc.Bytes, &aclValEnc)
//
//	upKey := unsafe.Pointer(&key)
//	//check if not exists first
//	oldValBytes, err := acl.GetValue(upKey)
//	var oldVal ipLPMVal
//	if err == nil { //update in any cases
//		fmt.Println("Key/Value exists.", key, oldValBytes)
//		oldVal = unmarshalValue(oldValBytes)
//		val.counter += oldVal.counter
//		fmt.Println("Counters:", oldVal.counter, val.counter)
//	}
//
//	upVal := unsafe.Pointer(&val)
//
//	err = acl.Update(upKey, upVal)
//	if err != nil {
//		fmt.Println("[updatACL] Can't upate ACLP, err:", err)
//		return err
//	} else {
//		fmt.Printf("[updateACLValue] ACL updated for, key:%v, val:%v\n", key, val)
//	}
//	//!!} else {
//	//!!	fmt.Printf("[updateACLValue] Key already exists in ACL, key:%v val:%v\n", key, binary.LittleEndian.Uint64(v))
//	//!!}
//	return nil
//}

//func updateACLValue2(acl *bpf.BPFMap, key ipv6LPMKey, val ipLPMVal) error {
//	//alyternative way
//	//aclKeyEnc := bytes.NewBuffer(encodeUint32(32))
//	//aclKeyEnc.Write(encodeUint32(ip2Uint32(ip)))
//	//aclValEnc := encodeUint32(1)
//	//fmt.Printf("IP:%s val:%d, hex:%x\n", ip, ip2Uint32(ip), ip2Uint32(ip))
//	//fmt.Printf("Key:%s val:%s\n", insertNth(hex.EncodeToString(aclKeyEnc.Bytes()), 2), insertNth(hex.EncodeToString(aclValEnc), 2))
//	//ipv4ACL.UpdateClientEgg(&aclKeyEnc.Bytes, &aclValEnc)
//
//	upKey := unsafe.Pointer(&key)
//	//check if not exists first
//	oldValBytes, err := acl.GetValue(upKey)
//	var oldVal ipLPMVal
//	if err == nil { //update in any cases
//		fmt.Println("Key/Value exists.", key, oldValBytes)
//		oldVal = unmarshalValue(oldValBytes)
//		val.counter += oldVal.counter
//		fmt.Println("Counters:", oldVal.counter, val.counter)
//	}
//
//	upVal := unsafe.Pointer(&val)
//
//	err = acl.Update(upKey, upVal)
//	if err != nil {
//		fmt.Println("[updatACL] Can't upate ACLP, err:", err)
//		return err
//	} else {
//		fmt.Printf("[updateACLValue] ACL updated for, key:%v, val:%v\n", key, val)
//	}
//	//!!} else {
//	//!!	fmt.Printf("[updateACLValue] Key already exists in ACL, key:%v val:%v\n", key, binary.LittleEndian.Uint64(v))
//	//!!}
//	return nil
//}

func updateACLValueNew(acl *bpf.BPFMap, ikey ILPMKey, val ipLPMVal) error {
	//alyternative way
	//aclKeyEnc := bytes.NewBuffer(encodeUint32(32))
	//aclKeyEnc.Write(encodeUint32(ip2Uint32(ip)))
	//aclValEnc := encodeUint32(1)
	//fmt.Printf("IP:%s val:%d, hex:%x\n", ip, ip2Uint32(ip), ip2Uint32(ip))
	//fmt.Printf("Key:%s val:%s\n", insertNth(hex.EncodeToString(aclKeyEnc.Bytes()), 2), insertNth(hex.EncodeToString(aclValEnc), 2))
	//ipv4ACL.UpdateClientEgg(&aclKeyEnc.Bytes, &aclValEnc)

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
		fmt.Printf("[updateACLValue] ACL updated for, key:%v, val:%v\n", ikey, val)
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

func attachProg(bpfModule *bpf.Module, ifaceName string, attachPoint bpf.TcAttachPoint, progName string) error {
	hook := bpfModule.TcHookInit()
	err := hook.SetInterfaceByName(ifaceName)
	must(err, "Failed to set tc hook on interface %s.", ifaceName)

	fmt.Printf("[attachProg]:%s\n", progName)
	hook.SetAttachPoint(attachPoint)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			_, _ = fmt.Fprintf(os.Stderr, "TC hook create: %v.\n", err)
		}
	}

	tcProg, err := bpfModule.GetProgram(progName)
	if tcProg == nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	var tcOpts bpf.TcOpts
	tcOpts.ProgFd = int(tcProg.GetFd())
	err = hook.Attach(&tcOpts)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	return err
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

//
//func insertNth(s string, n int) string {
//	var buffer bytes.Buffer
//	var n_1 = n - 1
//	var l_1 = len(s) - 1
//	for i, rune := range s {
//		buffer.WriteRune(rune)
//		if i%n == n_1 && i != l_1 {
//			buffer.WriteRune(' ')
//		}
//	}
//	return buffer.String()
//}
//
//func containsStr(s []string, str string) bool {
//	for _, v := range s {
//		if strings.Contains(str, v) { //e.g. DNS returns str="abc.example.com" and v=".example.com"
//			return true
//		}
//	}
//
//	return false
//}

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

//func ip2Uint32(ip net.IP) uint32 {
//	//fmt.Println("ip len=", len(ip))
//	if len(ip) == 16 {
//		fatal("no sane way to convert ipv6 into uint32")
//	}
//	return binary.LittleEndian.Uint32(ip) //skb buff work on host endian, not network endian
//}

//func encodeUint32(val uint32) []byte {
//	b := make([]byte, 4)
//	binary.LittleEndian.PutUint32(b, val)
//	return b
//}

//func bytes2ip(bb []byte) net.IP {
//	ip := make(net.IP, 4)
//	binary.LittleEndian.PutUint32(ip, binary.LittleEndian.Uint32(bb[0:4]))
//	return ip
//}

//func bytes2ipv6(bb []byte) net.IP {
//	ip := make(net.IP, 16)
//	copy(ip, bb[0:16])
//	//binary.LittleEndian.PutUint32(ip, binary.LittleEndian.Uint32(bb[0:16]))
//	return ip
//}
//
//func determineHostByteOrder() binary.ByteOrder {
//	var i int32 = 0x01020304
//	u := unsafe.Pointer(&i)
//	pb := (*byte)(u)
//	b := *pb
//	if b == 0x04 {
//		return binary.LittleEndian
//	}
//
//	return binary.BigEndian
//}
