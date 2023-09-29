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
	"github.com/MaciekLeks/l7egg/pkg/common"
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

// ebpfy holds Eggy (extracted from ClusterEggSpec) and ebpf related structures, e.g. maps, channels operating on that maps
type ebpfy struct {
	eggy *Eggy
	// Longest Match Prefix Map for ipv4
	ipv4ACL *bpf.BPFMap
	// Longest Match Prefix Map for ipv6
	ipv6ACL *bpf.BPFMap
	// DNS packets channel from kernel space
	packets chan []byte
	// link between ingress program and either tc or cgroup hook
	ingressLink *bpf.BPFLink
	// link between egress program and either tc or cgroup hook
	egressLink *bpf.BPFLink
}

var (
	endian binary.ByteOrder
)

func init() {
	endian = hostEndian()
}

func newEbpfy(eggi *Eggy) *ebpfy {
	var egg ebpfy
	egg.eggy = eggi
	return &egg
}

func (eby *ebpfy) stop() error {
	var ierr, eerr error

	if eby.ingressLink != nil {
		ierr = eby.ingressLink.Destroy()
	}
	if eby.egressLink != nil {
		eerr = eby.egressLink.Destroy()
	}

	if ierr != nil || eerr != nil {
		return fmt.Errorf("Can't destroy BPF link: ingress: %s, egress: %s", ierr, eerr)
	}

	return nil
}

// loadModule loads one eBPF per one egg
func (eby *ebpfy) loadModule(ctx context.Context) error {
	var err error

	logger := klog.FromContext(ctx)
	if eby.eggy.bpfModule == nil {
		logger.V(2).Info("Loading eBPF module", "file", BpfObjectFileName, "egg", eby.eggy.Name)

		eby.eggy.Lock()
		defer eby.eggy.Unlock()

		eby.eggy.bpfModule, err = bpf.NewModuleFromFile(BpfObjectFileName)
		if err != nil {
			return err
		}
		err = eby.eggy.bpfModule.BPFLoadObject()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load BPF object: %s\n", err)
			return err
		}
		logger.V(2).Info("eBPF module loaded", "file", BpfObjectFileName, "egg", eby.eggy.Name)
	}

	return nil
}

// run runs the ebpfy, and if neither nsNetPath nor cgroupPath is Set, it will run the ebpfy in the current network netspace (tc over cgroup
func (eby *ebpfy) run(ctx context.Context, wg *sync.WaitGroup, programType common.ProgramType, netNsPath string, cgroupPath string, pid uint32) error {
	var err error
	logger := klog.FromContext(ctx)

	err = eby.loadModule(ctx)
	if err != nil {
		return err
	}

	eby.eggy.RLock()
	defer eby.eggy.RUnlock()

	logger.Info("attaching eBPF program having", programType)
	err = eby.attachProgram(ctx, programType, netNsPath, cgroupPath)
	if err != nil {
		return err
	}

	eby.packets = make(chan []byte)

	rb, err := eby.eggy.bpfModule.InitRingBuf("packets", eby.packets)
	if err != nil {
		return fmt.Errorf("can't init ring buffer: %s", err)
	}

	rb.Poll(300)

	eby.ipv4ACL, err = eby.eggy.bpfModule.GetMap("ipv4_lpm_map")
	if err != nil {
		return fmt.Errorf("can't get map: %s", err)
	}
	eby.ipv6ACL, err = eby.eggy.bpfModule.GetMap("ipv6_lpm_map")
	if err != nil {
		return fmt.Errorf("can't get map: %s", err)
	}

	eby.initCIDRs()
	eby.initCNs()

	wg.Add(1)
	go func() {
		defer wg.Done() //added with new tc filter approach via go-tc
		//defer close(eby.packets) //TODO observe if this is needed
		//defer eby.bpfModule.Close() -> moved to eggy

		var lwg sync.WaitGroup
		//runMapLooper(ctx, ebpfy.ipv4ACL, ebpfy.CommonNames, ipv4, &lwg, netNsPath, cgroupPath)
		//runMapLooper(ctx, ebpfy.ipv6ACL, ebpfy.CommonNames, ipv6, &lwg, netNsPath, cgroupPath)
		eby.runPacketsLooper(ctx, &lwg, netNsPath, cgroupPath)
		lwg.Wait()

		fmt.Println("///Stopping recvLoop.") //TODO: refactor
		rb.Stop()
		rb.Close()
		fmt.Println("recvLoop stopped.") //TODO: refactor
	}()

	return nil
}

// attachProgram attaches eBPF program to either tc hook or cgroup hook
func (eby *ebpfy) attachProgram(ctx context.Context, programType common.ProgramType, netNsPath string, cgroupPath string) error {
	var err error
	logger := klog.FromContext(ctx)

	if programType == common.ProgramTypeTC {
		err = attachTcBpfIngressStack(eby.eggy.bpfModule, eby.eggy.EgressInterface, netNsPath)
		if err != nil {
			return fmt.Errorf("can't attach egress tc hook: %s", err)
		}
		err = attachTcBpfEgressStack(eby.eggy.bpfModule, eby.eggy.EgressInterface, netNsPath, eby.eggy.Shaping)
		if err != nil {
			return fmt.Errorf("can't attach egress tc hook: %s", err)
		}
		logger.Info("eBPF program of tc type hooked")
	} else {
		var link *bpf.BPFLink
		link, err = attachCgroupProg(ctx, eby.eggy.bpfModule, BpfCgroupIngressProgram, bpf.BPFAttachTypeCgroupInetEgress, cgroupPath)
		if err != nil {
			return fmt.Errorf("can't attach egress cgroup hook: %s", err)
		}
		eby.egressLink = link
		link, err = attachCgroupProg(ctx, eby.eggy.bpfModule, BpfCgroupEgressProgram, bpf.BPFAttachTypeCgroupInetIngress, cgroupPath)
		if err != nil {
			return fmt.Errorf("can't attach ingress cgroup hook: %s", err)
		}
		eby.ingressLink = link

		logger.Info("eBPF program of cgroup type hooked")
	}
	return err
}

func (eby *ebpfy) initCIDRs() {
	//{cidrs
	fmt.Println("[ACL]: Init")
	for i := 0; i < len(eby.eggy.Cidrs); i++ {
		cidr := eby.eggy.Cidrs[i]
		val := ipLPMVal{
			ttl:     0,
			counter: 0,
			id:      cidr.Value.id, //test
			status:  uint8(common.AssetSynced),
		}

		var err error
		switch ip := cidr.Value.lpmKey.(type) {
		case ipv4LPMKey:
			err = updateACLValueNew(eby.ipv4ACL, ip, val)
		case ipv6LPMKey:
			err = updateACLValueNew(eby.ipv6ACL, ip, val)
		}
		must(err, "Can't update ACL.")
	}

	//eby.eggy.UpdateCidrStatus(common.AssetSynced)
}

// initCNs
func (eby *ebpfy) initCNs() {
	//eby.eggy.UpdateCommonNamesStatus(common.AssetSynced)
}

func (eby *ebpfy) updateCIDRs() error {
	// ipv4: Set stale
	i := eby.ipv4ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	if i.Err() != nil {
		return fmt.Errorf("BPF Map Iterator error", i.Err())
	}
	for i.Next() {
		fmt.Println("%%%>>>4.2")
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(eby.ipv4ACL, key)

		//we control CidrWithPort with ttl=0 only
		if val.ttl == 0 {
			for i := 0; i < len(eby.eggy.Cidrs); i++ {
				cidr := eby.eggy.Cidrs[i]
				ipv4Key, ok := cidr.Value.lpmKey.(ipv4LPMKey)
				if ok {
					if key.prefixLen == ipv4Key.prefixLen && key.data == ipv4Key.data {
						if cidr.Status == common.AssetStale {
							val.status = uint8(common.AssetStale)
							err := updateACLValueNew(eby.ipv4ACL, key, val)
							if err != nil {
								return fmt.Errorf("Updating value status", eby)
							}
						}
					}
				}
			}
		}
	}
	// ipv6: Set stale
	i = eby.ipv6ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	if i.Err() != nil {
		return fmt.Errorf("BPF Map Iterator error", i.Err())
	}
	for i.Next() {
		fmt.Println("%%%>>>4.2")
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv6ACLKey(keyBytes)
		val := getACLValue(eby.ipv6ACL, key)

		//we control CidrWithPort with ttl=0 only
		if val.ttl == 0 {
			for i := 0; i < len(eby.eggy.Cidrs); i++ {
				cidr := eby.eggy.Cidrs[i]
				ipv6Key, ok := cidr.Value.lpmKey.(ipv6LPMKey)
				if ok {
					if key.prefixLen == ipv6Key.prefixLen && key.data == ipv6Key.data {
						if cidr.Status == common.AssetStale {

							val.status = uint8(common.AssetStale)
							err := updateACLValueNew(eby.ipv6ACL, key, val)
							if err != nil {
								return fmt.Errorf("Updating value status", eby)
							}
						}
					}
				}
			}
		}
	}

	//add
	for _, cidr := range eby.eggy.Cidrs {
		if cidr.Status == common.AssetNew {
			val := ipLPMVal{
				ttl:     0,
				counter: 0,
				status:  uint8(common.AssetSynced),
			}

			err := updateACLValueNew(eby.ipv4ACL, cidr.Value.lpmKey, val)
			if err != nil {
				return fmt.Errorf("Can't update ACL %#v", err)
			}
		}
	}

	//eby.eggy.UpdateCidrStatus(common.AssetSynced)

	return nil
}

func (eby *ebpfy) updateCNs() error {
	// delete
	i := eby.ipv4ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	if i.Err() != nil {
		return fmt.Errorf("BPF Map Iterator error", i.Err())
	}
	for i.Next() {
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(eby.ipv4ACL, key)

		//we control CommonNames with ttl!=0 only
		if val.ttl != 0 {
			fmt.Println("%%%>>> Found ttl!=0")
			for i := 0; i < len(eby.eggy.CommonNames); i++ {
				current := eby.eggy.CommonNames[i]
				if val.id == current.Value.id {
					if current.Status == common.AssetStale {
						fmt.Println("%%%>>> current.Status is Stale")
						val.status = uint8(common.AssetStale)
						err := updateACLValueNew(eby.ipv4ACL, key, val) //invalidate all IPs for stale CommonNames
						if err != nil {
							return fmt.Errorf("Updating value status", eby)
						}
					}
				}
			}
		}
	}

	i = eby.ipv6ACL.Iterator() //determineHost Endian search by Itertaot in libbfpgo
	if i.Err() != nil {
		return fmt.Errorf("BPF Map Iterator error", i.Err())
	}
	for i.Next() {
		if i.Err() != nil {
			return fmt.Errorf("BPF Map Iterator error", i.Err())
		}

		keyBytes := i.Key()
		key := unmarshalIpv4ACLKey(keyBytes)
		val := getACLValue(eby.ipv4ACL, key)

		//we control CommonNames with ttl!=0 only
		if val.ttl != 0 {
			fmt.Println("%%%>>> Found ttl!=0")
			for i := 0; i < len(eby.eggy.CommonNames); i++ {
				current := eby.eggy.CommonNames[i]
				if val.id == current.Value.id {
					if current.Status == common.AssetStale {
						fmt.Println("%%%>>> current.Status is Stale")
						val.status = uint8(common.AssetStale)
						err := updateACLValueNew(eby.ipv4ACL, key, val) //invalidate all IPs for stale CommonNames
						if err != nil {
							return fmt.Errorf("Updating value status", eby)
						}
					}
				}
			}
		}
	}

	//eby.eggy.UpdateCommonNamesStatus(common.AssetSynced)

	return nil
}

func (eby *ebpfy) runPacketsLooper(ctx context.Context, lwg *sync.WaitGroup, netNsPath string, cgroupPath string) {
	lwg.Add(1)
	go func() {
		defer lwg.Done()
		defer fmt.Println("runPacketsLooper terminated")
	recvLoop:

		for {
			select {
			case <-ctx.Done():
				fmt.Println("[recvLoop]: stopCh closed.")
				break recvLoop
			case b, ok := <-eby.packets:
				if ok == false {
					fmt.Println("[recvLoop]: Channel not OK!")
					break recvLoop
				}

				skbLen := endian.Uint32(b[0:4])

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

							commonName := string(a.Name)
							if cn, found := containsCN(eby.eggy.CommonNames, commonName); found {
								ip := a.IP
								ttlSec := a.TTL //!!! remove * 5
								var key ILPMKey

								for i := range eby.eggy.Ports {
									port := eby.eggy.Ports[i].Value.port
									if a.Type == layers.DNSTypeA {
										key = ipv4LPMKey{32, port, [4]uint8(ip[0:4])}
									} else {
										key = ipv6LPMKey{128, port, [16]uint8(ip[0:16])}
									}
									//val := time.Now().Unix() + int64(ttl) //Now + ttl
									ttlNs := uint64(ttlSec) * 1000000000
									bootTtlNs := uint64(C.get_nsecs()) + ttlNs //boot time[ns] + ttl[ns]
									//fmt.Println("key size:", unsafe.Sizeof(key))
									//fmt.Println("key data:", key.data)

									val := ipLPMVal{
										ttl:     bootTtlNs,
										counter: 0, //zero existsing elements :/ //TODO why 0?
										id:      cn.Value.id,
										status:  uint8(common.AssetSynced),
									}
									var err error
									if a.Type == layers.DNSTypeA {
										err = updateACLValueNew(eby.ipv4ACL, key, val)
									} else {
										err = updateACLValueNew(eby.ipv6ACL, key, val)
									}
									must(err, "Can't update ACL.")
									fmt.Printf("ebpfy-ref: %p, netNsPath: %s cgroupPath: %s - updated for %s ip:%s DNS ttl:%d, ttlNs:%d, bootTtlNs:%d\n", eby, netNsPath, cgroupPath, cn, ip, ttlSec, ttlNs, bootTtlNs)
								}

							} else {
								fmt.Println("DROP")
							}
						}
					}
				} else {
					fmt.Println("This is not a DNS packet!:/")
				}
			}
		}
	}()
}

func runMapLooper(ctx context.Context, bpfM *bpf.BPFMap, cns *syncx.SafeSlice[CommonName], ipv ipProtocolVersion, lwg *sync.WaitGroup, netNsPath string, cgroupPath string) {
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
					prefixLen := endian.Uint32(keyBytes[0:4])
					port := endian.Uint16(keyBytes[4:6]) //port

					var key ILPMKey
					var ipB []byte
					if ipv == ipv4 {
						ipB = keyBytes[6:10]
						//ip := bytes2ip(ipBytes)
						key = ipv4LPMKey{prefixLen, port, [4]uint8((ipB))}
					} else {
						ipB = keyBytes[6:22]
						//ip := bytes2ip(ipBytes)
						key = ipv6LPMKey{prefixLen, port, [16]uint8((ipB))}
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
	prefixLen := endian.Uint32(bytes[0:4])
	port := endian.Uint16(bytes[4:6])
	ipB := bytes[6:10]

	return ipv4LPMKey{prefixLen, port, [4]uint8(ipB)}
}

func unmarshalIpv6ACLKey(bytes []byte) ipv6LPMKey {
	prefixLen := endian.Uint32(bytes[0:4])
	port := endian.Uint16(bytes[4:6])
	ipBytes := bytes[6:22]

	return ipv6LPMKey{prefixLen, port, [16]uint8(ipBytes)}
}

func getACLValue(acl *bpf.BPFMap, ikey ILPMKey) ipLPMVal {
	upKey := ikey.GetPointer()
	valBytes, err := acl.GetValue(upKey)
	must(err, "Can't get value.")
	return unmarshalValue(valBytes)
}

func unmarshalValue(bytes []byte) ipLPMVal {
	return ipLPMVal{
		ttl:     endian.Uint64(bytes[0:8]),
		counter: endian.Uint64(bytes[8:16]),
		id:      endian.Uint16(bytes[16:18]),
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

func containsCN(cns common.AssetList[CommonName], cnS string) (common.Asset[CommonName], bool) {
	var current common.Asset[CommonName]
	for i := 0; i < cns.Len(); i++ {
		current = cns[i]
		fmt.Printf("))) current=%#v cnS=%s\n", current, cnS)
		if current.Status == common.AssetSynced && strings.Contains(cnS, current.Value.cn) { //e.g. DNS returns cnS="abc.example.com" and current.cn=".example.com"
			fmt.Printf(" ^ found\n")
			return current, true
		}
	}
	fmt.Printf(" ^ not-found\n")
	return current, false
}

func hostEndian() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
