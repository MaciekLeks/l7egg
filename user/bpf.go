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
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

type Seg struct {
	CNs              []string
	CIDRs            []string
	IngressInterface string
	EgressInterface  string
	BPFObjectPath    string
}

type ipv4LPMKey struct {
	prefixLen uint32
	data      uint32
}

type ipv4LPMVal struct {
	ttl     uint64
	counter uint64
}

func (seg Seg) Run() {
	bpfModule, err := bpf.NewModuleFromFile(seg.BPFObjectPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	err = attachProg(bpfModule, seg.IngressInterface, bpf.BPFTcIngress, "tc_ingress")
	must(err, "Can't attach TC hook.")
	err = attachProg(bpfModule, seg.EgressInterface, bpf.BPFTcEgress, "tc_egress")
	must(err, "Can't attach TC hook.")

	packets := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("packets", packets)
	must(err, "Can't initialize ring buffer map.")

	rb.Start()

	//numberOfEventsReceived := 0
	go func() {
		time.Sleep(2 * time.Second)
		_, err := exec.Command("curl", "https://www.onet.pl").Output()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()

	acl, err := bpfModule.GetMap("ipv4_lpm_map")
	must(err, "Can't get map")

	sig := make(chan os.Signal, 0)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	//{cidrs
	fmt.Println("[ACL]: Init")
	for _, ipv4NetStr := range seg.CIDRs {
		_, ipv4Net, err := net.ParseCIDR(ipv4NetStr)
		must(err, "Can't parse ipv4 Net.")

		prefix, _ := ipv4Net.Mask.Size()
		ip := ipv4Net.IP.To4()
		//fmt.Println("-----mask: %d rest: %v", prefix, ipv4Net.IP)
		key := ipv4LPMKey{uint32(prefix), ip2Uint32(ip)}
		//tmpKey := ipv4LPMKey{32, ip2Uint32(ip)}
		//val := time.Now().Unix()
		//var val uint64 = 0 //means no TTL
		val := ipv4LPMVal{
			0,
			0,
		}

		err = updateACL(acl, key, val)
		must(err, "Can't update ACL.")
		//fmt.Println("tmpKeySize:", unsafe.Sizeof(tmpKey))
		//fmt.Println("tmpKey.data:", tmpKey.data)
	}
	//cidrs}

	//{show map
	go func() {
		for {
			time.Sleep(5 * time.Second)
			fmt.Printf("\n[ACL]:")
			i := acl.Iterator() //determineHost Endian search by Itertaot in libbfpgo
			for i.Next() {
				if i.Err() != nil {
					fatal("Iterator error", i.Err())
				}
				keyBytes := i.Key()
				prefixLen := binary.LittleEndian.Uint32(keyBytes[0:4])
				ipBytes := keyBytes[4:8]
				ip := bytes2ip(ipBytes)

				key := ipv4LPMKey{prefixLen, ip2Uint32(ip)}
				upKey := unsafe.Pointer(&key)
				valBytes, err := acl.GetValue(upKey)
				must(err, "Can't get value.")
				counter := binary.LittleEndian.Uint64(valBytes[8:16])
				ttl := binary.LittleEndian.Uint64(valBytes[0:8])
				val := ipv4LPMVal{
					ttl,
					counter,
				}
				bootNs := uint64(C.get_nsecs())
				//var expired string = fmt.Sprintf("%d-%d", bootNs, ttl)
				var expired string = " "
				if ttl != 0 && ttl < bootNs {
					//fmt.Printf("\nttl(%d)<bootNs(%d)=%t | ", ttl, bootNs, ttl < bootNs)
					expired = "x"
				}

				//valBytes := acl[ipv4LPMKey{1,1}]
				//fmt.Printf(" [bootTtlNs:%d,bootNs:%d][%s]%s/%d[%d]", ttl, bootNs, expired, ip, prefixLen, val.counter)
				fmt.Printf(" [%s]%s/%d[%d]", expired, ip, prefixLen, val.counter)

			}
		}

	}()

	//show}

recvLoop:

	for {
		select {
		case <-sig:
			fmt.Println("[recvLoop]: SIGnal came.")
			break recvLoop
		case b, ok := <-packets:
			if ok == false {
				fmt.Println("[recvLoop]: Channel not OK!")
				break recvLoop
			}

			skbLen := binary.LittleEndian.Uint32(b[0:4])

			//fmt.Printf("\n\nskb.len:%d, skb.", skbLen)
			data := b[4:(skbLen + 4)]
			//fmt.Println("Encoded packet:", insertNth(hex.EncodeToString(data), 2))

			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
			// Get the TCP layer from this packet

			//for _, l := range packet.Layers() {
			//	fmt.Println("Layer:", l.LayerType())
			//}

			var payload []byte
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				fmt.Println("This is a TCP packet!")
				// Get actual TCP data from this layer
				tcp, _ := tcpLayer.(*layers.TCP)
				fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)

				payload = tcp.Payload
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				fmt.Println("This is a UDP packet!")
				// Get actual TCP data from this layer
				udp, _ := udpLayer.(*layers.UDP)
				fmt.Printf("From src port %d to dst port %d\n", udp.SrcPort, udp.DstPort)

				payload = udp.Payload
			}

			dnsPacket := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
			if dnsLayer := dnsPacket.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				fmt.Println("This is a DNS packet!")
				// Get actual TCP data from this layer

				dns := dnsLayer.(*layers.DNS)
				questions := dns.Questions
				for _, q := range questions {
					fmt.Printf("Question: Name:%s Type:%s Class:%s\n", string(q.Name), q.Type, q.Class)
				}
				answers := dns.Answers
				for _, a := range answers {
					fmt.Printf("Type: %s, Answer: IP:%s Name:%s CName:%s\n", a.Type, a.IP, string(a.Name), string(a.CNAME))
					if a.Type == layers.DNSTypeA {

						cn := string(a.Name)
						ip := a.IP
						ttlSec := a.TTL //!!! remove * 5

						key := ipv4LPMKey{32, ip2Uint32(ip)}
						//val := time.Now().Unix() + int64(ttl) //Now + ttl
						ttlNs := uint64(ttlSec) * 1000000000
						bootTtlNs := uint64(C.get_nsecs()) + ttlNs //boot time[ns] + ttl[ns]
						//fmt.Println("key size:", unsafe.Sizeof(key))
						//fmt.Println("key data:", key.data)

						if contains(seg.CNs[:], cn) {
							////{check current value
							//upKey := unsafe.Pointer(&key)
							//valBytes, err := acl.GetValue(upKey)
							////check}

							val := ipv4LPMVal{
								bootTtlNs,
								0, //zero existsing elements :/
							}
							err = updateACL(acl, key, val)
							must(err, "Can't update ACL.")
							fmt.Printf("Updated for %s ip:%s DNS ttl:%d, ttlNs:%d, bootTtlNs:%d\n", cn, ip, ttlSec, ttlNs, bootTtlNs)

						} else {
							fmt.Println("DROP")
						}
					} else {
						fmt.Println("Anser.Type:", a.Type)

					}

				}
			}

			//numberOfEventsReceived++
			//
			//fmt.Println("[10]")
			//if numberOfEventsReceived > 3 {
			//	break recvLoop
			//}
		}
	}

	rb.Stop()
	rb.Close()
}

func unmarshalValue(bytes []byte) ipv4LPMVal {
	return ipv4LPMVal{
		ttl:     binary.LittleEndian.Uint64(bytes[0:8]),
		counter: binary.LittleEndian.Uint64(bytes[8:16]),
	}
}

func updateACL(acl *bpf.BPFMap, key ipv4LPMKey, val ipv4LPMVal) error {
	//alyternative way
	//aclKeyEnc := bytes.NewBuffer(encodeUint32(32))
	//aclKeyEnc.Write(encodeUint32(ip2Uint32(ip)))
	//aclValEnc := encodeUint32(1)
	//fmt.Printf("IP:%s val:%d, hex:%x\n", ip, ip2Uint32(ip), ip2Uint32(ip))
	//fmt.Printf("Key:%s val:%s\n", insertNth(hex.EncodeToString(aclKeyEnc.Bytes()), 2), insertNth(hex.EncodeToString(aclValEnc), 2))
	//acl.Update(&aclKeyEnc.Bytes, &aclValEnc)

	upKey := unsafe.Pointer(&key)
	//check if not exists first
	oldValBytes, err := acl.GetValue(upKey)
	var oldVal ipv4LPMVal
	if err == nil { //update in any cases
		fmt.Println("Key/Value exists.", key, oldValBytes)
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
		fmt.Printf("[updateACL] ACL updated for, key:%v, val:%v\n", key, val)
	}
	//!!} else {
	//!!	fmt.Printf("[updateACL] Key already exists in ACL, key:%v val:%v\n", key, binary.LittleEndian.Uint64(v))
	//!!}
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

func insertNth(s string, n int) string {
	var buffer bytes.Buffer
	var n_1 = n - 1
	var l_1 = len(s) - 1
	for i, rune := range s {
		buffer.WriteRune(rune)
		if i%n == n_1 && i != l_1 {
			buffer.WriteRune(' ')
		}
	}
	return buffer.String()
}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func ip2Uint32(ip net.IP) uint32 {
	//fmt.Println("ip len=", len(ip))
	if len(ip) == 16 {
		fatal("no sane way to convert ipv6 into uint32")
	}
	return binary.LittleEndian.Uint32(ip) //skb buff work on host endian, not network endian
}

func encodeUint32(val uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, val)
	return b
}

func bytes2ip(bb []byte) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, binary.LittleEndian.Uint32(bb[0:4]))
	return ip
}

func determineHostByteOrder() binary.ByteOrder {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
