//+build ignore
#include "vmlinux.h"
//#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//#include <linux/if_ether.h>
//#include <linux/in.h>
//#include <linux/ip.h>
//#include <linux/udp.h>
//#include <linux/tcp.h>
//#include <linux/filter.h>

#define ETH_HLEN 14        /* Total octets in header.	 */
#define ETH_P_IPv4 0x0800
#define ETH_P_IPv6 0x86DD
#define ETH_FRAME_LEN 1514
#define DNS_HLEN 12

#define IP_SYNCED 0
#define IP_STALE 1

//#define TC_ACT_OK 0 // will terminate the packet processing pipeline and allows the packet to proceed
#define TC_ACT_OK -1 // will use the default action configured from tc
#define TC_ACT_SHOT 2 // will terminate the packet processing pipeline and drops the packet
#define TC_ACT_UNSPEC -1  //will use the default action configured from tc (similarly as returning -1 from a classifier)
#define TC_ACT_PIPE 3 //will iterate to the next action, if available
#define TC_ACT_RECLASSIFY 1  //will terminate the packet processing pipeline and start classification from the beginning
#define TC_MOVE_ONE -3 //local code to move further

#define TC_H_MAKE(maj, min) ((maj) << 16 | (min))

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#if defined DEBUG && DEBUG == 0
#define bpf_printk(fmt,...)
#endif

//DNS header structure
struct dnshdr {
    __u16 id; // identification number

    __u8 rd: 1; // recursion desired
    __u8 tc: 1; // truncated message
    __u8 aa: 1; // authoritive answer
    __u8 opcode: 4; // purpose of message
    __u8 qr: 1; // query/response flag

    __u8 rcode: 4; // response code
    __u8 cd: 1; // checking disabled
    __u8 ad: 1; // authenticated data
    __u8 z: 1; // its z! reserved
    __u8 ra: 1; // recursion available

    __u16 q_count; // number of question entries
    __u16 ans_count; // number of answer entries
    __u16 auth_count; // number of authority entries
    __u16 add_count; // number of resource entries
};

struct packet {
    __u32 len;
    __u8 data[ETH_FRAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packets SEC(".maps");

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
}  __attribute__((packed));

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 data[16];
}  __attribute__((packed));

struct value_t {
    __u64 ttl;
    __u64 counter;
    __u16 id;
    __u8 status; //0 - synced, 1 - stale
}  __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct value_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipv4_lpm_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, struct value_t);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
} ipv6_lpm_map SEC(".maps");


//struct {
//    __uint(type, BPF_MAP_TYPE_RINGBUF);
//    //__type(value, struct packet);
//    __uint(max_entries, 1 << 24);
//} events_dns SEC(".maps");
//

long ringbuffer_flags = 0;

static __always_inline void *ipv4_lookup(__u32 ipaddr) {
    struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .data = ipaddr
    };

    return bpf_map_lookup_elem(&ipv4_lpm_map, &key);
}

static __always_inline void *ipv6_lookup(__u8 ipaddr[16]) {
    long err;
    struct ipv6_lpm_key key = {
            .prefixlen = 128,
    };

    //TODO: do we need deep copy of the ipaddr for searching?
    err = bpf_probe_read_kernel(key.data, 16, ipaddr); //bpf_probe_read->bpf_probe_read_kernel
    if (err != 0) {
        bpf_printk("Can't copy memory %d", err);
        return NULL;
    }

    return bpf_map_lookup_elem(&ipv6_lpm_map, &key);
}

static __always_inline long ipv4_update(__u32 ipaddr, struct value_t val) {
    struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .data = ipaddr
    };

    return bpf_map_update_elem(&ipv4_lpm_map, &key, &val, BPF_EXIST);
}

static __always_inline long ipv6_update(__u8 ipaddr[16], struct value_t val) {
    long err;
    struct ipv6_lpm_key key = {
            .prefixlen = 128,
            //   .data = ipaddr
    };

    err = bpf_probe_read_kernel(key.data, 16, ipaddr); //bpf_probe_read->bpf_probe_read_kernel
    if (err != 0) {
        bpf_printk("Can't copy memory %d", err);
        return -1; //error
    }

    return bpf_map_update_elem(&ipv6_lpm_map, &key, &val, BPF_EXIST);
}

static __always_inline void ipv4_print_ip(char *prefix, char *suffix, __u32 ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    bpf_printk("%s:%d.%d.%d.%d%s", prefix, bytes[0], bytes[1], bytes[2], bytes[3], suffix);
}

static __always_inline void ipv6_print_ip(char *str, const __u8 *ipv6) {
    unsigned char bytes[16];
    bytes[0] = ipv6[0];
    bytes[1] = ipv6[1];
    bytes[2] = ipv6[2];
    bytes[3] = ipv6[3];
    bytes[4] = ipv6[4];
    bytes[5] = ipv6[5];
    bytes[6] = ipv6[6];
    bytes[7] = ipv6[7];
    bytes[8] = ipv6[8];
    bytes[9] = ipv6[9];
    bytes[10] = ipv6[10];
    bytes[11] = ipv6[11];
    bytes[12] = ipv6[12];
    bytes[13] = ipv6[13];
    bytes[14] = ipv6[14];
    bpf_printk("%s: %d%d:%d%d", str, bytes[0], bytes[1], bytes[2], bytes[3]);
    bpf_printk(":%d%d:%d%d", bytes[4], bytes[5], bytes[6], bytes[7]);
    bpf_printk(":%d%d:%d%d", bytes[8], bytes[9], bytes[10], bytes[11]);
    bpf_printk(":%d%d:%d%d\n", bytes[12], bytes[13], bytes[14], bytes[15]);
}

static __always_inline int ipv4_check_and_update(struct iphdr *ipv4) {
    __u32 daddr = ipv4->daddr;
    __u32 saddr = ipv4->saddr;
    bpf_printk("[egress]: daddr:%u, saddr:%u", daddr, saddr);
    void *pv = ipv4_lookup(daddr);
    if (!pv) {
        bpf_printk("[egress]: drop:%u", daddr);
        ipv4_print_ip("[egress] DROP", "\n", daddr);
        return TC_ACT_SHOT;
    }
    //}egress gate
    struct value_t *pval = pv;
    // does not process STALE IPs
    if (pval->status == IP_STALE) {
        ipv4_print_ip("[egress] STALE, DROP", "\n", daddr);
        return TC_ACT_SHOT;
    }
    __u64 boot_plus_ttl_ns = pval->ttl;
    __u64 boot_ns = bpf_ktime_get_boot_ns();
    if (boot_plus_ttl_ns != 0 && boot_plus_ttl_ns < boot_ns) { //0 means no TTL
        bpf_printk("[egress]: TTL expired:%u, boot_plus_ttl_ns:%u boot_ns:%u", daddr, boot_plus_ttl_ns, boot_ns);
        ipv4_print_ip("[egress] DROP_TTL", "\n", daddr);
        return TC_ACT_SHOT;
    }
    pval->counter = pval->counter + 1; //it would not work /24 subnet and /32 ip addr
    long ret = ipv4_update(daddr, *pval); //it creates /32 ip addr if you hit some subnet e.g. /24
    if (ret) {
        bpf_printk("[egress]: can't update counter, code:%d", ret);
    } else {
        bpf_printk("[egress]: Counter updated");
    }
    bpf_printk("[egress]: accept:%u, boot_plus_ttl_ns:%u boot_ns:%u", daddr, boot_plus_ttl_ns, boot_ns);
    ipv4_print_ip("[egress] ACCEPT", "\n", daddr);

    return TC_MOVE_ONE; //process further inside bpf
}

static __always_inline int ipv6_check_and_update(struct ipv6hdr *ipv6) {
    struct in6_addr daddr = ipv6->daddr;
    struct in6_addr saddr = ipv6->saddr;
    // bpf_printk("[egress]: daddr:%u, saddr:%u", daddr.in6_u.u6_addr8, saddr.in6_u.u6_addr8);
    void *pv = ipv6_lookup(daddr.in6_u.u6_addr8);
    if (!pv) {
        //   bpf_printk("[egress]: drop:%u", daddr.in6_u.u6_addr8);
        ipv6_print_ip("[egress] DROP", daddr.in6_u.u6_addr8);
        return TC_ACT_SHOT;
    }
    //}egress gate
    struct value_t *pval = pv;
    // does not process STALE IPs
    if (pval->status == IP_STALE) {
        ipv6_print_ip("[egress] STALE, DROP", daddr.in6_u.u6_addr8);
        return TC_ACT_SHOT;
    }
    __u64 boot_plus_ttl_ns = pval->ttl;
    __u64 boot_ns = bpf_ktime_get_boot_ns();
    if (boot_plus_ttl_ns != 0 && boot_plus_ttl_ns < boot_ns) { //0 means no TTL
        //    bpf_printk("[egress]: TTL expired:%u, boot_plus_ttl_ns:%u boot_ns:%u", daddr.in6_u.u6_addr8, boot_plus_ttl_ns, boot_ns);
        ipv6_print_ip("[egress] DROP_TTL", daddr.in6_u.u6_addr8);
        return TC_ACT_SHOT;
    }
    pval->counter = pval->counter + 1; //it would not work /24 subnet and /32 ip addr
    long ret = ipv6_update(daddr.in6_u.u6_addr8, *pval); //it creates /32 ip addr if you hit some subnet e.g. /24
    if (ret) {
        bpf_printk("[egress]: can't update counter, code:%d", ret);
    } else {
        bpf_printk("[egress]: Counter updated");
    }
    //  bpf_printk("[egress]: accept:%u, boot_plus_ttl_ns:%u boot_ns:%u", daddr.in6_u.u6_addr8, boot_plus_ttl_ns, boot_ns);
    ipv6_print_ip("[egress] ACCEPT", daddr.in6_u.u6_addr8);

    return TC_MOVE_ONE; //process further inside bpf
}


// depreciated - use process_relative instead
static __always_inline int process(struct __sk_buff *skb, bool is_egress) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    int off;
    bool is_ipv6 = false;
    __u8 protocol;

    //implement TC_H_MAKE
    //skb->tc_classid = TC_H_MAKE(10, 3); //set classid to 1:0

    //L2
    if (data + ETH_HLEN > data_end)
        return 0;

    bpf_printk("[process] /1");
    /* for easy access we re-use the Kernel's struct definitions */
    struct ethhdr *eth = data;
    /* Only actual IP packets are allowed */
    if (eth->h_proto == bpf_htons(ETH_P_IPv6)) {
        bpf_printk("[IPv6] --- ipv6");
        is_ipv6 = true;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPv4)) {
        bpf_printk("[IPv4] --- ipv4");
    } else {
        return 0;
    }

    bpf_printk("[process] /2");

    //L3
    off = ETH_HLEN;


    //struct iphdr *ip = (data + off);
    __u8
    version = *(__u8 * )(
    long)(data + off) & 0xF0 >> 2;
    if (data + off + sizeof(__u8) > data_end) {
        return 0;
    }
    if (is_ipv6 && version != 6) {
        bpf_printk("[IPv6] --- version:%d", version);
        return 0;
    } else if (version != 4) {
        bpf_printk("[IPv4] --- version:%d!=%d", version, 4);
        return 0;
    }


    bpf_printk("[process] /3");

    __u16 ihl;
    if (!is_ipv6) {
        struct iphdr *ipv4 = (data + off);
        if (data + off + sizeof(struct iphdr) > data_end)
            return 0;
        ihl = (ipv4->ihl & 0xF) << 2;
        if (data + off + ihl > data_end)
            return 0;
        protocol = ipv4->protocol;
        bpf_printk("[IPv4] --- protocol:%d", protocol);
    } else {
        struct ipv6hdr *ipv6 = data + off;
        ihl = sizeof(struct ipv6hdr);
        if (data + off + ihl > data_end) {
            return 0;
        }
        protocol = ipv6->nexthdr;
        bpf_printk("[IPv6] --- protocol:%d", protocol);
    }

    bpf_printk("[process] /4");
//    //TODO done to this place
//    if (is_ipv6) {
//        return 0; //TODO REMOVE
//    }

    // ip header pointer to either iphdr or ipv6hdr
    struct iphdr *ip = (data + off);

    bpf_printk("[process] /5");
    //L4
    __u16 sport = 0;
    __u16 dport = 0;
    off += ihl;
    /* We handle only UDP traffic */
    if (protocol == IPPROTO_UDP) {
        if (data + off + sizeof(struct udphdr) > data_end)
            return 0;

        struct udphdr *udp = (data + off);
        off += sizeof(struct udphdr);

        // bpf_printk("ip.protocol:%d, ihl:%d, off:%d", ip->protocol, ihl, ETH_HLEN + ihl);
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        bpf_printk("[UDP] sport:%d, dport:%d", sport, dport);
    } else if (protocol == IPPROTO_TCP) {
        if (data + off + sizeof(struct tcphdr) > data_end)
            return 0;

        struct tcphdr *tcp = (data + off);
        off += sizeof(struct tcphdr);


        //bpf_printk("ip.protocol:%d, ihl:%d, off:%d", ip->protocol, ihl, ETH_HLEN + ihl);

        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);

        bpf_printk("[TCP] sport:%d, dport:%d", sport, dport);
    } else
        return 0;

    bpf_printk("[process] /6");

    //TODO: what about different ports? see: https://stackoverflow.com/questions/7565300/identifying-dns-packets
    if (sport != 53 && dport != 53) {

        if (is_egress) {
            int ret;
            if (!is_ipv6) {
                ret = ipv4_check_and_update((struct iphdr *) ip);
            } else {
                ret = ipv6_check_and_update((struct ipv6hdr *) ip);
            }

            bpf_printk("[process] /6.1 ret:%d", ret);

            if (ret != TC_MOVE_ONE)
                return ret;
        }
        bpf_printk("[process] /6.2 before 0");
        return 0;

    }

    bpf_printk("[process] /7");
//    // Reserve space on the ringbuffer for the sample
//    __u32 len = skb->len;
////    if (len > ETH_FRAME_LEN)
////        return 0;
//    __u32  len_size =sizeof(skb->len);

//    check only for dnq query
    if (is_egress && dport == 53) { //only answers matters
        const __u32 len = skb->len;
        if (len > ETH_FRAME_LEN)
            return 0;

        //{dns deep dive
        if (data + off + sizeof(struct dnshdr) > data_end)
            return 0;

        struct dnshdr *dnshp = (data + off);
        off += sizeof(struct dnshdr);
        bpf_printk("[DNS] q.header.flags|1 = rd:%u tc:%u opcode:%u qr:%u", dnshp->rd, dnshp->tc, dnshp->opcode,
                   dnshp->qr);
        bpf_printk("[DNS] q.header.flag|2 = rcode:%u cd:%u ad:%u z:%u", dnshp->rcode, dnshp->cd, dnshp->ad, dnshp->z);
        bpf_printk("[DNS] q.header.flag|3 = ra:%u", dnshp->ra);
        bpf_printk("[DNS] q. qdcount:%u nscount: %u, arcount:%u", bpf_htons(dnshp->q_count),
                   bpf_htons(dnshp->ans_count), bpf_htons(dnshp->add_count));
        //}dns
    }

    bpf_printk("[process] /8");

    if (!is_egress && sport == 53) { //only answers matters
        const __u32 len = skb->len;
        if (len > ETH_FRAME_LEN)
            return 0;

        //{dns deep dive
        if (data + off + sizeof(struct dnshdr) > data_end)
            return 0;

        struct dnshdr *dnshp = (data + off);
        off += sizeof(struct dnshdr);
        bpf_printk("[DNS] a.header.flags|1 = rd:%u tc:%u opcode:%u qr:%u", dnshp->rd, dnshp->tc, dnshp->opcode,
                   dnshp->qr);
        bpf_printk("[DNS] a.header.flag|2 = rcode:%u cd:%u ad:%u z:%u", dnshp->rcode, dnshp->cd, dnshp->ad, dnshp->z);
        bpf_printk("[DNS] a.header.flag|3 = ra:%u", dnshp->ra);
        bpf_printk("[DNS] a. qdcount:%u nscount: %u, arcount:%u", bpf_htons(dnshp->q_count),
                   bpf_htons(dnshp->ans_count), bpf_htons(dnshp->add_count));
        //}dns


        struct packet *valp;
        valp = bpf_ringbuf_reserve(&packets, sizeof(struct packet), ringbuffer_flags);
        if (!valp) {
            return 0;
        }

        //bpf_printk("[###] data[0]:%x,%x, len: %d", eth->h_dest[0], eth->h_dest[1], data_end - data);

        long err;
        valp->len = len;
        err = bpf_probe_read_kernel(valp->data, len, data); //ok
        //err = bpf_skb_load_bytes(skb, 0, &valp->data[0], len); //ok
        if (err) { //!err -> err
            bpf_ringbuf_discard(valp, ringbuffer_flags); //memory not consumed
            return 0;
        }


        bpf_printk("[DNS] packet added into packets ringbuffer");

        //bpf_printk("[!!!] len:%d, data:%x, valp.data:%x ", valp->len, *(__u8 *) (long) data, valp->data[0]);

        bpf_ringbuf_submit(valp, ringbuffer_flags);
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// packet processing for either tc o cgroup programs; cgroup skb->data points to L3 header while in tc to L2
static __always_inline int
process_relative(struct __sk_buff *skb, enum bpf_hdr_start_off hdr_start_off, bool is_egress) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;
    int off = 0;
    bool is_ipv6 = false;
    __u8 protocol;

    // specific class for the
    //skb->tc_classid = TC_H_MAKE(10,10);
    //skb->tc_classid = 0xA000A;

    //L2
    bpf_printk("[process] /1");

    // common for all hdr_start_off(s)
    if (skb->protocol == bpf_htons(ETH_P_IPv6)) {
        bpf_printk("[IPv6] --- ipv6");
        is_ipv6 = true;
    } else if (skb->protocol == bpf_htons(ETH_P_IPv4)) {
        bpf_printk("[IPv4] --- ipv4");
    } else {
        bpf_printk("[???] --- L3 protocol not known");
        return 1;
    }

    if (hdr_start_off == BPF_HDR_START_MAC) {
        if (data + ETH_HLEN > data_end)
            return 0;
        off = ETH_HLEN; //off for tc must be moved ETH_HLEN octets forward
    }

    //L3
    bpf_printk("[process] /2");


    //struct iphdr *ip = (data + off);
    __u8 version = *(__u8 * )(
    long)(data + off) & 0xF0 >> 2;
    if (data + off + sizeof(__u8) > data_end) {
        return 0;
    }
    if (is_ipv6 && version != 6) {
        bpf_printk("[IPv6] --- version:%d", version);
        return 0;
    } else if (version != 4) {
        bpf_printk("[IPv4] --- version:%d!=%d", version, 4);
        return 0;
    }


    bpf_printk("[process] /3");

    __u16 ihl;
    if (!is_ipv6) {
        struct iphdr *ipv4 = (data + off);
        if (data + off + sizeof(struct iphdr) > data_end)
            return 0;
        ihl = (ipv4->ihl & 0xF) << 2;
        if (data + off + ihl > data_end)
            return 0;
        protocol = ipv4->protocol;
        bpf_printk("[IPv4] --- protocol:%d", protocol);
    } else {
        struct ipv6hdr *ipv6 = data + off;
        ihl = sizeof(struct ipv6hdr);
        if (data + off + ihl > data_end) {
            return 0;
        }
        protocol = ipv6->nexthdr;
        bpf_printk("[IPv6] --- protocol:%d", protocol);
    }

    bpf_printk("[process] /4");
//    //TODO done to this place
//    if (is_ipv6) {
//        return 0; //TODO REMOVE
//    }

    // ip header pointer to either iphdr or ipv6hdr
    struct iphdr *ip = (data + off);

    bpf_printk("[process] /5");
    //L4
    __u16 sport = 0;
    __u16 dport = 0;
    off += ihl;
    /* We handle only UDP traffic */
    if (protocol == IPPROTO_UDP) {
        if (data + off + sizeof(struct udphdr) > data_end)
            return 0;

        struct udphdr *udp = (data + off);
        off += sizeof(struct udphdr);

        // bpf_printk("ip.protocol:%d, ihl:%d, off:%d", ip->protocol, ihl, ETH_HLEN + ihl);
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        bpf_printk("[UDP] sport:%d, dport:%d", sport, dport);
    } else if (protocol == IPPROTO_TCP) {
        if (data + off + sizeof(struct tcphdr) > data_end)
            return 0;

        struct tcphdr *tcp = (data + off);
        off += sizeof(struct tcphdr);


        //bpf_printk("ip.protocol:%d, ihl:%d, off:%d", ip->protocol, ihl, ETH_HLEN + ihl);

        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);

        bpf_printk("[TCP] sport:%d, dport:%d", sport, dport);
    } else
        return 0;

    bpf_printk("[process] /6");

    //TODO: what about different ports? see: https://stackoverflow.com/questions/7565300/identifying-dns-packets
    if (sport != 53 && dport != 53) {

        if (is_egress) {
            int ret;
            if (!is_ipv6) {
                ret = ipv4_check_and_update((struct iphdr *) ip);
            } else {
                ret = ipv6_check_and_update((struct ipv6hdr *) ip);
            }

            if (ret != TC_MOVE_ONE)
                return ret;
        }
        return 0;

    }

    bpf_printk("[process] /7");
//    // Reserve space on the ringbuffer for the sample
//    __u32 len = skb->len;
////    if (len > ETH_FRAME_LEN)
////        return 0;
//    __u32  len_size =sizeof(skb->len);

//    check only for dnq query
    if (is_egress && dport == 53) { //only answers matters
        const __u32 len = skb->len;
        if (len > ETH_FRAME_LEN)
            return 0;

        //{dns deep dive
        if (data + off + sizeof(struct dnshdr) > data_end)
            return 0;

        struct dnshdr *dnshp = (data + off);
        off += sizeof(struct dnshdr);
        bpf_printk("[DNS] q.header.flags|1 = rd:%u tc:%u opcode:%u qr:%u", dnshp->rd, dnshp->tc, dnshp->opcode,
                   dnshp->qr);
        bpf_printk("[DNS] q.header.flag|2 = rcode:%u cd:%u ad:%u z:%u", dnshp->rcode, dnshp->cd, dnshp->ad, dnshp->z);
        bpf_printk("[DNS] q.header.flag|3 = ra:%u", dnshp->ra);
        bpf_printk("[DNS] q. qdcount:%u nscount: %u, arcount:%u", bpf_htons(dnshp->q_count),
                   bpf_htons(dnshp->ans_count), bpf_htons(dnshp->add_count));
        //}dns
    }

    bpf_printk("[process] /8");

    if (!is_egress && sport == 53) { //only answers matters
        __u32 len = skb->len;


        //{dns deep dive
        if (data + off + sizeof(struct dnshdr) > data_end)
            return 0;

        struct dnshdr *dnshp = (data + off);
        off += sizeof(struct dnshdr);
        bpf_printk("[DNS] a.header.flags|1 = rd:%u tc:%u opcode:%u qr:%u", dnshp->rd, dnshp->tc, dnshp->opcode,
                   dnshp->qr);
        bpf_printk("[DNS] a.header.flag|2 = rcode:%u cd:%u ad:%u z:%u", dnshp->rcode, dnshp->cd, dnshp->ad, dnshp->z);
        bpf_printk("[DNS] a.header.flag|3 = ra:%u", dnshp->ra);
        bpf_printk("[DNS] a. qdcount:%u nscount: %u, arcount:%u", bpf_htons(dnshp->q_count),
                   bpf_htons(dnshp->ans_count), bpf_htons(dnshp->add_count));
        //}dns


        struct packet *valp;
        valp = bpf_ringbuf_reserve(&packets, sizeof(struct packet), ringbuffer_flags);
        if (!valp) {
            return 0;
        }

        //bpf_printk("[###] data[0]:%x,%x, len: %d", eth->h_dest[0], eth->h_dest[1], data_end - data);

        long err;
        if (hdr_start_off == BPF_HDR_START_MAC) {
            bpf_printk("[DNS]  len=%d", len);
            if (len > ETH_FRAME_LEN) {
                len = ETH_FRAME_LEN;
            }
            err = bpf_probe_read_kernel(valp->data, len, data); //ok
        } else {
            bpf_printk("[DNS] before len=%d", len);
            len += ETH_HLEN; //cgroup_skb program skb->len does not contain ETH_HLEN
            bpf_printk("[DNS] after len=%d",len);
            if (len > ETH_FRAME_LEN) {
                len = ETH_FRAME_LEN;
            }
            if (len < 1) {
                len = 1; //see: https://stackoverflow.com/questions/76371104/bpf-skb-load-bytes-array-loading-when-len-could-be-0-invalid-access-to-memor
            }
            err = bpf_skb_load_bytes_relative(skb, 0, valp->data, len, BPF_HDR_START_MAC);
        }
        if (err) { //!err -> err
            bpf_ringbuf_discard(valp, ringbuffer_flags); //memory not consumed
            return 0;
        }


        bpf_printk("[DNS] packet added into packets ringbuffer len=%d", len);

        //bpf_printk("[!!!] len:%d, data:%x, valp.data:%x ", valp->len, *(__u8 *) (long) data, valp->data[0]);

        valp->len = len;
        bpf_ringbuf_submit(valp, ringbuffer_flags);
    }

    return 0;
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    //return process(skb, false);
    return process_relative(skb, BPF_HDR_START_MAC, false);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    //return firewall(skb);
    //return process(skb, true);
    return process_relative(skb, BPF_HDR_START_MAC, true);
}

//test only for go-tc
//SEC("mlk_ingress")
//int tc_ingress2(struct __sk_buff *skb) {
//    //return process(skb, false);
//    return process_relative(skb, BPF_HDR_START_MAC, false);
//}
//
////test only for go-tc
//SEC("mlk_egress")
//int tc_egress2(struct __sk_buff *skb) {
//    //return firewall(skb);
//    //return process(skb, true);
//    return process_relative(skb, BPF_HDR_START_MAC, true);
//}

// depreciated - use process_relative instead
static __always_inline int cgroup_process(struct __sk_buff *skb, bool is_egress) {
    bool is_ipv6 = false;
    __u8 l4_protocol;
    int offset = 0;

    //Info: cant use skb->data in cgroup programs

    /* Only actual IP packets are allowed */
    if (skb->protocol == bpf_htons(ETH_P_IPv6)) {
        bpf_printk("[IPv6] --- ipv6");
        is_ipv6 = true;
    } else if (skb->protocol == bpf_htons(ETH_P_IPv4)) {
        bpf_printk("[IPv4] --- ipv4");
    } else {
        bpf_printk("[???] --- L3 protocol not known");
        return 1;
    }

    bpf_printk("[process] /2: %d", is_egress);
    //L3

    struct bpf_sock *sk = skb->sk;
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/x: could not get bpf_sock");
        return 1;
    }
    sk = bpf_sk_fullsock(sk);
    if (!sk) {
        bpf_printk("ERROR: cgroup_skb/ingress: could not get full bpf_sock");
        return 1;
    }


    bpf_printk("[process] /3: %d", is_egress);

    void *pip; //ip pointer either to ipv4 or ipv6
    union ipv46hdr {
        struct iphdr ipv4hdr;
        struct ipv6hdr ipv6hdr;
    } iph = {0};
    //struct iphdr ip = {0}; //TODO :/
    //struct ipv6hdr ipv6 = {0}; //TODO :/
    __u16 l3_hlen = 0;
    if (!is_ipv6) {
        pip = &iph.ipv4hdr;
        if (bpf_skb_load_bytes_relative(skb, offset, pip, sizeof(struct iphdr), BPF_HDR_START_NET))
            return 1;
        l4_protocol = iph.ipv4hdr.protocol;
        offset += sizeof(struct iphdr);
        l3_hlen = (iph.ipv4hdr.ihl & 0xF) << 2;
        bpf_printk("[IPv4] --- protocol:%d", l4_protocol);
    } else {
//        pip = &ipv6;
//        if (bpf_skb_load_bytes_relative(skb, offset, &ipv6, sizeof(ipv6), BPF_HDR_START_NET))
//            return 1;
//        l4_protocol = ipv6.nexthdr;
//        offset += sizeof(ipv6);
//        l3_hlen = sizeof(struct ipv6hdr);
//        bpf_printk("[IPv6] --- protocol:%d", l4_protocol);

        pip = &iph.ipv6hdr;
        if (bpf_skb_load_bytes_relative(skb, offset, pip, sizeof(struct ipv6hdr), BPF_HDR_START_NET))
            return 1;
        l4_protocol = iph.ipv6hdr.nexthdr;
        l3_hlen = sizeof(struct ipv6hdr);
        offset += l3_hlen;
        bpf_printk("[IPv6] --- protocol:%d", l4_protocol);
    }


    bpf_printk("[process] /5: %d", is_egress);
    //L4
    __u16 sport = 0;
    __u16 dport = 0;
    __u16 l4_hlen = 0;
    /* We handle only UDP traffic */
    if (l4_protocol == IPPROTO_UDP) {
        struct udphdr udp = {0};
        if (bpf_skb_load_bytes_relative(skb, offset, &udp, sizeof(struct udphdr), BPF_HDR_START_NET))
            return 1;
        l4_hlen = sizeof(struct udphdr);
        offset += l4_hlen;
        sport = bpf_ntohs(udp.source);
        dport = bpf_ntohs(udp.dest);
        bpf_printk("[UDP] sport:%d, dport:%d", sport, dport);
    } else if (l4_protocol == IPPROTO_TCP) {
        struct tcphdr tcp = {0};
        if (bpf_skb_load_bytes_relative(skb, offset, &tcp, sizeof(struct tcphdr), BPF_HDR_START_NET))
            return 1;

        l4_hlen = sizeof(struct tcphdr);
        offset += l4_hlen;
        sport = bpf_ntohs(tcp.source);
        dport = bpf_ntohs(tcp.dest);
        bpf_printk("[TCP] sport:%d, dport:%d", sport, dport);
    } else
        return 1;

    bpf_printk("[process] /6: %d", is_egress);

    //TODO: what about different ports? see: https://stackoverflow.com/questions/7565300/identifying-dns-packets
    if (sport != 53 && dport != 53) {

        bpf_printk("[process] /6a");
        if (is_egress) {
            int ret;
            if (!is_ipv6) {
                bpf_printk("[process] /6b");
                ret = ipv4_check_and_update((struct iphdr *) pip);
            } else {
                bpf_printk("[process] /6c");
                ret = ipv6_check_and_update((struct ipv6hdr *) pip);
            }


            bpf_printk("[process] /6d: %d", ret);

            if (ret != TC_MOVE_ONE)
                return ret;
        }
        return 1;

    }
    bpf_printk("[process] /7: %d ", is_egress);
//    // Reserve space on the ringbuffer for the sample
//    __u32 len = skb->len;
////    if (len > ETH_FRAME_LEN)
////        return 0;
//    __u32  len_size =sizeof(skb->len);

//    check only for dnq query - uncomment do see details
//    if (is_egress && dport == 53) { //only answers matters
//        const __u32 len = skb->len;
//        if (len > ETH_FRAME_LEN)
//            return 0;
//
//        //{dns deep dive
//        if (data + off + sizeof(struct dnshdr) > data_end)
//            return 0;
//
//        struct dnshdr *dnshp = (data + off);
//        off += sizeof(struct dnshdr);
//        bpf_printk("[DNS] q.header.flags|1 = rd:%u tc:%u opcode:%u qr:%u", dnshp->rd, dnshp->tc, dnshp->opcode, dnshp->qr);
//        bpf_printk("[DNS] q.header.flag|2 = rcode:%u cd:%u ad:%u z:%u", dnshp->rcode, dnshp->cd, dnshp->ad, dnshp->z);
//        bpf_printk("[DNS] q.header.flag|3 = ra:%u", dnshp->ra);
//        bpf_printk("[DNS] q. qdcount:%u nscount: %u, arcount:%u", bpf_htons(dnshp->q_count), bpf_htons(dnshp->ans_count), bpf_htons(dnshp->add_count));
//        //}dns
//    }

    bpf_printk("[process] /8: %d ", is_egress);


    if (!is_egress && sport == 53) { //only answers matters
        struct dnshdr dns = {0};

        if (bpf_skb_load_bytes_relative(skb, offset, &dns, sizeof(struct dnshdr), BPF_HDR_START_NET))
            return 1;


        bpf_printk("[DNS] a.header.flags|1 = rd:%u tc:%u opcode:%u qr:%u", dns.rd, dns.tc, dns.opcode, dns.qr);
        bpf_printk("[DNS] a.header.flag|2 = rcode:%u cd:%u ad:%u z:%u", dns.rcode, dns.cd, dns.ad, dns.z);
        bpf_printk("[DNS] a.header.flag|3 = ra:%u", dns.ra);
        bpf_printk("[DNS] a. qdcount:%u nscount: %u, arcount:%u", bpf_htons(dns.q_count), bpf_htons(dns.ans_count),
                   bpf_htons(dns.add_count));
        //}dns

        long err;
        struct packet *valp;
        valp = bpf_ringbuf_reserve(&packets, sizeof(struct packet), ringbuffer_flags);
        if (!valp) {
            return 1;
        }
        //__u32 dns_packet_len = skb->len - ETH_HLEN - l3_hlen - l4_hlen + DNS_HLEN;
        __u32 dns_packet_len = skb->len + ETH_HLEN; //cgroup_skb program skb->len does not contain ETH_HLEN

        if (dns_packet_len > ETH_FRAME_LEN) {
            dns_packet_len = ETH_FRAME_LEN;
        }
        if (dns_packet_len < 1) {
            //bpf_ringbuf_discard(valp, ringbuffer_flags);
            //return 1;
            dns_packet_len = 1; //see: https://stackoverflow.com/questions/76371104/bpf-skb-load-bytes-array-loading-when-len-could-be-0-invalid-access-to-memor
        }
        //err = bpf_skb_load_bytes(skb, 0, valp->data, dns_packet_len ); //ok
        //       ok = bpf_skb_load_bytes(skb, 0, pto, dns_packet_len); //ok

        err = bpf_skb_load_bytes_relative(skb, 0, valp->data, dns_packet_len, BPF_HDR_START_MAC);
        valp->len = dns_packet_len;
////        // err = bpf_skb_load_bytes_relative(skb, 0, valp->data, len, BPF_HDR_START_MAC);
        if (err) {
            bpf_printk("[DNS] packet discarded-1 from packets ringbuffer, len:%d offset:%d p:%p ok:%d",
                       dns_packet_len, offset, valp->data, err);
            bpf_ringbuf_discard(valp, ringbuffer_flags); //memory not consumed
            return 1;
        }


        // load whole package in ebpf group program into struct packet
/*
        err = bpf_probe_read_kernel(valp->data, len,  (void *) (long) skb->data); //ok
        err = bpf_skb_load_bytes(skb, 0, &valp->data[0], len); //ok
        if (err) {
            bpf_ringbuf_discard(valp, ringbuffer_flags); //memory not consumed
            return 0;
        }
*/
        //bpf_printk("[!!!] len:%d, data:%x, valp.data:%x ", valp->len, *(__u8 *) (long) data, valp->data[0]);
        void *data = (void *) (long) skb->data;
        void *data_end = (void *) (long) skb->data_end;
        if (data + ETH_HLEN > data_end) {
            bpf_ringbuf_discard(valp, ringbuffer_flags); //memory not consumed
            return 1;
        }

        bpf_printk("[DNS] packet in ringbuffer, len:%d; data:%x%x%x%x", dns_packet_len, *(__u8 *) data,
                   *(__u8 * )(data + 1), *(__u8 * )(data + 2), *(__u8 * )(data + 3));
        bpf_ringbuf_submit(valp, ringbuffer_flags);

        offset += sizeof(struct dnshdr);
    }
    return 1;
}


SEC("cgroup_skb/ingress")
int cgroup__skb_ingress(struct __sk_buff *skb) {

    //return cgroup_process(skb, false);
    int ret;
    ret = process_relative(skb, BPF_HDR_START_NET, false);
    return (ret == 0) ? 1 : 0;

//    bpf_printk("[cgroup] ingress");
//
//    if (ctx->protocol != bpf_htons(ETH_P_IPv4)) // ethernet (IPv4) only
//        return 1;
//
//    struct bpf_sock *sk = ctx->sk;
//    if (!sk) {
//        bpf_printk("ERROR: cgroup_skb/ingress: could not get bpf_sock");
//        return 1;
//    }
//
//   __u64 cookie = bpf_get_socket_cookie(ctx);
//    sk = bpf_sk_fullsock(sk);
//    if (!sk) {
//        bpf_printk("ERROR: cgroup_skb/ingress: could not get full bpf_sock");
//        return 1;
//    }
//
//    struct iphdr ip = {0};
//    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
//        return 1;
//
//    ipv4_print_ip("[cgroup-ingress] ip.src:", "", ip.saddr);
//    ipv4_print_ip("[cgroup-ingress] ip.dst:", "\n", ip.daddr);
//    bpf_printk("[cgroup-ingress] cookie: %u", cookie);
//    return 1;
}

SEC("cgroup_skb/egress")
int cgroup__skb_egress(struct __sk_buff *skb) {

    //return cgroup_process(skb, true);
    int ret;
    ret = process_relative(skb, BPF_HDR_START_NET, true);
    return (ret == 0) ? 1 : 0;

//    bpf_printk("[cgroup] egress");
//
//    if (ctx->protocol != bpf_htons(ETH_P_IPv4)) // ethernet (IPv4) only
//        return 1;
//
//    __u64 cookie = bpf_get_socket_cookie(ctx);
//    // shwow bpf_get_netns_cookie usage here
//    //__u64 netns_cookie = bpf_get_netns_cookie(ctx);
//    struct bpf_sock *sk = ctx->sk;
//    if (!sk) {
//        bpf_printk("ERROR: cgroup_skb/egress: could not get bpf_sock");
//        return 1;
//    }
//
//
//    sk = bpf_sk_fullsock(sk);
//    if (!sk) {
//        bpf_printk("ERROR: cgroup_skb/egress: could not get full bpf_sock");
//        return 1;
//    }
//
//    struct iphdr ip = {0};
//    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
//        return 1;
//
//    ipv4_print_ip("[cgroup-egress] ip.src:", "", ip.saddr);
//    ipv4_print_ip("[cgroup-egress] ip.dst:", "\n", ip.daddr);
//    bpf_printk("[cgroup-egress] cookie: %u", cookie);
    // bpf_printk("[cgroup-egress] netns_cookie: %u", netns_cookie);

//    struct icmphdr icmp = {0};

//    switch (ip.protocol) {
//        case IPPROTO_ICMP:
//            if (bpf_skb_load_bytes_relative(ctx,
//                                            sizeof(ip),
//                                            &icmp,
//                                            sizeof(struct icmphdr),
//                                            BPF_HDR_START_NET))
//                return 1;
//
//            u32 bleh = 20220823;
//            bpf_perf_event_output(ctx, &perfbuffer, BPF_F_CURRENT_CPU, &bleh, sizeof(bleh));
//            break;
//    }

    //  return 1;
}

//SEC("cgroup/sock")
//int cgroup__sock(struct bpf_sock *sk) {
//    __u64 netns_cookie = bpf_get_netns_cookie(sk);
//    bpf_printk("[cgroup-sock] netns_cookie: %u", netns_cookie);
//
//
//        __u64 classid = bpf_get_cgroup_classid(sk);
//
//        bpf_printk("[cgroup-sock] classid: %u", classid);
//
//
//
//    //
////    ctx->protocol != bpf_htons(ETH_P_IPv4)) // ethernet (IPv4) only
////        return 1;
////
// //   __u64 cookie = bpf_get_socket_cookie(ctx);
////    struct bpf_sock *sk = ctx->sk;
////    if (!sk) {
////        bpf_printk("ERROR: cgroup_sock: could not get bpf_sock");
////        return 1;
////    }
////
////
////    sk = bpf_sk_fullsock(sk);
////    if (!sk) {
////        bpf_printk("ERROR: cgroup_sock: could not get full bpf_sock");
////        return 1;
////    }
//
////    struct iphdr ip = {0};
////    if (bpf_skb_load_bytes_relative(ctx, 0, &ip, sizeof(ip), BPF_HDR_START_NET))
////        return 1;
////
////    __u32 src_ip4, dst_ip4;
////
////    src_ip4 = sk->src_ip4;
////    dst_ip4 = sk->dst_ip4;
////
////    ipv4_print_ip("[cgroup-sock] ip.src:", "", src_ip4);
////    ipv4_print_ip("[cgroup-sock] ip.dst:", "\n", sk->dst_ip4);
// //   bpf_printk("[cgroup-sock] cookie: %u", cookie);
//
//    return 1;
//}


char LICENSE[] SEC("license") = "GPL";
