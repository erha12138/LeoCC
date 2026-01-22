#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

#define TC_ACT_OK 0
#define IPPROTO_TCP 6
#define DOFF_EXPECTED 12 // with one SACK block and our option, replace with other length if needed
#define EXP_KIND_OFFSET 24 // offset of our option in TCP options

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    // validation and parsing
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    // IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // TCP header
    int ip_hdr_len = iph->ihl * 4;
    __u8 *tcph_base = data + sizeof(*eth) + ip_hdr_len;
    if (tcph_base + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;

    __u16 doff_flags;
    __builtin_memcpy(&doff_flags, tcph_base + 12, sizeof(__u16));
    doff_flags = __bpf_ntohs(doff_flags);
    __u8 doff = (doff_flags >> 12) & 0xF;
    if (doff != DOFF_EXPECTED) return TC_ACT_OK;

    __u8 *opt_ptr = tcph_base + sizeof(struct tcphdr);

    if (opt_ptr + EXP_KIND_OFFSET + 4 > data_end) return TC_ACT_OK;

    // check our experimental option
    __u8 exp_kind, exp_len;
    __builtin_memcpy(&exp_kind, opt_ptr + EXP_KIND_OFFSET, 1);
    __builtin_memcpy(&exp_len, opt_ptr + EXP_KIND_OFFSET + 1, 1);

    if (exp_kind != 0xfd || exp_len != 0x04) return TC_ACT_OK;

    // extract reconfiguration signal
    __u16 is_reconfig;
    __builtin_memcpy(&is_reconfig, opt_ptr + EXP_KIND_OFFSET + 2, 2);
    is_reconfig = __bpf_ntohs(is_reconfig);
    skb->mark = (__u32)is_reconfig;

    return TC_ACT_OK;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
