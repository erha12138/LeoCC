#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

#define TC_ACT_OK 0
#define IPPROTO_TCP 6
#define MAX_TCP_HDR_LEN 100
#define EXP_OPT_LEN 4
#define TCP_HEADER_LEN 11 // with one SACK block, replace with other length if needed

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} reconf_state SEC(".maps");

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    // validation and parsing
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;
    
    // IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->protocol != IPPROTO_TCP) return TC_ACT_OK;
    int ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < 20) return TC_ACT_OK;
    __u16 old_tot_len = __bpf_ntohs(iph->tot_len);

    // TCP header
    __u8 *tcph_base = data + sizeof(*eth) + ip_hdr_len;
    if (tcph_base + sizeof(struct tcphdr) > data_end) return TC_ACT_OK;

    __u16 doff_flags;
    __builtin_memcpy(&doff_flags, tcph_base + 12, sizeof(__u16));
    doff_flags = __bpf_ntohs(doff_flags);

    __u8 ack = (doff_flags >> 4) & 1;
    if (!ack) return TC_ACT_OK;

    __u8 doff = (doff_flags >> 12) & 0xF; // 4 bits
	if (doff != TCP_HEADER_LEN) return TC_ACT_OK;

    int old_tcp_len = doff * 4;
    if (old_tcp_len > MAX_TCP_HDR_LEN) return TC_ACT_OK;

    int dst_off = sizeof(*eth) + ip_hdr_len;
    int src_off = dst_off + EXP_OPT_LEN;
    __u8 tcp_hdr_buf[MAX_TCP_HDR_LEN];
    if (bpf_skb_load_bytes(skb, dst_off, tcp_hdr_buf, old_tcp_len)) return TC_ACT_OK;

    // leave room for new option
    if (bpf_skb_adjust_room(skb, EXP_OPT_LEN, BPF_ADJ_ROOM_NET, 0)) return TC_ACT_OK; 
    
    // re-check pointers after adjusting room
    data     = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    eth = data;
    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    ip_hdr_len = iph->ihl * 4;
    tcph_base = data + sizeof(*eth) + ip_hdr_len;
    if (tcph_base + old_tcp_len > data_end) return TC_ACT_OK;
    dst_off = sizeof(*eth) + ip_hdr_len;

    if (bpf_skb_load_bytes(skb, src_off, tcp_hdr_buf, old_tcp_len)) return TC_ACT_OK;
    if (bpf_skb_store_bytes(skb, dst_off, tcp_hdr_buf, old_tcp_len, 0)) return TC_ACT_OK;

    // insert new option
    __u8 option[EXP_OPT_LEN] = {0xFD, 0x04, 0x00, 0x00}; // Kind=253, Len=4
    __u32 key = 0;
    __u32 *is_reconf = bpf_map_lookup_elem(&reconf_state, &key);
    if (is_reconf) {
        option[3] = (__u8)(*is_reconf & 0xFF);
        __builtin_memcpy(&option[3], is_reconf, 1);
    }

    int opt_offset = sizeof(*eth) + ip_hdr_len + old_tcp_len;
    if (bpf_skb_store_bytes(skb, opt_offset, option, EXP_OPT_LEN, 0)) return TC_ACT_OK;
    
    // update IP total length and checksum
    __u16 old_tot_len_net = __bpf_htons(old_tot_len);
    __u16 new_tot_len = __bpf_htons(old_tot_len + EXP_OPT_LEN);
    bpf_skb_store_bytes(skb, sizeof(*eth) + 2, &new_tot_len, 2, 0);
    bpf_l3_csum_replace(skb, sizeof(*eth) + 10, old_tot_len_net, new_tot_len, 2);

    // Update TCP Data Offset
    __u16 old_df_net_u16 = __bpf_htons(doff_flags);
    __u8 new_doff_u8 = doff + (EXP_OPT_LEN + 3) / 4;
    __u16 new_df_host_u16 = (doff_flags & 0x0FFF) | (new_doff_u8 << 12);
    __u16 new_df_net_u16 = __bpf_htons(new_df_host_u16);

    int tcp_offset = sizeof(struct ethhdr) + ip_hdr_len;
    if (bpf_skb_store_bytes(skb, tcp_offset + 12, &new_df_net_u16, 2, 0)) return TC_ACT_OK;
 
    // Update L4 Checksum
    __u32 csum_diff = 0;
    __u16 new_doff = doff + (EXP_OPT_LEN + 3) / 4;
    __u16 new_df_host = (doff_flags & 0x0FFF) | (new_doff << 12);
    __be16 new_df_net = __bpf_htons(new_df_host);
    __be16 old_df_net = __bpf_htons(doff_flags);
    __be32 diff_from = 0, diff_to = 0;
    __builtin_memcpy(&diff_from, &old_df_net, 2);
    __builtin_memcpy(&diff_to, &new_df_net, 2);
    csum_diff = bpf_csum_diff(&diff_from, 4, &diff_to, 4, csum_diff);
    csum_diff = bpf_csum_diff(NULL, 0, (__be32 *)option, 4, csum_diff);
    if (bpf_l4_csum_replace(skb, tcp_offset + 16, 0, csum_diff, BPF_F_PSEUDO_HDR)) return TC_ACT_OK;

    return TC_ACT_OK;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
