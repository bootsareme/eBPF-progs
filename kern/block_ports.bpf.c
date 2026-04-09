/*
   This program takes a list of ports from userspace (see harness)
   and blocks any other machine from connecting to it despite any
   objections from upper layer firewalls or applications.
*/

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(blocked_ports, u16, u8);

int fw_block_ports(struct xdp_md *ctx)
{
    void *end_of_frame = (void *)(long)ctx->data_end;
    void *frame = (void *)(long)ctx->data;

    // parse ethernet header
    struct ethhdr *eth_header = frame;
    if ((void *)(eth_header + 1) > end_of_frame)
        return XDP_PASS; // bounds check

    if (eth_header->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS; // ignore if next layer is not IP

    // parse IP header
    struct iphdr *ip_header = (void *)(eth_header + 1);
    if ((void *)(ip_header + 1) > end_of_frame)
        return XDP_PASS; // bounds check 

    if (ip_header->protocol != IPPROTO_TCP)
        return XDP_PASS; // ignore if next layer is not TCP

    // parse TCP header
    struct tcphdr *tcp_header = (void *)ip_header + ip_header->ihl * 4;
    if ((void *)(tcp_header + 1) > end_of_frame)
        return XDP_PASS; // bounds check
    
    u16 dport = __builtin_bswap16(tcp_header->dest);
    u8 *exists = blocked_ports.lookup(&dport);

    if (exists) {
        bpf_trace_printk("Blocked port %d access from IP = 0x%x\n", dport, ip_header->saddr);
        return XDP_DROP;
    }

    return XDP_PASS;
}
