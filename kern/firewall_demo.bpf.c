/*
    This program blocks your machine from contacting BLOCKED_IP using XDP.
    It is attached to your primary network interface and does filtering there.
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bcc/helpers.h>

typedef unsigned char byte;

// union means addr will be filled out by the octets as they occupy same memory
static const union {
    uint32_t addr;
    struct {
        byte octet1;
        byte octet2;
        byte octet3;
        byte octet4;
    };
} BLOCKED_IP = {1, 0, 0, 1}; // 1.0.0.1 as an example

SEC("xdp/firewall")
int fw_block_ip(struct xdp_md *ctx)
{
    void *frame_end = (void *)(long)ctx->data_end; // pointer to end of ethernet frame
    void *frame = (void *)(long)ctx->data; // pointer to start of frame

    struct ethhdr *eth_header = frame;
    if ((void *)eth_header + sizeof(*eth_header) > frame_end) // ethernet header too large!
        return XDP_PASS;

    // if an IP packet is inside
    if (eth_header->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip_header = data + sizeof(*eth);
        if ((void *)ip_header + sizeof(*ip_header) > frame_end) // IP header too large!
            return XDP_PASS;

        // if destination is the blocked IP, then drop the packet
        if (ip->daddr == __constant_htonl(BLOCKED_IP.addr))
            return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "MIT";
