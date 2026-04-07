/*
    This program blocks your machine from contacting BLOCKED_IP using XDP.
    It is attached to your network interface of choosing and does filtering there.
*/

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

static const struct {
    uint8_t octet1;
    uint8_t octet2;
    uint8_t octet3;
    uint8_t octet4;
} BLOCKED_IP = {1, 0, 0, 1}; // 1.0.0.1 as an example

int fw_block_ip(struct xdp_md *ctx)
{
    void *frame_end = (void *)(long)ctx->data_end; // pointer to end of ethernet frame
    void *frame = (void *)(long)ctx->data; // pointer to start of frame

    struct ethhdr *eth_header = frame;
    if ((void *)eth_header + sizeof(*eth_header) > frame_end) // ethernet header too large!
        return XDP_PASS;

    // if an IP packet is inside
    if (eth_header->h_proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip_header = frame + sizeof(*eth_header); // index past ethernet header
        if ((void *)ip_header + sizeof(*ip_header) > frame_end) // IP header too large!
            return XDP_PASS;

        uint32_t blocked_ip = (BLOCKED_IP.octet1 << 24) |
                                (BLOCKED_IP.octet2 << 16) |
                                (BLOCKED_IP.octet3 << 8) |
                                BLOCKED_IP.octet4;

        // if destination is the blocked IP, then drop the packet
        if (ip_header->daddr == __constant_htonl(blocked_ip))
            return XDP_DROP;
    }

    return XDP_PASS;
}
