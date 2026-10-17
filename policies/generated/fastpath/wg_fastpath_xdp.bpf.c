/*
 * WireGuard 100GbE eBPF XDP Fast-Path Packet Filter
 * Interface: wg0
 * Synthesized by nix-k8s-sentinel
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define WG_PORT 51820

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} fastpath_ringbuf SEC(".maps");

SEC("xdp")
int xdp_wireguard_fastpath(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)((unsigned char *)ip + (ip->ihl * 4));
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest == __constant_htons(WG_PORT)) {
        /* WireGuard UDP packet - steer to native crypto pipeline */
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
