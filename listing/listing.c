#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#define ACTION_PASS 0
#define ACTION_DROP 1

//TODO: read from a .text file with python startup

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 data[4];
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 data[16];
};

//TODO: when merging the programs, implement the whitelist at the earliest stage to pass
//BPF_MAP_TYPE_LPM_TRIE provides a longest prefix match algorithm (https://docs.kernel.org/bpf/map_lpm_trie.html)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32); //stores either ACTION_PASS or ACTION_DROP
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC); 
} map_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} map_v6 SEC(".maps");

SEC("xdp")
int xdp_listing(struct xdp_md *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;

    struct ethhdr* eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* iph = data + sizeof(struct ethhdr);
        if ((void*)(iph + 1) > data_end)
            return XDP_PASS;

        struct ipv4_lpm_key key;
        key.prefixlen = 32; //should be set to max key length for longest prefix match
        __builtin_memcpy(key.data, &iph->saddr, 4);

        __u32* action = bpf_map_lookup_elem(&map_v4, &key);
        if (action)
            return (*action == ACTION_DROP) ? XDP_DROP : XDP_PASS;

    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6h = data + sizeof(struct ethhdr);
        if ((void*)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct ipv6_lpm_key key;
        key.prefixlen = 128; 
        __builtin_memcpy(key.data, &ip6h->saddr, 16);

        __u32* action = bpf_map_lookup_elem(&map_v6, &key);
        if (action)
            return (*action == ACTION_DROP) ? XDP_DROP : XDP_PASS;
    }

    return XDP_PASS; //not whitelist or blacklisted. TODO: don't pass them normally, let the remaining logic of the program handle it
}

char _license[] SEC("license") = "GPL";