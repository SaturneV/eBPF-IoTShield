#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// MODIFY HERE TO CHANGE RATE LIMIT PARAMETERS
#define RATE_LIMIT_THRESHOLD 10
#define RATE_LIMIT_TIMEOUT 1000000000 // 1 sec in ns

#define ACTION_PASS 0
#define ACTION_DROP 1


struct ipv4_lpm_key {
    __u32 prefixlen;
    __u8 data[4];
};

struct ipv6_lpm_key {
    __u32 prefixlen;
    __u8 data[16];
};

struct rate_limit_map_entry {
	__u64 last_counter_reset;
	__u32 counter;
};

//listing xdp maps
//BPF_MAP_TYPE_LPM_TRIE provides a longest prefix match algorithm (https://docs.kernel.org/bpf/map_lpm_trie.html)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32); //stores either ACTION_PASS or ACTION_DROP
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC); 
} listing_map_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv6_lpm_key);
    __type(value, __u32);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} listing_map_v6 SEC(".maps");

//rate limiting maps
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); //ipv4 address
	__type(value, struct rate_limit_map_entry); // counter and last reset time
} rate_limit_map_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u128); //ipv6 address
	__type(value, struct rate_limit_map_entry); // counter and last reset time
} rate_limit_map_v6 SEC(".maps");

static __always_inline int check_rate_limit(void *map, void *key) {
    struct rate_limit_map_entry *entry;
    __u64 curr_time = bpf_ktime_get_ns();

    entry = bpf_map_lookup_elem(map, key);
    if (entry) {
        __u64 elapsed_time = curr_time - entry->last_counter_reset;
        if (elapsed_time < RATE_LIMIT_TIMEOUT) {
            entry->counter++;
            if (entry->counter > RATE_LIMIT_THRESHOLD)
                return XDP_DROP;
        } else {
            // Time window exceeded, reset logic
            entry->last_counter_reset = curr_time;
            entry->counter = 1;
        }
    } else {
        // New entry
        struct rate_limit_map_entry new_val = {0};
        new_val.counter = 1;
        new_val.last_counter_reset = curr_time;
        
        // If map is full we block everything, as in our case the important ips will already be whitelisted and will be accepted before coming to the rate limiter
        // If we were to pass, someone could simply fill up the map with bogus addresses and then bypass the rate limiting
        if (bpf_map_update_elem(map, key, &new_val, BPF_ANY) != 0)
            return XDP_DROP;
            
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
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
        key.prefixlen = 32; // Should be set to max key length for longest prefix match
        __builtin_memcpy(key.data, &iph->saddr, 4);

        __u32* action = bpf_map_lookup_elem(&listing_map_v4, &key);
        if (action)
            return (*action == ACTION_DROP) ? XDP_DROP : XDP_PASS;

        // If we're here means that the IPv4 is neither whitelisted or blacklisted
        return check_rate_limit(&rate_limit_map_v4, &iph->saddr);

    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip6h = data + sizeof(struct ethhdr);
        if ((void*)(ip6h + 1) > data_end)
            return XDP_PASS;

        struct ipv6_lpm_key key;
        key.prefixlen = 128; 
        __builtin_memcpy(key.data, &ip6h->saddr, 16);

        __u32* action = bpf_map_lookup_elem(&listing_map_v6, &key);
        if (action)
            return (*action == ACTION_DROP) ? XDP_DROP : XDP_PASS;
        
        // If we're here means that the IPv6 is neither whitelisted or blacklisted
        return check_rate_limit(&rate_limit_map_v6, &ip6h->saddr);
    }

    // Not IPv4 nor IPv6, just pass them.
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

