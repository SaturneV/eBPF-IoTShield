#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); //ipv4 address
	__type(value, __u64); //counter
} ipv4_counters SEC(".maps");

SEC("xdp")
int count_ipv4_packets(struct xdp_md *ctx) {
	void* start = (void *)(long) ctx->data;
	void* end = (void *)(long) ctx->data_end;

	// Retreive the ip header
	
	struct ethhdr *eth_header = start;
	if ((void *) (eth_header + 1) > end){
		//No space for the ehternet header
		return XDP_PASS;
	}


	if (eth_header->h_proto != bpf_htons(ETH_P_IP)){
		// Not an IPV4 so we let it through
		return XDP_PASS;
	}


	struct iphdr *ip_hdr = (void *) (eth_header + 1); //the ip header (right after the ethernet header
	if ((void *)(ip_hdr + 1) > end) {
		//No space for ip header 
		return XDP_PASS;
	}

	__u32 source = ip_hdr->saddr;

	__u64 *count = bpf_map_lookup_elem(&ipv4_counters, &source);

	if (count) {
		__sync_fetch_and_add(count, 1); //Needed since it's not a per cpu map
	} else {
		// Element does not exist
		__u64 new_val = 1;
		bpf_map_update_elem(&ipv4_counters, &source, &new_val, BPF_ANY);
	}

	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
