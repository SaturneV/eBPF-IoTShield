#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>

#define THRESHOLD 10
#define TIME_PERIOD 1000000000 // 1 sec in ns
struct map_entry {
	__u64 last_counter_reset;
	__u32 counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32); //ipv4 address
	__type(value, struct map_entry); // counter and last reset time
} rate_limit_map SEC(".maps");

SEC("xdp")
int count_ipv4_packets(struct xdp_md *ctx) {
	void* start = (void *)(long) ctx->data;
	void* end = (void *)(long) ctx->data_end;

	
	// Retreive the eth header
	struct ethhdr *eth_header = start;
	if ((void *) (eth_header + 1) > end){
		//No space for the ehternet header
		return XDP_PASS;
	}


	if (eth_header->h_proto != bpf_htons(ETH_P_IP)){
		// Not an IPV4 so we let it through
		return XDP_PASS;
	}


	//Retreive the ip header (right after the ethheader)
	struct iphdr *ip_hdr = (void *) (eth_header + 1); 
	if ((void *)(ip_hdr + 1) > end) {
		//No space for ip header 
		return XDP_PASS;
	}

	__u32 source = bpf_ntohs(ip_hdr->saddr); //retreive the address

	struct map_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &source);

	__u64 curr_time = bpf_ktime_get_ns();

	if (entry) {
		__u64 elapsed_time = curr_time - entry->last_counter_reset;
		if (elapsed_time < TIME_PERIOD) {
			entry->counter++;
			if (entry->counter > THRESHOLD) {
				// Threshold reached within the time window
				return XDP_DROP;
			}
		} else {
			//time window exceeded
			entry->last_counter_reset = curr_time;
			entry->counter = 1;
		}
	} else {
		// Element does not exist
		struct map_entry new_val;
		new_val.counter = 1;
		new_val.last_counter_reset = curr_time;
		if(bpf_map_update_elem(&rate_limit_map, &source, &new_val, BPF_ANY) != 0){
			return XDP_ABORTED; //Error occured
		}
	}
	return XDP_PASS;
}
char _license[] SEC("license") = "GPL";

