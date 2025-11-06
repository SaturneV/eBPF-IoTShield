#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); //better for performance no locking
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} percpu_counter SEC(".maps"); //save this type of map in a special ELF section .maps

SEC("xdp")
int xdp_count_ipv6(struct xdp_md *ctx){
	void *data_start = (void*)(long) ctx->data; //cast a u32 in a void* pointer
	void *data_end = (void*)(long) ctx->data_end; //cast a u32 in a void* pointer
	
	struct ethhdr *header = data_start; //ethernet header exactly 14 bytes
	if ((void*)(header + 1) > data_end) {
		//Not enough room fo the header
		return XDP_PASS;
	}

	__be16 proto = header->h_proto; //big endian protocol

	__u32 key = 0; //always use the same key here

	if (proto == bpf_htons(ETH_P_IPV6)){ //if protocol is ipv6 
		__u64 *count = bpf_map_lookup_elem(&percpu_counter, &key);

		if (count) { //check if not null
			*count += 1; //safe on perCPU maps
		}
		return XDP_DROP;
	}

	return XDP_PASS; // else let it through
}
char _license[] SEC("license") = "GPL";
