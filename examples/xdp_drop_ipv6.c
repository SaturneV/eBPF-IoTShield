#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>


SEC("xdp")
int xdp_drop_ipv6(struct xdp_md *ctx){
	void *data_start = (void*)(long) ctx->data; //cast a u32 in a void* pointer
	void *data_end = (void*)(long) ctx->data_end; //cast a u32 in a void* pointer
	
	struct ethhdr *header = data_start; //ethernet header exactly 14 bytes
	if ((void*)(header + 1) > data_end) {
		//Not enough room fo the header
		return XDP_PASS;
	}

	__be16 proto_big_endian = header->h_proto; //big endian protocol
	__u16 proto = bpf_ntohs(proto_big_endian); //litle endian proto

	if (proto == ETH_P_IPV6){ //if protocol is ipv6
		return XDP_DROP;
	}

	return XDP_PASS; // else let it through
}
char _license[] SEC("license") = "GPL";
