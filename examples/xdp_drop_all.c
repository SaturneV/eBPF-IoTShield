#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp") //puts this section in a specific elf section named xdp (means attach to an xdp hook)
int xdp_drop_all(struct xdp_md *ctx){
	return XDP_DROP; //drop everything
}

char _license[] SEC("license") = "GPL"; //Get access to all kernel helpers (no restriction)

