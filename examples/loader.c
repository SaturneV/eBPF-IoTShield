#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

struct xdp_program *prog = NULL;
int ifindex;

static void exit_prog(int sig){
	xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
	xdp_program__close(prog);
	printf("Closing the program\n");
	exit(0);	
}

static void print_map(int map_fd, int interval){
	
	int nb_cpus = libbpf_num_possible_cpus();
	if (!nb_cpus) {
		printf("Error when trying to get the number of CPUs\n");
		return;
	}

	long values[nb_cpus];
	int key = 0;

	while (1) {

		sleep(interval);
		if (bpf_map_lookup_elem(map_fd, &key, values) != 0){
			printf("Error when trying to retreive the element from the map\n");
		}
		printf("Map state :\n");
		for (int i = 0; i < nb_cpus; i++){
			printf("\tcpu[%d]: %10llu packets dropped\n", i, values[i]);
		}
	}
}

int main(int argc, char *argv[]){
	int prog_fd, map_fd, ret;

	struct bpf_object *bpf_obj;

	if (argc != 2) {
		printf("Usage: %s IFNAME\n", argv[0]);
		return 1;
    	}

	ifindex = if_nametoindex(argv[1]); //retreive the id from the name given to the program
	if (!ifindex){
		printf("Failed to get index from the given name\n");
		return 1;
	}

	prog = xdp_program__open_file("xdp_count_ipv6.o", "xdp", NULL);

	if (!prog) {
		printf("Error load xdp prog failed\n");
		return 1;
	}

	ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
	if (ret) {
		printf("Error, Set xdp fd on %d failed\n", ifindex);
		return ret;
	}

	/* Find the map fd from the bpf object */
	bpf_obj = xdp_program__bpf_obj(prog);
	map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "percpu_counter");
	if (map_fd < 0) {
		printf("Error, get map fd from bpf obj failed\n");
		return map_fd;
	}


	/* Remove attached program when it is interrupted or killed */
	signal(SIGINT, exit_prog);
	signal(SIGTERM, exit_prog);

	print_map(map_fd, 2);

	return 0;
}





