CLANG = clang
ARCH := $(shell uname -m)
CFLAGS = -O2 -target bpf -I/usr/include -I/usr/include/$(ARCH)-linux-gnu -I/usr/include/bpf -g

SRCS = listing.c
OBJS = $(SRCS:.c=.o)

IFACE ?= veth-host

all : $(OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@


load: $(OBJS)
	@echo "Loading $(OBJS) onto $(IFACE)..."
	sudo ip link set dev $(IFACE) xdp obj $(OBJS) sec xdp

unload:
	sudo ip link set dev $(IFACE) xdp off


clean :
	rm -rf *.o