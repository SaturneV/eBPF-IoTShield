CLANG = clang
CFLAGS = -O2 -target bpf   -I/usr/include   -I/usr/include/x86_64-linux-gnu   -I/usr/include/bpf  -g

SRCS = xdp_drop_all.c xdp_drop_ipv6.c xdp_count_ipv6.c xdp_count_perIP.c
OBJS = $(SRCS:.c=.o)


all : $(OBJS)


%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@
clean :
	rm -rf *.o
