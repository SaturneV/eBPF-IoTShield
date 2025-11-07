CLANG = clang
CFLAGS = -O2 -target bpf -I/usr/include -I/usr/include/x86_64-linux-gnu -I/usr/include/bpf -g

SRCS = xdp_rate_based_filter.c xdp_punisher.c
OBJS = $(SRCS:.c=.o)


all : $(OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean :
	rm -rf *.o
