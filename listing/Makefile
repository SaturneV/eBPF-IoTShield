CLANG = clang
ARCH := $(shell uname -m)
CFLAGS = -O2 -target bpf -I/usr/include -I/usr/include/$(ARCH)-linux-gnu -I/usr/include/bpf -g

SRCS = listing.c
OBJS = $(SRCS:.c=.o)


all : $(OBJS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean :
	rm -rf *.o