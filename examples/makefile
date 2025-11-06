all : xdp_drop_all


xdp_drop_all : xdp_drop_all.c
	clang -O2 -target bpf   -I/usr/include   -I/usr/include/x86_64-linux-gnu   -I/usr/include/bpf  -g  -c xdp_drop_all.c -o xdp_drop_all.o

clean :
	rm -rf *.o
