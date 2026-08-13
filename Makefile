BPF_OBJS = monitor.bpf.o page_fault.bpf.o rate_limit.bpf.o

all: main $(BPF_OBJS)

main: main.c
	gcc -g -O2 main.c -o main -lbpf

%.bpf.o: %.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

clean:
	rm -f main $(BPF_OBJS)

.PHONY: all clean
