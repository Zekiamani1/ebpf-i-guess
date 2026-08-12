#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
struct Data{
    __u64  count;
};
int main() {
    struct bpf_object *obj;
    int err;
    obj = bpf_object__open_file("monitor.bpf.o", NULL);
    if (!obj) {
        printf("Tidak bisa membuka monitor.bpf.o\n");
        return 1;
    }
    err = bpf_object__load(obj);
    if (err) {
        printf("Gagal meload BPF program ke Kernel\n");
        return 1;
    }
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }
    int map_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    int num_cpus = libbpf_num_possible_cpus();
    Data syscall_vals[num_cpus];
    Data sched_vals[num_cpus];
    __u32 key_sys = 0;
    __u32 key_sched = 1;
    while (1) {
        sleep(1);
        bpf_map_lookup_elem(map_fd, &key_sys, syscall_vals);
        bpf_map_lookup_elem(map_fd, &key_sched, sched_vals);
        printf("=====================================\n");
        for (int i = 0; i < num_cpus; i++) {
            printf("CPU Core %d \nSyscalls: %llu \nContext Switches: %llu\n", i, syscall_vals[i], sched_vals[i]);
        }
        printf("=====================================\n");
    }
    return 0;
}