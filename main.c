#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
typedef struct {
    __u32 pid;
    char name[16];
    __u32 cpu_id;
    __u64 timestamp;
    long syscall_id;
    __u64 args[6];
} Data;
static int f(void *ctx, void *data, size_t data_sz) {
    const struct Data *ini = data;
    printf("=====================================\n");
    printf("syscall pid: %u \ncpu core: %u \nsyscall id: %ld \ntime: %llu ns\n", ini->pid, ini->cpu_id, ini->syscall_id, ini->timestamp);
    printf("=====================================\n");
    return 0;
}
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
    int count_map_fd = bpf_object__find_map_fd_by_name(obj, "count_map");
    int data_map_fd = bpf_object__find_map_fd_by_name(obj, "data_map");
    int num_cpus = libbpf_num_possible_cpus();
    Data syscall_vals[num_cpus];
    Data sched_vals[num_cpus];
    __u32 key_sys = 0;
    __u32 key_sched = 1;
    struct ring_buffer  rb = ring_buffer__new(data_map_fd, f, NULL, NULL);
    while (1) {
        err = ring_buffer__poll(rb, 100);
        sleep(1);
        bpf_map_lookup_elem(count_map_fd, &key_sys, syscall_vals);
        bpf_map_lookup_elem(count_map_fd, &key_sched, sched_vals);
        printf("=====================================\n");
        for (int i = 0; i < num_cpus; i++) {
            printf("CPU Core %d \nSyscalls: %llu \nContext Switches: %llu\n", i, syscall_vals[i].count, sched_vals[i].count);
        }
        printf("=====================================\n");
    }
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}