#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
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
typedef struct {
    __u32 pid;
    char name[16];
    __u32 cpu_id;
    __u64 timestamp;
} Sched;
typedef struct {
    __u32 pid;
    char name[16];
    __u64 address;
}Fault;
static FILE *syscall_log, *sched_log, *fault_log;
static int on_fault(void *ctx, void *data, size_t data_sz) {
    Fault *ini = data;
    fprintf(fault_log, "=====================================\n");
    fprintf(fault_log, "page fault pid: %u \naddress: %llu \nprocess: %s\n", ini->pid, ini->address, ini->name);
    fprintf(fault_log, "=====================================\n");
    return 0;
}
static int on_syscall(void *ctx, void *data, size_t data_sz) {
    Data *ini = data;
    fprintf(syscall_log, "=====================================\n");
    fprintf(syscall_log, "syscall pid: %u \nprocess: %s \ncpu core: %u \nsyscall id: %ld \ntime: %llu ns\n", ini->pid, ini->name, ini->cpu_id, ini->syscall_id, ini->timestamp);
    fprintf(syscall_log, "=====================================\n");
    return 0;
}
static int on_sched(void *ctx, void *data, size_t data_sz) {
    Sched *ini = data;
    fprintf(sched_log, "=====================================\n");
    fprintf(sched_log, "context switch pid: %u \nprocess: %s \ncpu core: %u \ntime: %llu ns\n", ini->pid, ini->name, ini->cpu_id, ini->timestamp);
    fprintf(sched_log, "=====================================\n");
    return 0;
}
static int poll_ringbuf(void *rb) {
    while (ring_buffer__poll(rb, 100) >= 0)
        ;
    return 0;
}
static FILE *open_log(const char *path) {
    FILE *f = fopen(path, "a");
    if (!f) {
        perror(path);
        exit(1);
    }
    setlinebuf(f);
    return f;
}
static struct bpf_object *load_bpf(const char *path) {
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj) {
        printf("Tidak bisa membuka %s\n", path);
        exit(1);
    }
    if (bpf_object__load(obj)) {
        printf("Gagal meload %s ke Kernel\n", path);
        exit(1);
    }
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog))
            printf("Gagal attach %s (%s)\n", bpf_program__name(prog), path);
    }
    return obj;
}
int main(int argc, char **argv) {
    int want_ratelimit = 0, want_fault = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--ratelimit")) want_ratelimit = 1;
        else if (!strcmp(argv[i], "--fault")) want_fault = 1;
        else {
            printf("Penggunaan: %s [--ratelimit] [--fault]\n", argv[0]);
            return 1;
        }
    }

    syscall_log = open_log("syscall.log");
    sched_log = open_log("context_switch.log");

    struct bpf_object *monitor = load_bpf("monitor.bpf.o");
    int count_map_fd = bpf_object__find_map_fd_by_name(monitor, "count_map");
    struct ring_buffer *rb_syscall = ring_buffer__new(bpf_object__find_map_fd_by_name(monitor, "data_map"), on_syscall, NULL, NULL);
    struct ring_buffer *rb_sched = ring_buffer__new(bpf_object__find_map_fd_by_name(monitor, "sched_map"), on_sched, NULL, NULL);
    struct ring_buffer *rb_fault = NULL;

    struct bpf_object *fault = NULL, *ratelimit = NULL;
    if (want_fault) {
        fault_log = open_log("fault.log");
        fault = load_bpf("page_fault.bpf.o");
        rb_fault = ring_buffer__new(bpf_object__find_map_fd_by_name(fault, "fault_map"), on_fault, NULL, NULL);
    }
    if (want_ratelimit)
        ratelimit = load_bpf("rate_limit.bpf.o");

    int num_cpus = libbpf_num_possible_cpus();
    __u64 syscall_vals[num_cpus];
    __u64 sched_vals[num_cpus];
    __u64 syscall_prev[num_cpus];
    memset(syscall_prev, 0, sizeof(syscall_prev));
    __u32 key_sys = 0;
    __u32 key_sched = 1;

    thrd_t syscall_thread, sched_thread, fault_thread;
    thrd_create(&syscall_thread, poll_ringbuf, rb_syscall);
    thrd_create(&sched_thread, poll_ringbuf, rb_sched);
    if (rb_fault) thrd_create(&fault_thread, poll_ringbuf, rb_fault);
    while (1) {
        sleep(1);
        bpf_map_lookup_elem(count_map_fd, &key_sys, syscall_vals);
        bpf_map_lookup_elem(count_map_fd, &key_sched, sched_vals);
        printf("=====================================\n");
        for (int i = 0; i < num_cpus; i++) {
            printf("CPU Core %d \nSyscalls/s: %llu \nContext Switches: %llu\n", i, syscall_vals[i] - syscall_prev[i], sched_vals[i]);
            syscall_prev[i] = syscall_vals[i];
        }
        printf("=====================================\n");
    }
    thrd_join(syscall_thread, NULL);
    thrd_join(sched_thread, NULL);
    if (rb_fault) thrd_join(fault_thread, NULL);
    ring_buffer__free(rb_syscall);
    ring_buffer__free(rb_sched);
    ring_buffer__free(rb_fault);
    bpf_object__close(monitor);
    if (fault) bpf_object__close(fault);
    if (ratelimit) bpf_object__close(ratelimit);
    return 0;
}
