#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno-base.h>
struct Data {
    __u32 pid;
    char name[16];
    __u32 cpu_id;
    __u64 timestamp;
    long syscall_id;
    __u64 args[6];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} count_map SEC(".maps");
struct Sched {
    __u32 pid;
    char name[16];
    __u32 cpu_id;
    __u64 timestamp;
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} data_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sched_map SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct Data *data;
    data = bpf_ringbuf_reserve(&data_map, sizeof(*data), 0);
    __u64 *count = bpf_map_lookup_elem(&count_map, &key);
    if (count)
    {
        *count += 1;
    }
    if (data) {
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->cpu_id = bpf_get_smp_processor_id();
        data->timestamp = bpf_ktime_get_ns();
        data->syscall_id = ctx->id;
        bpf_get_current_comm(&data->name, sizeof(data->name));
        bpf_ringbuf_submit(data, 0);
    }
    return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(void *ctx) {
    __u32 key = 1;
    __u64 *count = bpf_map_lookup_elem(&count_map, &key);
    if (count) {
        *count += 1;
    }
    struct Sched *sched = bpf_ringbuf_reserve(&sched_map, sizeof(*sched), 0);
    if (sched) {
        sched->pid = bpf_get_current_pid_tgid() >> 32;
        sched->cpu_id = bpf_get_smp_processor_id();
        sched->timestamp = bpf_ktime_get_ns();
        bpf_get_current_comm(&sched->name, sizeof(sched->name));
        bpf_ringbuf_submit(sched, 0);
    }
    return 0;
}
char _license[] SEC("license") = "GPL";