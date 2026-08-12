#include "vmlinux.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
struct Data{
    __u64  count;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct Data);
} stats_map SEC(".maps");

SEC("tp/raw_syscalls/sys_enter")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    Data *data = bpf_map_lookup_elem(&stats_map, &key);
    if (data) {
        data->count += 1;
    }
    return 0;
}

SEC("tp/sched/sched_switch")
int handle_sched_switch(void *ctx) {
    __u32 key = 1; 
    Data *data = bpf_map_lookup_elem(&stats_map, &key);
    if (data) {
        data->count += 1; 
    }
    return 0;
}
char _license[] SEC("license") = "GPL";