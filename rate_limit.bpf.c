#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno-base.h>
#define MAX_SYSCALL_PER_SEC 100
#define ONE_SEC 1000000000ULL
struct rate_limit_state {
    __u64 start;
    __u64 count;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, struct rate_limit_state);
} rate_limit_map SEC(".maps");

SEC("lsm/file_permission")
int BPF_PROG(rate_limit_write, struct file *file, int mask){
    if (!(mask & 0x02)) { //0x02 = mask write
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid == 0) return 0;
    __u64 now = bpf_ktime_get_ns();
    struct rate_limit_state *state = bpf_map_lookup_elem(&rate_limit_map, &pid);
    if (!state) {
        struct rate_limit_state new_state = {
            .start = now,
            .count = 1
        };
        bpf_map_update_elem(&rate_limit_map, &pid, &new_state, BPF_ANY);
        return 0;
    }
    if (now - state->start >= ONE_SEC) {
        //reset
        state->start = now;
        state->count = 1;
    } else if (state->count >= MAX_SYSCALL_PER_SEC) {
        //tolak syscall
        return -EAGAIN;
    } else{
        state->count++;
    }
    return 0;
}
char _license[] SEC("license") = "GPL";