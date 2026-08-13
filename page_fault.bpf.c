#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <asm-generic/errno-base.h>
struct Fault {
    __u32 pid;
    char name[16];
    __u64 address;
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} fault_map SEC(".maps");
SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(handle_mm_fault_entry, struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
    struct Fault *fault;
    fault = bpf_ringbuf_reserve(&fault_map, sizeof(*fault), 0);
    if (!fault) return 0;
    fault->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&fault->name, sizeof(fault->name));
    fault->address = (__u64) address; 

    bpf_ringbuf_submit(fault, 0);

    return 0;
}
char _license[] SEC("license") = "GPL";
