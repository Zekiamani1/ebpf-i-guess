#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
struct Write {
    __u32 pid;
    int fd;
    __u64 count;
    char buffer[256];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} write_map SEC(".maps");
SEC("kprobe/__x64_sys_write")
int BPF_KPROBE(write_entry, struct pt_regs *regs) {  
    int fd = (int) PT_REGS_PARM1_CORE_SYSCALL(regs);       
    const char *buf = (const char *) PT_REGS_PARM2_CORE_SYSCALL(regs);
    __u64 count = (__u64) PT_REGS_PARM3_CORE_SYSCALL(regs);
    struct Write *data;
    data = bpf_ringbuf_reserve(&write_map, sizeof(*data), 0);
    if (data){
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->fd = fd;
        data->count = count;
        __u32 limit = count;
        if (limit >= sizeof(data->buffer)) {
            limit = sizeof(data->buffer) - 1;
        }

        limit &= 0xFF; 
        bpf_probe_read_user(data->buffer, limit, buf);
        data->buffer[limit] = '\0';
        bpf_ringbuf_submit(data, 0);
    }
    return 0;
}
char _license[] SEC("license") = "GPL";