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
SEC("fentry/ksys_write")
int BPF_PROG(write_entry, unsigned int fd, const char *buf, size_t count) {
    struct Write *data;
    data = bpf_ringbuf_reserve(&write_map, sizeof(*data), 0);
    if (data) {
        data->pid = bpf_get_current_pid_tgid() >> 32;
        data->fd = fd;
        data->count = count;
        __u32 limit = count;
        if (limit > sizeof(data->buffer) - 1) {
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