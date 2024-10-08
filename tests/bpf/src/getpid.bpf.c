// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 /* one page */);
} ringbuf SEC(".maps");

static __noinline u64 symbolization_target(void)
{
    asm volatile ("");
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle__getpid(void *ctx)
{
    u64 *value;

    value = bpf_ringbuf_reserve(&ringbuf, sizeof(*value), 0);
    if (!value) {
        bpf_printk("handle__getpid: failed to reserve ring buffer space");
        return 1;
    }

    (void)symbolization_target();

    *value = (u64)&symbolization_target;
    bpf_printk("symbolization_target = %lx\n", *value);
    bpf_ringbuf_submit(value, 0);
    bpf_printk("handle__getpid: submitted ringbuf value");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
