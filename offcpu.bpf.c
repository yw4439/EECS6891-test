#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Define maps for storing data
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);           // PID key
    __type(value, u64);         // Start timestamp value
    __uint(max_entries, 1024);
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);           // Time delta in microseconds
    __type(value, u64);         // Histogram bucket count
    __uint(max_entries, 1024);
} offcpu_histogram SEC(".maps");

// BPF program to trace task switches
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct task_struct *prev, struct task_struct *next) {
    u64 ts = bpf_ktime_get_ns();  // Current timestamp in nanoseconds
    u64 prev_pid, next_pid;

    // Read PIDs of previous and next tasks
    bpf_core_read(&prev_pid, sizeof(prev_pid), &prev->pid);
    bpf_core_read(&next_pid, sizeof(next_pid), &next->pid);

    // Track off-CPU time for TASK_RUNNING state
    u32 prev_flags;
    bpf_core_read(&prev_flags, sizeof(prev_flags), &prev->flags);
    if (prev_flags & (1 << 0)) {  // TASK_RUNNING check
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    u64 *start = bpf_map_lookup_elem(&start_time, &next_pid);
    if (start) {
        u64 delta = ts - *start;
        u64 key = delta / 1000;  // Convert to microseconds
        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &key);

        if (count) {
            (*count)++;
        } else {
            u64 init_val = 1;
            bpf_map_update_elem(&offcpu_histogram, &key, &init_val, BPF_ANY);
        }

        bpf_map_delete_elem(&start_time, &next_pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
