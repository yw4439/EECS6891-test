#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);    // pid of the task
    __type(value, u64);  // start timestamp
    __uint(max_entries, 1024);
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);    // latency (in microseconds)
    __type(value, u64);  // histogram count
    __uint(max_entries, 1024);
} offcpu_histogram SEC(".maps");

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct task_struct *prev, struct task_struct *next) {
    u64 key, *value;
    u64 ts = bpf_ktime_get_ns();  // Current timestamp in nanoseconds
    u64 prev_pid, next_pid;

    // Read task_struct fields safely
    bpf_core_read(&prev_pid, sizeof(prev_pid), &prev->pid);
    bpf_core_read(&next_pid, sizeof(next_pid), &next->pid);

    // Use flags instead of state to check for TASK_RUNNING
    u32 prev_flags;
    bpf_core_read(&prev_flags, sizeof(prev_flags), &prev->flags);

    // If prev task is TASK_RUNNING, record its start time
    if (prev_flags & (1 << 0)) {
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    // Check if the task being switched in has a start time recorded
    value = bpf_map_lookup_elem(&start_time, &next_pid);
    if (value) {
        u64 delta = ts - *value;  // Calculate the latency
        key = delta / 1000;       // Convert to microseconds
        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &key);

        if (count) {
            (*count)++;  // Increment the histogram bucket
        } else {
            u64 init_val = 1;
            bpf_map_update_elem(&offcpu_histogram, &key, &init_val, BPF_ANY);
        }

        // Remove the start time entry
        bpf_map_delete_elem(&start_time, &next_pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
