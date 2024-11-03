#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>  // This should define u32, u64 and other types

// Define u32 and u64 explicitly if they are still undefined
#ifndef u32
#define u32 __u32
#endif

#ifndef u64
#define u64 __u64
#endif

struct hist_key {
    u64 slot;
};

// Define maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct hist_key);
    __type(value, u64);
} offcpu_histogram SEC(".maps");

// Minimal struct task_struct definition for eBPF usage
struct task_struct {
    u32 pid;
    u32 flags;
};

// Helper function to calculate histogram slot
static __always_inline u64 log2l(u64 v) {
    u64 r = 0;
    while (v >>= 1)
        r++;
    return r;
}

// BPF program for the scheduler switch tracepoint
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct task_struct *prev, struct task_struct *next) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid = 0, next_pid = 0;

    // Read previous and next task's PID
    bpf_core_read(&prev_pid, sizeof(prev_pid), &prev->pid);
    bpf_core_read(&next_pid, sizeof(next_pid), &next->pid);

    u32 prev_flags = 0;
    bpf_core_read(&prev_flags, sizeof(prev_flags), &prev->flags);

    // If the previous task was in a running state, store its timestamp
    if (prev_flags & (1 << 0)) {
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    // Check if the next task was previously recorded in start_time
    u64 *start_ts = bpf_map_lookup_elem(&start_time, &next_pid);
    if (start_ts) {
        u64 delta = ts - *start_ts;
        u64 usec = delta / 1000;  // Convert nanoseconds to microseconds

        struct hist_key key = {.slot = log2l(usec)};
        u64 *count = bpf_map_lookup_elem(&offcpu_histogram, &key);
        
        if (count) {
            (*count)++;
        } else {
            u64 init_val = 1;
            bpf_map_update_elem(&offcpu_histogram, &key, &init_val, BPF_ANY);
        }

        // Clean up
        bpf_map_delete_elem(&start_time, &next_pid);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
