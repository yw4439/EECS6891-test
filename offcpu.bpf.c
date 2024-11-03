#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>

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
    __type(key, u64);
    __type(value, u64);
} offcpu_histogram SEC(".maps");

// Helper function to calculate log2l
static __always_inline u64 log2l(u64 v) {
    u64 r = 0;
    while (v >>= 1)
        r++;
    return r;
}

// BPF program for the scheduler switch tracepoint
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(void *ctx) {
    u64 ts = bpf_ktime_get_ns();
    u32 prev_pid, next_pid;
    u64 *start_ts, delta, key;

    // Read prev_pid and next_pid directly from the tracepoint context
    bpf_core_read(&prev_pid, sizeof(prev_pid), (void *)((char *)ctx + 24));
    bpf_core_read(&next_pid, sizeof(next_pid), (void *)((char *)ctx + 56));

    // Record the start time for the previous PID if it was running
    long prev_state;
    bpf_core_read(&prev_state, sizeof(prev_state), (void *)((char *)ctx + 32));
    if (prev_state == 0) { // TASK_RUNNING
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    // Calculate the off-CPU time for the next PID if it has a recorded start time
    start_ts = bpf_map_lookup_elem(&start_time, &next_pid);
    if (start_ts) {
        delta = ts - *start_ts;
        key = log2l(delta / 1000); // Convert from nanoseconds to microseconds
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

char _license[] SEC("license") = "GPL";
