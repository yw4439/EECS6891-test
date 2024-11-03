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

// Minimal struct task_struct definition for eBPF usage
struct task_struct {
    u32 pid;
    u32 flags;
};

// BPF program for the scheduler switch tracepoint
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct task_struct *prev, struct task_struct *next) {
    u64 key, *value;
    u64 ts = bpf_ktime_get_ns();
    u64 prev_pid, next_pid;

    bpf_core_read(&prev_pid, sizeof(prev_pid), &prev->pid);
    bpf_core_read(&next_pid, sizeof(next_pid), &next->pid);

    u32 prev_flags;
    bpf_core_read(&prev_flags, sizeof(prev_flags), &prev->flags);

    if (prev_flags & (1 << 0)) {
        bpf_map_update_elem(&start_time, &prev_pid, &ts, BPF_ANY);
    }

    value = bpf_map_lookup_elem(&start_time, &next_pid);
    if (value) {
        u64 delta = ts - *value;
        key = delta / 1000;
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
