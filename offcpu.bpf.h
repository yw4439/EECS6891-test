#ifndef OFFCPU_BPF_H
#define OFFCPU_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Define constants, structs, or shared declarations here
// Example: extern int example_function();

// Map declaration
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

// Function prototype
SEC("tracepoint/sched/sched_switch")
int handle_sched_switch(struct task_struct *prev, struct task_struct *next);

#endif // OFFCPU_BPF_H
