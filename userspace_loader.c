#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "offcpu.bpf.h"

#define INTERVAL 2

int main() {
    struct bpf_object *obj;
    int err;

    // Load BPF program
    obj = bpf_object__open_file("offcpu.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach BPF program to tracepoint
    struct bpf_program *prog;
    prog = bpf_object__find_program_by_title(obj, "tracepoint/sched/sched_switch");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        bpf_object__close(obj);
        return 1;
    }

    if (bpf_prog_attach(prog_fd, 0, BPF_TRACE_FENTRY, 0) < 0) {
        fprintf(stderr, "Failed to attach BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF tracepoint program attached. Press ENTER to exit...\n");
    getchar();

    bpf_prog_detach(prog_fd, BPF_TRACE_FENTRY);
    bpf_object__close(obj);
    return 0;
}
