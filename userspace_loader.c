#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>          // For sleep()
#include <bpf/bpf.h>         // For BPF-related functions
#include <bpf/libbpf.h>      // For libbpf functions
#include "vmlinux.h"         // Use quotes for local vmlinux.h
#include "offcpu.bpf.h"      // This should match the name of your BPF program header

#define INTERVAL 2           // Polling interval in seconds

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd, map_fd;

    // Load BPF program from object file
    obj = bpf_object__open_file("offcpu.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object file\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Get file descriptor for BPF program
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_sched_switch");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program by name\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return 1;
    }

    // Attach BPF program to the tracepoint
    if (bpf_prog_attach(prog_fd, 0, BPF_TRACE_FENTRY, 0) < 0) {
        perror("Failed to attach BPF program");
        return 1;
    }
    printf("BPF tracepoint program attached. Press ENTER to exit...\n");

    // Polling loop to keep the program running
    while (1) {
        sleep(INTERVAL);
        // Here you could add code to fetch data from your BPF maps if needed
    }

    // Detach the BPF program
    if (bpf_prog_detach(prog_fd, BPF_TRACE_FENTRY) < 0) {
        perror("Failed to detach BPF program");
    }

    bpf_object__close(obj);
    return 0;
}
