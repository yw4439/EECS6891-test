#include <bpf/libbpf.h>
#include <unistd.h>  // For sleep
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static int running = 1;

void handle_signal(int sig) {
    running = 0;
}

int main() {
    struct bpf_object *obj;
    int prog_fd;

    signal(SIGINT, handle_signal);

    obj = bpf_object__open_file("offcpu.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF program.\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_sched_switch");
    if (!prog) {
        fprintf(stderr, "Error finding BPF program by name.\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error getting program file descriptor.\n");
        return 1;
    }

    if (bpf_prog_attach(prog_fd, 0, BPF_TRACE_FENTRY, 0)) {
        fprintf(stderr, "Error attaching BPF program.\n");
        return 1;
    }

    printf("BPF program attached. Press Ctrl+C to exit...\n");

    while (running) {
        sleep(1);
    }

    bpf_prog_detach(prog_fd, BPF_TRACE_FENTRY);
    bpf_object__close(obj);

    printf("BPF program detached and resources cleaned up.\n");

    return 0;
}
