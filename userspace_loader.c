#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    int prog_fd;
    char filename[] = "offcpu.bpf.o";

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", filename);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_sched_switch");
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program FD\n");
        return 1;
    }

    if (bpf_prog_attach(prog_fd, 0, BPF_TRACE_FENTRY, 0) < 0) {
        perror("Failed to attach BPF program");
        return 1;
    }

    printf("BPF program attached. Press ENTER to exit...\n");
    getchar();

    if (bpf_prog_detach(prog_fd, BPF_TRACE_FENTRY) < 0) {
        perror("Failed to detach BPF program");
        return 1;
    }

    bpf_object__close(obj);
    return 0;
}
