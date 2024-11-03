
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <bpf/libbpf.h>

static int parse_args(int argc, char **argv, int *interval, int *pid) {
    // Parse time interval and optional pid argument
    return 0;
}

int main(int argc, char **argv) {
    int interval = 1;
    int pid = -1;

    parse_args(argc, argv, &interval, &pid);

    struct bpf_object *obj;
    struct bpf_program *prog;
    int map_fd;

    obj = bpf_object__open_file("offcpu.bpf.o", NULL);
    bpf_object__load(obj);
    prog = bpf_object__find_program_by_name(obj, "trace_sched_switch");

    // Attach program and handle polling of histograms
    printf("Collecting data...\n");

    while (1) {
        sleep(interval);
        // Fetch histogram data and print
    }

    bpf_object__close(obj);
    return 0;
}
