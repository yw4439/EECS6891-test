# Compiler and Flags
CLANG ?= clang
CFLAGS = -O2 -target bpf -c -g
USERSPACE_CFLAGS = -O2 -Wall -I/usr/include
USERSPACE_LINKER_FLAGS = -lbpf

# BPF Source and Object Files
BPF_SRC = offcpu.bpf.c
BPF_OBJ = $(BPF_SRC:.c=.o)
USERSPACE_SRC = userspace_loader.c
USERSPACE_BIN = $(USERSPACE_SRC:.c=)

# Clang system includes
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

all: $(BPF_OBJ) $(USERSPACE_BIN)

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) $(BPF_SRC) -o $(BPF_OBJ)

$(USERSPACE_BIN): $(USERSPACE_SRC)
	$(CLANG) $(USERSPACE_CFLAGS) $(USERSPACE_SRC) -o $(USERSPACE_BIN) $(USERSPACE_LINKER_FLAGS)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(BPF_OBJ) $(USERSPACE_BIN)

cleanall: clean
	rm -f vmlinux.h

.PHONY: all clean
