# Define the compiler and flags
CLANG ?= clang
CFLAGS = -O2 -target bpf -c -g
USERSPACE_CFLAGS = -O2 -Wall -I/usr/include
USERSPACE_LINKER_FLAGS = -lbpf

# Source files
BPF_SRC = offcpu.bpf.c
USERSPACE_SRC = userspace_loader.c

# Object files
BPF_OBJ = $(BPF_SRC:.c=.o)
USERSPACE_BIN = $(USERSPACE_SRC:.c=)

# System includes
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Build all
all: $(BPF_OBJ) $(USERSPACE_BIN)

# Compile the BPF program
$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) $(CFLAGS) $(CLANG_BPF_SYS_INCLUDES) $(BPF_SRC) -o $(BPF_OBJ)

# Compile the userspace program
$(USERSPACE_BIN): $(USERSPACE_SRC)
	$(CLANG) $(USERSPACE_CFLAGS) $(USERSPACE_SRC) -o $(USERSPACE_BIN) $(USERSPACE_LINKER_FLAGS)

# Generate vmlinux.h if it doesn't exist
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Clean up
clean:
	rm -f $(BPF_OBJ) $(USERSPACE_BIN)

.PHONY: all clean
