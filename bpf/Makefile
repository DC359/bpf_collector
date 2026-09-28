# Build the BPF snapshot+exit collector ON THE TARGET HOST.
#
# Requires:
#   - clang/llvm     (compile the BPF object, -target bpf)
#   - bpftool        (generate vmlinux.h from local BTF + the skeleton header)
#   - libbpf-devel   (headers + libbpf.so for the userspace loader)
#   - /sys/kernel/btf/vmlinux present (CO-RE)
#
# Output: ./cgroup_cpu_snap  (the userspace driver with the BPF object embedded)

CLANG    ?= clang
BPFTOOL  ?= bpftool
CC       ?= cc

ARCH     := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
VMLINUX  := vmlinux.h
BPF_SRC  := cgroup_cpu_snap.bpf.c
BPF_OBJ  := cgroup_cpu_snap.bpf.o
SKEL     := cgroup_cpu_snap.skel.h
USER_SRC := cgroup_cpu_snap.c
TARGET   := cgroup_cpu_snap

# libbpf headers usually live under /usr/include (libbpf-devel). Allow override.
LIBBPF_CFLAGS ?= -I/usr/include
LIBBPF_LIBS   ?= -lbpf -lelf -lz

.PHONY: all clean

all: $(TARGET)

# 1) Generate vmlinux.h from the running kernel's BTF (CO-RE source of truth).
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# 2) Compile the BPF program to an object (BPF target).
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. $(LIBBPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)

# 3) Generate the skeleton header from the BPF object.
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

# 4) Compile the userspace loader (native arch) and link libbpf.
$(TARGET): $(USER_SRC) $(SKEL)
	$(CC) -g -O2 -I. $(LIBBPF_CFLAGS) $(USER_SRC) -o $(TARGET) $(LIBBPF_LIBS)

clean:
	rm -f $(BPF_OBJ) $(SKEL) $(VMLINUX) $(TARGET)
