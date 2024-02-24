ARCH := $(subst x86_64,x86,$(shell uname -m))
CFLAGS ?= -D__TARGET_ARCH_$(ARCH)

.PHONY: probe
probe: vmlinux.h
	clang $(CFLAGS) -g -O2 -c -target bpf -o kernel/profile.o kernel/profile.c

.PHONY: vmlinux.h
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > kernel/vmlinux.h
