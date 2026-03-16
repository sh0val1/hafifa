# File: Makefile
#
# Build system for eBPF programs
# Uses Clang for eBPF compilation and GCC for user-space code

# Compiler settings
# clang is required for eBPF - GCC doesn't support eBPF target
CLANG := clang
CC := gcc

# Architecture detection for proper header includes
# eBPF programs need architecture-specific definitions
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Compiler flags for eBPF programs
# -target bpf: Generate eBPF bytecode
# -D__TARGET_ARCH_$(ARCH): Define architecture for CO-RE
# -O2: Optimization required for eBPF (verifier needs it)
# -g: Include debug info for better error messages
BPF_CFLAGS := -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -O2 \
              -g \
              -Wall

# Compiler flags for user-space programs
# -lbpf: Link against libbpf
# -lelf: Link against libelf for ELF parsing
CFLAGS := -Wall -O2
LDFLAGS := -lbpf -lelf

# Default target builds everything
all: hello.bpf.o hello

# Rule to compile eBPF program
# Input: src/hello.bpf.c (eBPF source)
# Output: hello.bpf.o (eBPF bytecode in ELF format)
hello.bpf.o: src/hello.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Rule to compile user-space loader
# Links against libbpf for eBPF management functions
hello: src/hello.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

# Clean up build artifacts
clean:
	rm -f *.o hello

# Phony targets don't correspond to actual files
.PHONY: all clean