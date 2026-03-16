/* File: src/hello.bpf.c
 *
 * This is the eBPF program that runs in kernel space.
 * It attaches to the execve system call and logs whenever
 * a new process is executed.
 */

// Required header for eBPF helper definitions
// This provides access to eBPF helper functions and types
#include <linux/bpf.h>

// Provides BPF helper function macros like SEC() and BPF_KPROBE()
// SEC() macro defines the ELF section where the program is placed
#include <bpf/bpf_helpers.h>

// Provides macros for kprobe/kretprobe attachment
#include <bpf/bpf_tracing.h>

// Define the license - GPL is required for many helper functions
// Without GPL license, certain eBPF helpers won't be available
char LICENSE[] SEC("license") = "GPL";

// SEC("kprobe/...") tells the loader where to attach this program
// We're attaching to __x64_sys_execve - the execve syscall handler
// This function is called every time a new program is executed
SEC("kprobe/__x64_sys_execve")
int hello_execve(struct pt_regs *ctx)
{
    // Get the process ID and thread group ID
    // bpf_get_current_pid_tgid() returns both in a single 64-bit value
    // Upper 32 bits = TGID (process ID), Lower 32 bits = PID (thread ID)
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;  // Extract the process ID

    // Get the current process name (comm)
    // This buffer will hold up to 16 characters of the process name
    char comm[16];

    // bpf_get_current_comm() fills the buffer with current process name
    // Returns 0 on success, negative error code on failure
    bpf_get_current_comm(&comm, sizeof(comm));

    // Print a message to the kernel trace pipe
    // bpf_printk() is a debugging helper - output goes to:
    // /sys/kernel/debug/tracing/trace_pipe
    // Format: "Hello from eBPF! PID: <pid>, Command: <comm>"
    bpf_printk("Hello from eBPF! PID: %d, Command: %s\n", pid, comm);

    // Return 0 to indicate successful execution
    // Non-zero returns can affect program behavior depending on type
    return 0;
}