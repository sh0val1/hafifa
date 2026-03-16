/* File: src/hello.c
 *
 * This is the user-space loader program that:
 * 1. Opens the compiled eBPF object file
 * 2. Loads the eBPF program into the kernel
 * 3. Attaches it to the specified hook point
 * 4. Keeps the program running until interrupted
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// libbpf provides the API for loading and managing eBPF programs
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Global flag for signal handling - volatile ensures visibility across threads
static volatile sig_atomic_t running = 1;

// Signal handler for graceful shutdown
// Called when user presses Ctrl+C (SIGINT) or sends SIGTERM
static void sig_handler(int sig)
{
    // Set running to 0 to exit the main loop
    running = 0;
}

int main(int argc, char **argv)
{
    // Declare pointers for eBPF object and link
    // bpf_object represents the loaded ELF file
    // bpf_link represents the attachment to a hook point
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link = NULL;
    int err;

    // Register signal handlers for graceful cleanup
    // SIGINT is sent when user presses Ctrl+C
    // SIGTERM is the standard termination signal
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load the eBPF object file
    // This parses the ELF file and prepares programs for loading
    // "hello.bpf.o" is the compiled eBPF bytecode
    obj = bpf_object__open_file("hello.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: Failed to open BPF object file\n");
        return 1;
    }

    // Load the eBPF program into the kernel
    // This triggers the verifier to validate the program
    // If verification fails, this function returns an error
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // Find the specific program by its section name
    // The section name matches what we defined with SEC() macro
    prog = bpf_object__find_program_by_name(obj, "hello_execve");
    if (!prog) {
        fprintf(stderr, "ERROR: Failed to find BPF program\n");
        err = -1;
        goto cleanup;
    }

    // Attach the program to its hook point
    // For kprobes, this creates the attachment automatically
    // based on the SEC("kprobe/...") definition
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Failed to attach BPF program\n");
        link = NULL;
        err = -1;
        goto cleanup;
    }

    // Print instructions for the user
    printf("Successfully loaded and attached eBPF program!\n");
    printf("Run 'sudo cat /sys/kernel/debug/tracing/trace_pipe' to see output\n");
    printf("Press Ctrl+C to exit...\n");

    // Main loop - keep the program running
    // The eBPF program continues to execute as long as this runs
    while (running) {
        // Sleep to avoid busy-waiting and reduce CPU usage
        sleep(1);
    }

    printf("\nDetaching and cleaning up...\n");

cleanup:
    // Clean up resources in reverse order of creation
    // Destroy the link first to detach from the hook
    if (link)
        bpf_link__destroy(link);

    // Close the object to free all associated resources
    bpf_object__close(obj);

    return err;
}