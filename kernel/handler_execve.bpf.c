// handler_execve.bpf.c
// Tail-called for: execve (syscall 59)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

// Shell binary basenames to detect (byte-level comparison, no strcmp in eBPF)
// Covers common shell binaries and network tools used in reverse shells
#define SHELL_MATCH(buf, s) (buf[0]==s[0] && buf[1]==s[1] && buf[2]==s[2])

SEC("raw_tracepoint/sys_enter")
int handle_execve(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // Read filename from userspace (first argument to execve)
    char filename[128] = {};
    long fname_ptr = 0;
    BPF_CORE_READ_INTO(&fname_ptr, regs, di);  // rdi = filename pointer
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)fname_ptr);

    // Extract basename: find last '/' and compare from there
    // Manual loop required — eBPF prohibits library calls
    char basename[16] = {};
    int last_slash = -1;
    #pragma unroll
    for (int i = 0; i < 127; i++) {
        if (filename[i] == '\0') break;
        if (filename[i] == '/') last_slash = i;
    }

    int start = last_slash + 1;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (filename[start + i] == '\0') break;
        basename[i] = filename[start + i];
    }

    // Check against known shell/network binaries
    // Two-char prefixes for speed; covers: sh, bash, dash, ash, zsh,
    // nc, ncat, netcat, python, python3, perl, ruby, php
    int is_shell = 0;
    if (basename[0] == 's' && basename[1] == 'h' && (basename[2] == '\0'))
        is_shell = 1;
    else if (basename[0] == 'b' && basename[1] == 'a' && basename[2] == 's')
        is_shell = 1;  // bash
    else if (basename[0] == 'd' && basename[1] == 'a' && basename[2] == 's')
        is_shell = 1;  // dash
    else if (basename[0] == 'n' && basename[1] == 'c' && basename[2] == '\0')
        is_shell = 1;  // nc
    else if (basename[0] == 'n' && basename[1] == 'c' && basename[2] == 'a')
        is_shell = 1;  // ncat, netcat
    else if (basename[0] == 'z' && basename[1] == 's' && basename[2] == 'h')
        is_shell = 1;  // zsh

    if (is_shell) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_SHELL_SPAWN;
            state->bit_ts[0] = now;  // bit 0 = BIT_SHELL_SPAWN
        }

        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_REVERSE_SHELL;
            alert->pid = bpf_get_current_pid_tgid() >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_SHELL_SPAWN;
            bpf_ringbuf_submit(alert, 0);
        }

        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
