// handler_file.bpf.c
// Tail-called for: openat (syscall 257)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_file(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    // openat(dirfd, pathname, flags, mode)
    // rsi = pathname (second argument)
    long path_ptr = 0;
    BPF_CORE_READ_INTO(&path_ptr, regs, si);  // x86_64: rsi = second arg

    char path[128] = {};
    bpf_probe_read_user_str(path, sizeof(path), (void *)path_ptr);

    // Byte-level prefix matching against sensitive paths
    // eBPF prohibits strcmp() — manual comparison required
    // Patterns: /etc/shadow, /etc/passwd, /proc/1/ns, /var/run/secrets
    int is_sensitive = 0;

    // /etc/shadow
    if (path[0]=='/' && path[1]=='e' && path[2]=='t' && path[3]=='c' &&
        path[4]=='/' && path[5]=='s' && path[6]=='h' && path[7]=='a')
        is_sensitive = 1;

    // /etc/passwd
    if (path[0]=='/' && path[1]=='e' && path[2]=='t' && path[3]=='c' &&
        path[4]=='/' && path[5]=='p' && path[6]=='a' && path[7]=='s')
        is_sensitive = 1;

    // /proc/1/ns (namespace probe — host PID 1's namespaces)
    if (path[0]=='/' && path[1]=='p' && path[2]=='r' && path[3]=='o' &&
        path[4]=='c' && path[5]=='/' && path[6]=='1' && path[7]=='/')
        is_sensitive = 1;

    // /var/run/secrets (Kubernetes service account tokens)
    if (path[0]=='/' && path[1]=='v' && path[2]=='a' && path[3]=='r' &&
        path[4]=='/' && path[5]=='r' && path[6]=='u' && path[7]=='n' &&
        path[8]=='/' && path[9]=='s' && path[10]=='e' && path[11]=='c')
        is_sensitive = 1;

    if (is_sensitive) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            // Set appropriate bit based on path type.
            // /proc/1/: path[6]='1', path[7]='/' (not path[5]/'/'=path[6]/'1')
            if (path[6] == '1' && path[7] == '/') {
                state->flags |= BIT_NS_PROBE;   // /proc/1/ access = namespace probe
                state->bit_ts[3] = now;         // bit 3 = BIT_NS_PROBE
            } else {
                state->flags |= BIT_SENSITIVE_FILE;
                state->bit_ts[2] = now;         // bit 2 = BIT_SENSITIVE_FILE
            }
        }

        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_SENSITIVE_FILE;
            alert->pid = bpf_get_current_pid_tgid() >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_SENSITIVE_FILE;
            bpf_ringbuf_submit(alert, 0);
        }

        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
