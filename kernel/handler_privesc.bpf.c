// handler_privesc.bpf.c
// Tail-called for: setuid (105), setns (308), unshare (272), ptrace (101)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_privesc(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_nr = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    __u64 cg = bpf_get_current_cgroup_id();
    __u64 now = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    int should_kill = 0;

    if (syscall_nr == 272) {  // unshare
        long flags_long = 0;
        BPF_CORE_READ_INTO(&flags_long, regs, di);  // rdi = flags
        long flags = flags_long;

        // CLONE_NEWCGROUP: register for behavior inheritance on next syscall
        if (flags & 0x02000000) {
            bpf_map_update_elem(&pending_cgroup_inherit, &pid_tgid, &cg, BPF_ANY);
        }

        // CLONE_NEWNS (mount) or CLONE_NEWUSER: namespace escape attempt
        if (flags & 0x00020000 || flags & 0x10000000) {
            should_kill = 1;
        }
    }

    else if (syscall_nr == 105) {  // setuid
        long uid_long = 0;
        BPF_CORE_READ_INTO(&uid_long, regs, di);
        if (uid_long == 0) {
            should_kill = 1;
        }
    }

    // setns and ptrace: always suspicious in container context
    else if (syscall_nr == 308 || syscall_nr == 101) {
        should_kill = 1;
    }

    if (should_kill) {
        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_PRIVESC;
            state->bit_ts[4] = now;
        }

        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_PRIVESC;
            alert->pid = pid_tgid >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_PRIVESC;
            alert->extra = (__u64)syscall_nr;
            bpf_ringbuf_submit(alert, 0);
        }

        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
