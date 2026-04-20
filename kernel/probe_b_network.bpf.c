// probe_b_network.bpf.c
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

// Entry: stash sock pointer for the return probe
// The socket fields (dst_addr, dst_port) aren't populated at entry time
SEC("kprobe/tcp_v4_connect")
int trace_connect_entry(struct pt_regs *ctx) {
    // tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    // sk is the first argument — PT_REGS_PARM1 gets rdi
    __u64 sk_ptr = PT_REGS_PARM1(ctx);
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Stash sk pointer keyed by pid_tgid for the return probe
    // LRU_HASH ensures this doesn't exhaust under flood attacks
    bpf_map_update_elem(&connect_sk_stash, &pid_tgid, &sk_ptr, BPF_ANY);
    return 0;
}

// Return: connection is established, read socket fields
SEC("kretprobe/tcp_v4_connect")
int trace_connect_return(struct pt_regs *ctx) {
    // Only process successful connects (return value = 0)
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *sk_ptr = bpf_map_lookup_elem(&connect_sk_stash, &pid_tgid);
    if (!sk_ptr) return 0;

    struct sock *sk = (struct sock *)(*sk_ptr);
    bpf_map_delete_elem(&connect_sk_stash, &pid_tgid);

    // Read 4-tuple from socket structure via CO-RE
    __u32 dst_addr = 0;
    __u16 dst_port = 0;
    BPF_CORE_READ_INTO(&dst_addr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&dst_port, sk, __sk_common.skc_dport);
    dst_port = __bpf_ntohs(dst_port);  // convert from network to host byte order

    // Resolve destination IP to container cgroup
    __u64 *dst_cg_ptr = bpf_map_lookup_elem(&ip_to_cgroup, &dst_addr);
    if (!dst_cg_ptr) return 0;  // not a known container — skip
    __u64 dst_cg = *dst_cg_ptr;

    __u64 src_cg = bpf_get_current_cgroup_id();
    __u64 now = bpf_ktime_get_ns();

    // ── TWO-HOP INVARIANT CHECK ───────────────────────────────────────
    struct behavior_state *src_state = bpf_map_lookup_elem(&container_behavior, &src_cg);
    if (src_state) {
        // Set lateral connect bit with per-bit timestamp
        src_state->flags |= BIT_LATERAL_CONNECT;
        src_state->bit_ts[1] = now;
        src_state->conn_dst_cg = dst_cg;
        src_state->conn_port = dst_port;

        // Lazy expiry: clear bits whose per-bit timestamps have expired
        // This prevents stale-bit false positives (v5 fix for the Monday-Friday problem)
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if ((now - src_state->bit_ts[i]) > TWOHOP_WINDOW_NS) {
                src_state->flags &= ~(1ULL << i);
            }
        }

        // Check: was there a shell spawn (bit0) or fd-redirect (bit6) recently?
        // Using per-bit timestamps — ONLY check the relevant bits' own timestamps
        __u64 shell_ts    = src_state->bit_ts[0];  // BIT_SHELL_SPAWN timestamp
        __u64 fd_redir_ts = src_state->bit_ts[6];  // BIT_FD_REDIRECT timestamp
        __u64 latest_dangerous = shell_ts > fd_redir_ts ? shell_ts : fd_redir_ts;

        if ((now - latest_dangerous) < TWOHOP_WINDOW_NS) {
            if (src_state->flags & (BIT_SHELL_SPAWN | BIT_FD_REDIRECT)) {
                // TWO-HOP ATTACK PATTERN DETECTED IN KERNEL
                // (shell OR reverse shell) + lateral connect within 5 seconds
                struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
                if (alert) {
                    alert->type = ALERT_TWO_HOP;
                    alert->pid = pid_tgid >> 32;
                    alert->cgroup_id = src_cg;
                    alert->timestamp = now;
                    alert->flags = src_state->flags;
                    alert->extra = dst_cg;  // which container was targeted
                    bpf_ringbuf_submit(alert, 0);
                }
                bpf_send_signal(9);
            }
        }
    }

    // Emit connection event to TELEMETRY ring buffer (not alerts)
    // This is used by Tier 3 for novel-edge detection and sheaf calibration
    struct alert_t *evt = bpf_ringbuf_reserve(&telemetry_rb, sizeof(struct alert_t), 0);
    if (evt) {
        evt->type = EVENT_CONNECTION;
        evt->cgroup_id = src_cg;
        evt->timestamp = now;
        evt->extra = ((__u64)dst_addr << 32) | (__u64)dst_port;
        evt->flags = dst_cg;   // reusing flags field for dst_cgroup_id
        bpf_ringbuf_submit(evt, 0);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
