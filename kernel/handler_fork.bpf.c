// handler_fork.bpf.c
// Tail-called for: clone (syscall 56) and clone3 (syscall 435)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_fork(struct bpf_raw_tracepoint_args *ctx) {
    __u64 cg = bpf_get_current_cgroup_id();
    __u64 now = bpf_ktime_get_ns();

    struct rate_state *rs = bpf_map_lookup_elem(&rate_map, &cg);
    if (!rs) {
        // First fork from this container — initialize state
        struct rate_state new_rs = {};
        new_rs.window_start = now;
        new_rs.count = 1;
        bpf_map_update_elem(&rate_map, &cg, &new_rs, BPF_NOEXIST);
        return 0;
    }

    // ── Window rotation (1-second windows) ───────────────────────────
    __u64 window_ns = 1000000000ULL;  // 1 second in nanoseconds
    if (now - rs->window_start > window_ns) {
        // Rotate: current → prev → prev_prev
        rs->prev_prev_count = rs->prev_count;
        rs->prev_count = rs->count;
        rs->count = 1;  // start new window with current fork
        rs->window_start = now;
    } else {
        rs->count += 1;
    }

    // ── ACCELERATION INVARIANT ────────────────────────────────────────
    // Only check when we have 3 full windows of data AND rate exceeds floor.
    // The floor (50 forks/s) prevents false positives on startup bursts.
    __u64 rate = rs->count;
    __u64 prev = rs->prev_count;
    __u64 prev_prev = rs->prev_prev_count;

    if (rate > 50 && prev > 0 && prev_prev > 0) {
        // Second discrete derivative (d2)
        // d2 > 0 means rate is accelerating (exponential growth signature)
        // Using signed arithmetic for the subtraction
        __s64 d2 = (__s64)rate - 2*(__s64)prev + (__s64)prev_prev;

        // Three conditions for fork bomb:
        // 1. d2 > 0: rate is accelerating
        // 2. rate > prev: current window is higher than previous
        // 3. prev > prev_prev: previous window was higher than the one before
        // Together: monotonically increasing with positive acceleration = exponential
        if (d2 > 0 && rate > prev && prev > prev_prev) {
            struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
            if (state) {
                state->flags |= BIT_FORK_ACCEL;
                state->bit_ts[7] = now;  // bit 7 = BIT_FORK_ACCEL
            }

            struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
            if (alert) {
                alert->type = ALERT_FORK_ACCEL;
                alert->pid = bpf_get_current_pid_tgid() >> 32;
                alert->cgroup_id = cg;
                alert->timestamp = now;
                alert->flags = state ? state->flags : BIT_FORK_ACCEL;
                alert->extra = rate;  // current fork rate for logging
                bpf_ringbuf_submit(alert, 0);
            }

            bpf_send_signal(9);  // SIGKILL
        }
    }

    // Hard ceiling: 500 forks/second is never legitimate in a container
    // Defense in depth — catches edge cases where acceleration check might miss
    if (rate > 500) {
        bpf_send_signal(9);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
