// dispatcher.bpf.c
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int dispatcher(struct bpf_raw_tracepoint_args *ctx) {

    // ── Step 1: Read syscall number ──────────────────────────────────
    // For raw_tracepoint/sys_enter: ctx->args[1] is the syscall number
    unsigned long syscall_nr = ctx->args[1];

    // ── Step 2: Container filter — skip host processes ──────────────
    // Read current task's mount namespace inode via CO-RE
    // This is portable across kernel versions with different struct layouts
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct nsproxy *nsproxy = NULL;
    BPF_CORE_READ_INTO(&nsproxy, task, nsproxy);
    if (!nsproxy) return 0;

    struct mnt_namespace *mnt_ns = NULL;
    BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
    if (!mnt_ns) return 0;

    unsigned int mnt_ns_inum = 0;
    BPF_CORE_READ_INTO(&mnt_ns_inum, mnt_ns, ns.inum);

    // Compare against stored host namespace inode
    __u32 key_zero = 0;
    __u32 *host_ns_inum = bpf_map_lookup_elem(&host_ns, &key_zero);
    if (!host_ns_inum) return 0;
    if (mnt_ns_inum == *host_ns_inum) return 0;  // host process — skip

    // All subsequent code runs only for container processes
    __u64 cg = bpf_get_current_cgroup_id();

    // ── Step 3: Verdict map check (Tier 3 → Tier 1 feedback) ────────
    // This is how Tier 3's sheaf verdict becomes kernel enforcement.
    // If Tier 3 has written VERDICT_KILL for this cgroup, kill immediately.
    __u32 *verdict = bpf_map_lookup_elem(&verdict_map, &cg);
    if (verdict && *verdict == VERDICT_KILL) {
        bpf_send_signal(9);  // SIGKILL — instant
        return 0;
    }

    // ── Step 4: Cgroup inheritance check (unshare fix) ──────────────
    // If this PID recently called unshare(CLONE_NEWCGROUP), it may have
    // moved to a new cgroup. We need to copy behavioral history.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *old_cg_ptr = bpf_map_lookup_elem(&pending_cgroup_inherit, &pid_tgid);
    if (old_cg_ptr) {
        __u64 old_cg = *old_cg_ptr;
        if (cg != old_cg) {
            // Cgroup transition detected — copy behavioral history
            struct behavior_state *old_state = bpf_map_lookup_elem(&container_behavior, &old_cg);
            if (old_state) {
                // BPF_NOEXIST: don't overwrite if new cgroup already has state
                bpf_map_update_elem(&container_behavior, &cg, old_state, BPF_NOEXIST);
            }
        }
        bpf_map_delete_elem(&pending_cgroup_inherit, &pid_tgid);
    }

    // ── Step 5: Bigram CMS update (verifier-safe) ────────────────────
    // Cold path (sketch NULL): skip bigram tracking but CONTINUE to tail-call.
    // This ensures Tier 1 handlers are active even during the startup race window.
    // Hot path: update the CMS with the (prev_syscall, current_syscall) bigram.
    struct bigram_sketch *sketch = bpf_map_lookup_elem(&bigram_sketch_map, &cg);

    if (sketch) {
        __u64 now = bpf_ktime_get_ns();

        // Window reset: zero all counters when current window expires
        if (now - sketch->window_start > WINDOW_NS) {
            // Cannot memset the full 2KB struct inline — unroll loops instead
            #pragma unroll
            for (int row = 0; row < CMS_ROWS; row++) {
                #pragma unroll
                for (int col = 0; col < CMS_COLS; col++) {
                    sketch->counters[row][col] = 0;
                }
            }
            sketch->total_count = 0;
            sketch->window_start = now;
        }

        // Map current syscall to [0..24] index
        __u32 curr_idx = syscall_to_idx((__u32)syscall_nr);

        // NOISE FILTER: Skip prev_idx update for side-effect-free syscalls.
        // These are used by attackers to break bigram signatures. By not advancing
        // prev_idx, noise syscalls are invisible to the CMS.
        // IMPORTANT: tail-call still fires — invariant handlers still run.
        if (!is_noise_syscall((__u32)syscall_nr)) {
            __u32 prev_idx = sketch->prev_idx;
            // Defensive bound: verifier requires proof that prev_idx <= 24
            if (prev_idx > 24) prev_idx = 24;

            // Compute bigram key: prev * TOP_SYSCALLS + curr
            // Max value: 24*25+24 = 624 < MAX_BIGRAMS=625 — safe
            __u32 bigram_key = prev_idx * TOP_SYSCALLS + curr_idx;

            // CMS update: 4 hash functions, each bounded by CMS_COL_MASK
            // The & operator provides the verifier-required array bound proof
            #pragma unroll
            for (int i = 0; i < CMS_ROWS; i++) {
                __u32 hash = (bigram_key * CMS_PRIMES[i] + CMS_SEEDS[i]) & CMS_COL_MASK;
                // hash is provably in [0, 127] — verifier accepts this array access
                sketch->counters[i][hash] += 1;
            }

            sketch->total_count += 1;
            sketch->prev_idx = curr_idx;  // advance only for non-noise syscalls
        }
        // For noise syscalls: CMS not updated, prev_idx unchanged, they're transparent
    }
    // Cold path (sketch == NULL): fall through to tail-call without bigram update

    // ── Step 6: Tail-call dispatch to handler by syscall number ──────
    // If no handler is registered for this syscall number, the tail call
    // silently fails and we return 0 — this is the normal case for most syscalls.
    bpf_tail_call(ctx, &prog_array, (__u32)syscall_nr);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
