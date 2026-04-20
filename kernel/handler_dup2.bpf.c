// handler_dup2.bpf.c
// Tail-called for: dup2 (syscall 33) and dup3 (syscall 292)
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

SEC("raw_tracepoint/sys_enter")
int handle_dup2(struct bpf_raw_tracepoint_args *ctx) {
    // For raw_tracepoint/sys_enter, ctx->args[0] is struct pt_regs *
    // On x86_64: rdi = first argument, rsi = second argument
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    long oldfd_long = 0, newfd_long = 0;
    BPF_CORE_READ_INTO(&oldfd_long, regs, di);  // x86_64: rdi = first arg
    BPF_CORE_READ_INTO(&newfd_long, regs, si);  // x86_64: rsi = second arg

    int oldfd = (int)oldfd_long;
    int newfd = (int)newfd_long;

    // ── BOUND CHECK 1: target must be stdin, stdout, or stderr ────────
    // We only care about socket → stdin/stdout/stderr redirections.
    // dup2 to any other fd is not a reverse shell invariant.
    if (newfd < 0 || newfd > 2) return 0;

    // ── BOUND CHECK 2: source fd must be in valid range ───────────────
    // REQUIRED for verifier to accept fd_array[oldfd] below.
    // Without this explicit bound, the verifier rejects the program.
    if (oldfd < 0 || oldfd >= MAX_FD) return 0;

    // ── Traverse kernel data structures to determine fd type ──────────
    // We need to check if oldfd refers to a socket (S_IFSOCK in i_mode).
    // Path: current_task → files_struct → fdtable → file[oldfd] → inode → i_mode
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct files_struct *files = NULL;
    BPF_CORE_READ_INTO(&files, task, files);
    if (!files) return 0;

    struct fdtable *fdt = NULL;
    BPF_CORE_READ_INTO(&fdt, files, fdt);
    if (!fdt) return 0;

    struct file **fd_array = NULL;
    BPF_CORE_READ_INTO(&fd_array, fdt, fd);
    if (!fd_array) return 0;

    // Read fd_array[oldfd] — safe: oldfd proven [0, MAX_FD-1] above
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_array[oldfd]);
    if (!f) return 0;

    struct inode *inode = NULL;
    BPF_CORE_READ_INTO(&inode, f, f_inode);
    if (!inode) return 0;

    unsigned short i_mode = 0;
    BPF_CORE_READ_INTO(&i_mode, inode, i_mode);

    // ── THE INVARIANT CHECK ───────────────────────────────────────────
    // S_IFSOCK = 0xC000, S_IFMT = 0xF000 (extracts file type bits)
    // If source fd is a socket being redirected to stdin/stdout/stderr,
    // this is the physical requirement of a reverse shell.
    if ((i_mode & 0xF000) == 0xC000) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        // Set BIT_FD_REDIRECT in the container's behavioral bitfield
        // with per-bit timestamp (v5 fix for stale-bit false positives)
        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_FD_REDIRECT;
            state->bit_ts[6] = now;  // bit 6 = BIT_FD_REDIRECT
        }

        // Emit alert to high-priority ring buffer
        struct alert_t *alert = bpf_ringbuf_reserve(&alerts_rb, sizeof(struct alert_t), 0);
        if (alert) {
            alert->type = ALERT_FD_REDIRECT;
            alert->pid = bpf_get_current_pid_tgid() >> 32;
            alert->cgroup_id = cg;
            alert->timestamp = now;
            alert->flags = state ? state->flags : BIT_FD_REDIRECT;
            // extra: encodes oldfd and newfd for logging
            alert->extra = ((__u64)oldfd << 32) | (__u64)(unsigned int)newfd;
            bpf_ringbuf_submit(alert, 0);
        }

        // ENFORCE: Kill the process immediately
        bpf_send_signal(9);  // SIGKILL
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
