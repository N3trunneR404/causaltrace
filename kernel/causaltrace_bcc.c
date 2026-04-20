/*
 * causaltrace_bcc.c — Complete CausalTrace eBPF kernel code (BCC-native)
 *
 * Single-file BCC program containing:
 *   - All struct definitions
 *   - All BPF map declarations (BCC macros)
 *   - Dispatcher (raw_tracepoint/sys_enter)
 *   - handler_fork (clone/clone3)
 *   - handler_execve (execve)
 *   - handler_file (openat)
 *   - handler_privesc (setuid/unshare/setns/ptrace)
 *   - handler_dup2 (dup2/dup3 — fd-type invariant)
 *   - probe_b: tcp_v4_connect kprobe/kretprobe
 *   - probe_c: sched_process_exec tracepoint
 *
 * v5 final spec compliance:
 *   - TOP_SYSCALLS=25, MAX_BIGRAMS=625
 *   - behavior_state.bit_ts[8] per-bit timestamps
 *   - alerts_rb (64KB) + telemetry_rb (256KB) separate
 *   - connect_sk_stash LRU_HASH 4096
 *   - pending_cgroup_inherit for unshare(CLONE_NEWCGROUP)
 *   - Noise filter: getpid/getuid/gettid/getppid/time/clock_gettime
 *   - Cold path continues to tail-call
 *   - Fork acceleration d2 = rate - 2*prev + prev_prev (NOT fixed threshold)
 *   - dup2 handler: oldfd bounds check [0, MAX_FD)
 *
 * Authors: Shubhankar Bhattacharya, Anmol Kashyap
 * IIITDM Kurnool, 2026
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/fdtable.h>
#include <net/sock.h>

/* ================================================================== */
/*  CONSTANTS                                                          */
/* ================================================================== */

#define MAX_CONTAINERS    256
#define CMS_ROWS          4
#define CMS_COLS          128
#define CMS_COL_MASK      (CMS_COLS - 1)
#define TOP_SYSCALLS      25
#define MAX_BIGRAMS       (TOP_SYSCALLS * TOP_SYSCALLS)
#define WINDOW_NS         (5ULL * 1000000000ULL)
#define MAX_FD            1024
#define TWOHOP_WINDOW_NS  (5ULL * 1000000000ULL)

#define ALERT_FORK_BOMB       1
#define ALERT_REVERSE_SHELL   2
#define ALERT_SENSITIVE_FILE  3
#define ALERT_PRIVESC         4
#define ALERT_FD_REDIRECT     5
#define ALERT_FORK_ACCEL      6
#define ALERT_TWO_HOP         7
#define ALERT_NS_ESCAPE       8
#define EVENT_CONNECTION      100

#define VERDICT_ALLOW  0
#define VERDICT_KILL   1

#define BIT_SHELL_SPAWN      (1ULL << 0)
#define BIT_LATERAL_CONNECT  (1ULL << 1)
#define BIT_SENSITIVE_FILE   (1ULL << 2)
#define BIT_NS_PROBE         (1ULL << 3)
#define BIT_PRIVESC          (1ULL << 4)
#define BIT_LARGE_TRANSFER   (1ULL << 5)
#define BIT_FD_REDIRECT      (1ULL << 6)
#define BIT_FORK_ACCEL       (1ULL << 7)

#define MY_CLONE_NEWCGROUP   0x02000000

/* ================================================================== */
/*  STRUCTS                                                            */
/* ================================================================== */

struct behavior_state {
    u64 flags;
    u64 bit_ts[8];
    u64 conn_dst_cg;
    u16 conn_port;
    u16 _pad[3];
};

struct rate_state {
    u64 window_start;
    u64 count;
    u64 prev_count;
    u64 prev_prev_count;
};

struct bigram_sketch {
    u32 counters[CMS_ROWS * CMS_COLS];   /* flat [r*CMS_COLS+c] — BCC 0.31 mishandles 2D arrays */
    u32 prev_idx;
    u32 _pad;
    u64 total_count;
    u64 window_start;
};

struct alert_t {
    u32 type;
    u32 pid;
    u64 cgroup_id;
    u64 timestamp;
    u64 flags;
    u64 extra;
};

/* ================================================================== */
/*  BCC MAP DECLARATIONS                                               */
/* ================================================================== */

BPF_ARRAY(host_ns, u32, 1);
BPF_PROG_ARRAY(prog_array, 512);
BPF_HASH(verdict_map, u64, u32, MAX_CONTAINERS);
BPF_HASH(rate_map, u64, struct rate_state, MAX_CONTAINERS);
BPF_HASH(container_behavior, u64, struct behavior_state, MAX_CONTAINERS);
BPF_HASH(ip_to_cgroup, u32, u64, MAX_CONTAINERS);
BPF_HASH(bigram_sketch_map, u64, struct bigram_sketch, MAX_CONTAINERS);
BPF_HASH(pending_cgroup_inherit, u64, u64, 256);
struct sk_key { u64 k; };
struct sk_val { u64 v; };
BPF_TABLE("lru_hash", struct sk_key, struct sk_val, connect_sk_stash, 4096);
/* Dedicated stash for tcp_recvmsg entry→return handoff. Keeping this
 * separate from connect_sk_stash avoids cross-contention on the hot TCP
 * recvmsg path where churn through the LRU is much higher. */
BPF_TABLE("lru_hash", struct sk_key, struct sk_val, tcp_recvmsg_stash, 8192);
BPF_ARRAY(stats, u64, 16);
BPF_RINGBUF_OUTPUT(alerts_rb, 16);
BPF_RINGBUF_OUTPUT(telemetry_rb, 64);

/* ================================================================== */
/*  PHASE 4 — RING BUFFER BACKPRESSURE                                */
/* ================================================================== */
/* Two ring buffers with asymmetric policy:
 *   alerts_rb    (64KB, 16 pages):  NEVER proactively shed. Alerts are
 *                                    observability-critical. Count real
 *                                    kernel drops (ENOSPC) as LOSS.
 *   telemetry_rb (256KB, 64 pages): Shed proactively at >=90% fill via
 *                                    bpf_ringbuf_query. Calibration and
 *                                    sheaf detection tolerate gaps.
 *
 * Counters exposed via ringbuf_stats (BPF_ARRAY u64 x 8):
 *   [0] telemetry_shed     — dropped before emit (>=90% fill)
 *   [1] telemetry_fail     — ringbuf_output returned < 0
 *   [2] telemetry_ok       — successfully emitted
 *   [3] alerts_fail        — ringbuf_output returned < 0 (LOST ALERT)
 *   [4] alerts_ok          — successfully emitted
 *   [5] alerts_near_full   — fill >=80% at emit time (daemon wake hint)
 *   [6] reserved
 *   [7] reserved
 *
 * Tier 3 reads this map each cycle and logs non-zero deltas.
 */
#define TELEMETRY_RB_BYTES  (64 * 4096)   /* must mirror BPF_RINGBUF_OUTPUT above */
#define ALERTS_RB_BYTES     (16 * 4096)

BPF_ARRAY(ringbuf_stats, u64, 8);

/* Emit helpers are inline functions, NOT macros: BCC's frontend rejects
 * map method calls like alerts_rb.ringbuf_output(...) when they appear
 * inside a #define expansion, but accepts them inside static __always_inline
 * bodies. All emit sites funnel through emit_alert / emit_telemetry. */

static __always_inline void rb_stat_bump(u32 idx) {
    u64 *c = ringbuf_stats.lookup(&idx);
    if (c) __sync_fetch_and_add(c, 1);
}

static __always_inline void emit_alert(struct alert_t *p) {
    /* Alerts: never proactively shed. Always try; count real kernel drops. */
    u64 avail = alerts_rb.ringbuf_query(0);  /* 0 == BPF_RB_AVAIL_DATA */
    if (avail >= (ALERTS_RB_BYTES * 4) / 5) rb_stat_bump(5);  /* near_full hint */
    long rc = alerts_rb.ringbuf_output(p, sizeof(*p), 0);
    rb_stat_bump(rc < 0 ? 3 : 4);
}

static __always_inline void emit_telemetry(struct alert_t *p) {
    /* Telemetry: proactively shed at >=90% fill so alerts stay fresh. */
    u64 avail = telemetry_rb.ringbuf_query(0);
    if (avail >= (TELEMETRY_RB_BYTES * 9) / 10) {
        rb_stat_bump(0);  /* shed */
        return;
    }
    long rc = telemetry_rb.ringbuf_output(p, sizeof(*p), 0);
    rb_stat_bump(rc < 0 ? 1 : 2);
}

/* ================================================================== */
/*  ENFORCEMENT ENGINE — Surgical syscall denial via bpf_override_return */
/* ================================================================== */
/*
 * These maps are populated by the Tier 3 daemon based on detection verdicts.
 * Each rule has a TTL (expire_ns) so false positives auto-heal.
 *
 * Enforcement levels (Tier 3 decides):
 *   L0: OBSERVE   — increase telemetry, no enforcement
 *   L1: DENY      — block specific syscalls (bpf_override_return)
 *   L2: SEVER     — destroy specific sockets
 *   L3: THROTTLE  — rate-limit connections to calibrated baseline
 *   L4: FIREWALL  — only calibrated destinations allowed
 *   L5: DRAIN     — block new inbound, let existing finish
 *   L6: QUARANTINE — block all network
 *   L7: FREEZE    — cgroup freeze (userspace)
 *   L8: KILL      — bpf_send_signal(9) (existing verdict_map)
 */

#define ENFORCE_OBSERVE    0
#define ENFORCE_DENY       1
#define ENFORCE_SEVER      2
#define ENFORCE_THROTTLE   3
#define ENFORCE_FIREWALL   4
#define ENFORCE_DRAIN      5
#define ENFORCE_QUARANTINE 6
/* L7 (FREEZE) and L8 (KILL) are userspace actions */

/* Per-container enforcement level — Tier 3 writes this */
struct enforce_state {
    u32 level;             /* current enforcement level (0-6) */
    u32 _pad;
    u64 expire_ns;         /* CLOCK_MONOTONIC ns — rule expires after this */
    u64 set_ns;            /* when rule was set */
};
BPF_HASH(enforce_level_map, u64, struct enforce_state, MAX_CONTAINERS);

/* Deny-connect map: (cgroup_id, dst_ip, dst_port) → errno to return
 * Populated by Tier 3 when novel edges are detected.
 * Key encodes: dst_ip(32) | dst_port(16) | 0(16) packed into u64 */
struct deny_connect_key {
    u64 cgroup_id;
    u64 dst_packed;    /* (dst_ip << 32) | (dst_port << 16) */
};
struct deny_connect_val {
    s32 errno_val;     /* e.g., -ECONNREFUSED (-111) */
    u32 _pad;
    u64 expire_ns;
};
BPF_HASH(deny_connect_map, struct deny_connect_key, struct deny_connect_val, 1024);

/* Deny-open map: (cgroup_id, path_prefix_hash) → errno to return
 * path_prefix_hash is a simple hash of first 16 bytes of path */
struct deny_open_key {
    u64 cgroup_id;
    u64 path_hash;
};
struct deny_open_val {
    s32 errno_val;     /* e.g., -EACCES (-13) */
    u32 _pad;
    u64 expire_ns;
};
BPF_HASH(deny_open_map, struct deny_open_key, struct deny_open_val, 256);

/* Deny-exec map: (cgroup_id, path_prefix_hash) → errno
 * Blocks specific binary execution */
struct deny_exec_key {
    u64 cgroup_id;
    u64 path_hash;
};
struct deny_exec_val {
    s32 errno_val;     /* -EPERM (-1) */
    u32 _pad;
    u64 expire_ns;
};
BPF_HASH(deny_exec_map, struct deny_exec_key, struct deny_exec_val, 256);

/* Rate-limit map: per-(container, destination) connection rate tracking
 * Tier 3 writes max_rate from calibration baseline; BPF enforces */
struct rate_limit_key {
    u64 cgroup_id;
    u64 dst_packed;
};
struct rate_limit_val {
    u64 max_per_sec;       /* calibrated baseline × multiplier */
    u64 window_start;
    u64 current_count;
    u64 expire_ns;
};
BPF_HASH(rate_limit_map, struct rate_limit_key, struct rate_limit_val, 512);

/* Firewall allow-list: only these (container, dst) pairs are allowed.
 * If enforce_level >= ENFORCE_FIREWALL, any connect not in this map is denied. */
struct fw_allow_key {
    u64 cgroup_id;
    u64 dst_packed;
};
BPF_HASH(fw_allow_map, struct fw_allow_key, u32, 2048);  /* value=1 if allowed */

/* Alert type for enforcement actions */
#define ALERT_ENFORCE_DENY    20
#define ALERT_ENFORCE_THROTTLE 21

/* ENFORCE_MODE is set via -D compiler flag from loader.py:
 *   -DENFORCE_MODE=0  → monitor/calibrate (no enforcement)
 *   -DENFORCE_MODE=1  → graduated response:
 *       - IMMEDIATE_KILL: fork bomb, reverse shell (can't wait for userspace)
 *       - ALERT_ONLY: everything else → Tier 3 decides enforcement
 *
 * Production philosophy: killing a container breaks the service chain.
 * Only kill when the attack is both confirmed AND time-critical (fork bomb
 * will exhaust PIDs in milliseconds, reverse shell gives attacker interactive
 * access). For everything else, set behavior bits, emit alerts, and let the
 * Tier 3 sheaf daemon evaluate the compound behavior before deciding to
 * isolate or kill.
 */
#ifndef ENFORCE_MODE
#define ENFORCE_MODE 1
#endif

/* Immediate kill — only for fork bomb and reverse shell.
 * These attacks cause irreversible damage in milliseconds. */
static void __always_inline immediate_kill(void) {
#if ENFORCE_MODE
    bpf_send_signal(9);
#endif
}

/* Alert only — sets behavior bits and emits to ring buffer.
 * Tier 3 userspace daemon decides enforcement action:
 *   - docker network disconnect (isolate)
 *   - docker pause (freeze)
 *   - kill (last resort, after compound confirmation)
 * This is a no-op because the caller already emits the alert. */
static void __always_inline alert_only(void) {
    /* Intentionally empty. The alert was already sent via ringbuf.
     * Tier 3 daemon reads alerts + sheaf analysis to decide action. */
}

/* ================================================================== */
/*  TRUST MODEL — L4 stability-based client-IP trust                   */
/* ================================================================== */
/*
 * Four trust levels per client IP:
 *   0 (UNKNOWN)     — never seen. Default for every new IP.
 *   1 (OBSERVED)    — TCP handshake completed, but not yet L4-stable.
 *   2 (CALIBRATED)  — sustained a benign flow (>=5120 B AND >=1 s).
 *                     Only CALIBRATED IPs get Case B (alert-only) treatment.
 *   255 (BURNED)    — triggered a strict invariant. Permanently hostile.
 *                     Overwrites even a prior CALIBRATED promotion.
 *
 * Trust is attached to CLIENT IP, not to the container. A calibrated IP
 * talking to one container can "burn" all its pending calibrations across
 * every container if it trips an invariant.
 */

#define TRUST_UNKNOWN        0
#define TRUST_OBSERVED       1
#define TRUST_CALIBRATED     2
#define TRUST_BURNED       255

/* Per-client-IP trust. Tier 3 populates; kernel reads (client_trust.lookup). */
BPF_HASH(client_trust, u32, u8, 4096);

/* Primary attribution: per-TID client IP. Populated when a task calls
 * accept(), inherited across fork via sched_process_fork (Inherited Sin).
 * This is the correct attribution for per-connection-worker servers
 * (nginx, gunicorn, Go net/http, Python Flask, uwsgi in worker mode).
 * Accept-thread + thread-pool servers (Apache mpm-worker, traditional
 * Java HTTP) fall back to cgroup_current_client — documented limitation. */
BPF_TABLE("lru_hash", u64, u32, tid_client_ip, 16384);

/* Fallback attribution: per-cgroup "last-accepted client".
 * Used only when tid_client_ip[current pid_tgid] is empty (e.g., worker
 * thread picked up work from a queue without having accept()ed itself). */
BPF_HASH(cgroup_current_client, u64, u32, MAX_CONTAINERS);

/* Per-socket connection context for L4 stability tracking.
 * Populated on accept/connect, updated on tcp_recvmsg/tcp_sendmsg.
 * Key = (u64)sock_ptr. Tier 3 reads this map during calibration. */
struct conn_context {
    u32 client_ip;
    u32 _pad0;
    u64 cgroup;
    u64 bytes_in;
    u64 bytes_out;
    u64 established_ns;
    u64 last_active_ns;
};
BPF_TABLE("lru_hash", u64, struct conn_context, connection_context, 8192);

/* ================================================================== */
/*  TC DROP LIST — severs attacker's TCP flow at the veth              */
/* ================================================================== */
/*
 * drop_ip_list is the sole input to the TC ingress/egress classifiers below.
 * Key = IPv4 address (u32, network byte order as seen on the wire).
 * Value = CLOCK_MONOTONIC ns expiry (0 = never expires, which we don't use).
 *
 * Populated by maybe_kill() when Case A (strict invariant) or Case C
 * (untrusted anomaly) fires on a syscall whose client IP is attributable.
 * Each insertion has a 5-minute TTL so false positives auto-heal without
 * operator intervention. Tier 3 may extend TTLs for persistent attackers.
 *
 * Why TC (not SIGKILL, not sockops TCP RST):
 *  - SIGKILL destroys the container's workload, punishing legitimate users.
 *  - sockops TCP RST is brittle under retransmit/half-open edge cases.
 *  - TC drop is datapath-inline (~hundreds of ns), sub-5μs total path,
 *    and surgical: only packets from/to the blacklisted IP are dropped.
 */
BPF_HASH(drop_ip_list, u32, u64, 4096);

/* Stats counters for TC programs — exposed so papers can quantify impact. */
#define TCSTAT_PKTS_SEEN_IN   0
#define TCSTAT_PKTS_DROPPED_IN 1
#define TCSTAT_PKTS_SEEN_OUT  2
#define TCSTAT_PKTS_DROPPED_OUT 3
BPF_ARRAY(tc_stats, u64, 8);

/* ================================================================== */
/*  COMPOUND ENFORCEMENT GATE                                          */
/* ================================================================== */
/*
 * maybe_kill(cg, case_id) — central kill decision. Case taxonomy:
 *
 *   'A'  STRICT INVARIANT (physical contract violation).
 *        Examples: dup2(socket, stdin/out/err), shell exec with socket stdio,
 *        namespace escape (unshare CLONE_NEWNS/USER), setns/ptrace inside
 *        container, setuid-0 from non-root, confirmed two-hop chain.
 *        Action: kill + BURN the originating client IP (if known).
 *
 *   'D'  SELF-INFLICTED (no external attacker identified).
 *        Examples: fork-bomb (d2>0 sustained, hard ceiling), runaway workload.
 *        Action: kill without burning any IP.
 *
 *   'X'  SUSPICIOUS SOFT BIT — gate decides B vs C based on client trust.
 *        Examples: plain shell exec, single lateral connect, single sensitive
 *        file read without an accompanying invariant.
 *         - trust == CALIBRATED  →  Case B (alert-only, Tier 3 compounds).
 *         - trust != CALIBRATED  →  Case C (kill, no benefit of the doubt).
 *
 * This is the sole kill path from Phase 1 forward. alert_only() is deprecated
 * (kept as a stub only so old callers don't break mid-edit).
 */

static void __always_inline burn_trust(u32 client_ip) {
#if ENFORCE_MODE
    if (client_ip == 0) return;
    u8 burned = TRUST_BURNED;
    client_trust.update(&client_ip, &burned);
#endif
}

/* Sever an attacker's TCP flow by blacklisting their IP for TC_DROP_TTL_NS.
 * The TC classifiers on each container's veth drop packets to/from this IP,
 * which terminates the attacker's session without killing the container. */
#define TC_DROP_TTL_NS (300ULL * 1000000000ULL)  /* 5 minutes */

static void __always_inline drop_session(u32 client_ip) {
#if ENFORCE_MODE
    if (client_ip == 0) return;
    u64 expire = bpf_ktime_get_ns() + TC_DROP_TTL_NS;
    drop_ip_list.update(&client_ip, &expire);
#endif
}

static void __always_inline maybe_kill(u64 cg, int case_id) {
#if ENFORCE_MODE
    /* Attribution: prefer per-TID (correct for per-connection-worker
     * servers), fall back to per-cgroup last-accept (best-effort for
     * accept-thread + thread-pool servers). */
    u32 client_ip = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 *tip = tid_client_ip.lookup(&pid_tgid);
    if (tip) {
        client_ip = *tip;
    } else {
        u32 *ipp = cgroup_current_client.lookup(&cg);
        if (ipp) client_ip = *ipp;
    }

    if (case_id == 'A') {
        /* Hard invariant. Sever the attacker's session at the veth and burn
         * their trust. SIGKILL falls back only if we have no IP to target —
         * some invariants (eg setuid-0 on internal script) have no external
         * attacker, in which case dropping nothing is worse than killing the
         * offending process. */
        if (client_ip) {
            burn_trust(client_ip);
            drop_session(client_ip);
            return;
        }
        bpf_send_signal(9);
        return;
    }
    if (case_id == 'D') {
        /* Self-inflicted (fork bomb, runaway workload). No external attacker
         * to drop — only the workload itself can be stopped. */
        bpf_send_signal(9);
        return;
    }
    /* 'X' — suspicious soft bit, gate by trust */
    u8 trust = TRUST_UNKNOWN;
    if (client_ip) {
        u8 *tp = client_trust.lookup(&client_ip);
        if (tp) trust = *tp;
    }
    if (trust == TRUST_CALIBRATED) {
        /* Case B: trusted client got flagged — let Tier 3 compound before kill */
        return;
    }
    /* Case C: untrusted anomaly. Drop their session if attributable,
     * SIGKILL only as last resort when attribution fails. */
    if (client_ip) {
        drop_session(client_ip);
        return;
    }
    bpf_send_signal(9);
#endif
}

/* ================================================================== */
/*  INLINE HELPERS                                                     */
/* ================================================================== */

/* CMS hash constants */
static u32 __always_inline cms_prime(int row) {
    switch (row) {
        case 0: return 2654435761U;
        case 1: return 2246822519U;
        case 2: return 3266489917U;
        case 3: return 668265263U;
        default: return 2654435761U;
    }
}

static u32 __always_inline cms_seed(int row) {
    switch (row) {
        case 0: return 1;
        case 1: return 7;
        case 2: return 13;
        case 3: return 31;
        default: return 1;
    }
}

/* Top-24 syscall index mapping + index 24 = "other" */
static u32 __always_inline syscall_to_idx(u32 nr) {
    switch (nr) {
        case 0:   return 0;   // read
        case 1:   return 1;   // write
        case 2:   return 2;   // open
        case 3:   return 3;   // close
        case 4:   return 4;   // stat
        case 5:   return 5;   // fstat
        case 9:   return 6;   // mmap
        case 10:  return 7;   // mprotect
        case 12:  return 8;   // brk
        case 16:  return 9;   // ioctl
        case 21:  return 10;  // access
        case 22:  return 11;  // pipe
        case 41:  return 12;  // socket
        case 42:  return 13;  // connect
        case 43:  return 14;  // accept
        case 44:  return 15;  // sendto
        case 101: return 16;  // ptrace
        case 165: return 17;  // mount
        case 272: return 18;  // unshare
        case 308: return 19;  // setns
        case 319: return 20;  // memfd_create
        case 321: return 21;  // bpf
        case 426: return 22;  // io_uring_enter
        case 59:  return 23;  // execve
        default:  return 24;  // other
    }
}

/* Noise filter: side-effect-free syscalls used for bigram obfuscation */
static int __always_inline is_noise_syscall(u32 nr) {
    switch (nr) {
        case 39:  // getpid
        case 102: // getuid
        case 186: // gettid
        case 110: // getppid
        case 201: // time
        case 228: // clock_gettime
            return 1;
        default:
            return 0;
    }
}

/* ================================================================== */
/*  DISPATCHER — runs on EVERY container syscall                       */
/* ================================================================== */

RAW_TRACEPOINT_PROBE(sys_enter) {
    /* Step 1: Read syscall number */
    unsigned long syscall_nr = ctx->args[1];

    /* Step 2: Container filter — skip host processes */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned int mnt_ns_inum = 0;

    /* Use bpf_probe_read_kernel — direct dereference generates memset on kernel 6.17+ */
    struct nsproxy *nsproxy = NULL;
    bpf_probe_read_kernel(&nsproxy, sizeof(nsproxy), &task->nsproxy);
    if (!nsproxy) return 0;

    struct mnt_namespace *mnt_ns = NULL;
    bpf_probe_read_kernel(&mnt_ns, sizeof(mnt_ns), &nsproxy->mnt_ns);
    if (!mnt_ns) return 0;

    /* mnt_namespace is incomplete in BCC — read inum via probe_read */
    /* ns_common is at offset 0 in mnt_namespace, inum is at offset 16 in ns_common */
    /* On kernel 5.15+: offsetof(struct ns_common, inum) after stash(8) + ops(8) = 16 */
    bpf_probe_read_kernel(&mnt_ns_inum, sizeof(mnt_ns_inum), (void *)mnt_ns + 16);

    u32 key_zero = 0;
    u32 *host_ns_val = host_ns.lookup(&key_zero);
    if (!host_ns_val) return 0;
    if (mnt_ns_inum == *host_ns_val) return 0;

    u64 cg = bpf_get_current_cgroup_id();

    /* Step 3: Verdict map check — Tier 3 already confirmed this container is attacking */
    u32 *verdict = verdict_map.lookup(&cg);
    if (verdict && *verdict == VERDICT_KILL) {
        immediate_kill();
        return 0;
    }

    /* Step 4: Cgroup inheritance check */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *old_cg_ptr = pending_cgroup_inherit.lookup(&pid_tgid);
    if (old_cg_ptr) {
        u64 old_cg = *old_cg_ptr;
        if (cg != old_cg) {
            struct behavior_state *old_state = container_behavior.lookup(&old_cg);
            if (old_state) {
                container_behavior.update(&cg, old_state);
            }
        }
        pending_cgroup_inherit.delete(&pid_tgid);
    }

    /* Step 5: Bigram CMS update */
    struct bigram_sketch *sketch = bigram_sketch_map.lookup(&cg);

    if (sketch) {
        u64 now = bpf_ktime_get_ns();

        if (now - sketch->window_start > WINDOW_NS) {
            /* Zero all counters so each window reflects only current traffic.
               #pragma unroll forces the verifier-safe unrolled form (not memset). */
            /* volatile prevents LLVM from optimizing 512 stores into memset (blocked on kernel 6.17) */
            #pragma unroll
            for (int _r = 0; _r < CMS_ROWS; _r++) {
                #pragma unroll
                for (int _c = 0; _c < CMS_COLS; _c++) {
                    *(volatile u32 *)&sketch->counters[_r * CMS_COLS + _c] = 0;
                }
            }
            sketch->total_count = 0;
            sketch->prev_idx = 24;
            sketch->window_start = now;
        }

        u32 curr_idx = syscall_to_idx((u32)syscall_nr);

        /* Noise filter: skip prev_idx update for obfuscation syscalls */
        if (!is_noise_syscall((u32)syscall_nr)) {
            u32 prev_idx = sketch->prev_idx;
            if (prev_idx > 24) prev_idx = 24;

            u32 bigram_key = prev_idx * TOP_SYSCALLS + curr_idx;

            #pragma unroll
            for (int i = 0; i < CMS_ROWS; i++) {
                u32 hash = (bigram_key * cms_prime(i) + cms_seed(i)) & CMS_COL_MASK;
                sketch->counters[i * CMS_COLS + hash] += 1;
            }

            sketch->total_count += 1;
            sketch->prev_idx = curr_idx;
        }
    }
    /* Cold path: sketch==NULL falls through to tail-call (NOT return 0) */

    /* Step 6: Tail-call dispatch */
    prog_array.call(ctx, (u32)syscall_nr);

    return 0;
}

/* ================================================================== */
/*  HANDLER: dup2/dup3 — fd-type invariant (reverse shell detection)   */
/* ================================================================== */

int handle_dup2(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    long __arg1 = 0, __arg2 = 0;
    bpf_probe_read_kernel(&__arg1, sizeof(__arg1), &regs->di);
    bpf_probe_read_kernel(&__arg2, sizeof(__arg2), &regs->si);
    int oldfd = (int)__arg1;
    int newfd = (int)__arg2;

    /* Bound check: target must be stdin/stdout/stderr */
    if (newfd < 0 || newfd > 2) return 0;

    /* Bound check: source fd in valid range — REQUIRED for verifier */
    if (oldfd < 0 || oldfd >= MAX_FD) return 0;

    /* Traverse kernel structs — use bpf_probe_read_kernel (direct deref generates memset on 6.17) */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    if (!files) return 0;

    struct fdtable *fdt = NULL;
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) return 0;

    struct file **fd_arr = NULL;
    bpf_probe_read_kernel(&fd_arr, sizeof(fd_arr), &fdt->fd);
    if (!fd_arr) return 0;

    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fd_arr[oldfd]);
    if (!f) return 0;

    struct inode *inode = NULL;
    bpf_probe_read_kernel(&inode, sizeof(inode), &f->f_inode);
    if (!inode) return 0;

    unsigned short i_mode = 0;
    bpf_probe_read_kernel(&i_mode, sizeof(i_mode), &inode->i_mode);

    /* THE INVARIANT: S_IFSOCK = 0xC000 — socket to stdin/stdout/stderr */
    if ((i_mode & 0xF000) == 0xC000) {
        u64 cg = bpf_get_current_cgroup_id();
        u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = container_behavior.lookup(&cg);
        if (state) {
            state->flags |= BIT_FD_REDIRECT;
            state->bit_ts[6] = now;
        }

        struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
        alert.type = ALERT_FD_REDIRECT;
        alert.pid = bpf_get_current_pid_tgid() >> 32;
        alert.cgroup_id = cg;
        alert.timestamp = now;
        alert.flags = state ? state->flags : BIT_FD_REDIRECT;
        alert.extra = ((u64)oldfd << 32) | (u64)(unsigned int)newfd;
        emit_alert(&alert);

        /* dup2(socket → stdin/stdout/stderr) is a pure physical reverse-shell
         * invariant. No legitimate workload redirects stdio onto a socket. */
        maybe_kill(cg, 'A');
    }

    return 0;
}

/* ================================================================== */
/*  HANDLER: fork acceleration (clone/clone3)                          */
/* ================================================================== */

int handle_fork(struct bpf_raw_tracepoint_args *ctx) {
    u64 cg = bpf_get_current_cgroup_id();
    u64 now = bpf_ktime_get_ns();

    struct rate_state *rs = rate_map.lookup(&cg);
    if (!rs) {
        struct rate_state new_rs; __builtin_memset(&new_rs, 0, sizeof(new_rs));
        new_rs.window_start = now;
        new_rs.count = 1;
        rate_map.update(&cg, &new_rs);
        return 0;
    }

    u64 window_ns = 1000000000ULL;
    if (now - rs->window_start > window_ns) {
        rs->prev_prev_count = rs->prev_count;
        rs->prev_count = rs->count;
        rs->count = 1;
        rs->window_start = now;
    } else {
        rs->count += 1;
    }

    u64 rate = rs->count;
    u64 prev = rs->prev_count;
    u64 prev_prev = rs->prev_prev_count;

    /* Second discrete derivative: d2 = rate - 2*prev + prev_prev */
    if (rate > 50 && prev > 0 && prev_prev > 0) {
        s64 d2 = (s64)rate - 2 * (s64)prev + (s64)prev_prev;

        if (d2 > 0 && rate > prev && prev > prev_prev) {
            struct behavior_state *state = container_behavior.lookup(&cg);
            if (state) {
                state->flags |= BIT_FORK_ACCEL;
                state->bit_ts[7] = now;
            }

            struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
            alert.type = ALERT_FORK_ACCEL;
            alert.pid = bpf_get_current_pid_tgid() >> 32;
            alert.cgroup_id = cg;
            alert.timestamp = now;
            alert.flags = state ? state->flags : BIT_FORK_ACCEL;
            alert.extra = rate;
            emit_alert(&alert);

            /* Self-inflicted: workload itself is accelerating, no external
             * client IP to burn. Kill on discrete-d2>0 sustained growth. */
            maybe_kill(cg, 'D');
        }
    }

    /* Hard ceiling: 500 forks/sec */
    if (rate > 500) {
        maybe_kill(cg, 'D'); /* fork-bomb hard ceiling */
    }

    return 0;
}

/* ================================================================== */
/*  HANDLER: execve — shell binary name matching                       */
/* ================================================================== */

int handle_execve(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    char filename[128]; filename[0] = 0;
    long __fname_raw = 0;
    bpf_probe_read_kernel(&__fname_raw, sizeof(__fname_raw), &regs->di);
    const char *fname_ptr = (const char *)__fname_raw;
    bpf_probe_read_user_str(filename, sizeof(filename), fname_ptr);

    /* Find basename: last '/' position */
    char basename[16]; basename[0] = 0;
    int last_slash = -1;
    #pragma unroll
    for (int i = 0; i < 127; i++) {
        if (filename[i] == '\0') break;
        if (filename[i] == '/') last_slash = i;
    }

    int start = last_slash + 1;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        int idx = start + i;
        if (idx >= 127) break;
        if (filename[idx] == '\0') break;
        basename[i] = filename[idx];
    }

    int is_shell = 0;
    if (basename[0] == 's' && basename[1] == 'h' && basename[2] == '\0')
        is_shell = 1;
    else if (basename[0] == 'b' && basename[1] == 'a' && basename[2] == 's')
        is_shell = 1;
    else if (basename[0] == 'd' && basename[1] == 'a' && basename[2] == 's')
        is_shell = 1;
    else if (basename[0] == 'n' && basename[1] == 'c' && basename[2] == '\0')
        is_shell = 1;
    else if (basename[0] == 'n' && basename[1] == 'c' && basename[2] == 'a')
        is_shell = 1;
    else if (basename[0] == 'z' && basename[1] == 's' && basename[2] == 'h')
        is_shell = 1;

    if (is_shell) {
        u64 cg = bpf_get_current_cgroup_id();
        u64 now = bpf_ktime_get_ns();

        /* FD-table reverse-shell check: inspect stdin/stdout/stderr at execve
         * time. If any of fd 0/1/2 is a socket, the child shell will run with
         * socket stdio — a reverse shell regardless of how redirection was
         * staged. Catches bash `-i >& /dev/tcp/...` and `nc -e` variants
         * whose redirection does NOT emit a dup2 syscall we can raw-tracepoint. */
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct files_struct *files = NULL;
        bpf_probe_read_kernel(&files, sizeof(files), &task->files);

        int fd_is_socket = 0;     /* bitmask: bit N = fd N is S_IFSOCK */
        if (files) {
            struct fdtable *fdt = NULL;
            bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
            if (fdt) {
                struct file **fd_arr = NULL;
                bpf_probe_read_kernel(&fd_arr, sizeof(fd_arr), &fdt->fd);
                if (fd_arr) {
                    #pragma unroll
                    for (int fd = 0; fd < 3; fd++) {
                        struct file *f = NULL;
                        bpf_probe_read_kernel(&f, sizeof(f), &fd_arr[fd]);
                        if (!f) continue;
                        struct inode *ino = NULL;
                        bpf_probe_read_kernel(&ino, sizeof(ino), &f->f_inode);
                        if (!ino) continue;
                        unsigned short imode = 0;
                        bpf_probe_read_kernel(&imode, sizeof(imode), &ino->i_mode);
                        if ((imode & 0xF000) == 0xC000) {
                            fd_is_socket |= (1 << fd);
                        }
                    }
                }
            }
        }

        struct behavior_state *state = container_behavior.lookup(&cg);
        if (state) {
            state->flags |= BIT_SHELL_SPAWN;
            state->bit_ts[0] = now;
            if (fd_is_socket) {
                state->flags |= BIT_FD_REDIRECT;
                state->bit_ts[6] = now;
            }
        }

        struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
        alert.type = fd_is_socket ? ALERT_FD_REDIRECT : ALERT_REVERSE_SHELL;
        alert.pid = bpf_get_current_pid_tgid() >> 32;
        alert.cgroup_id = cg;
        alert.timestamp = now;
        alert.flags = state ? state->flags : (u64)(BIT_SHELL_SPAWN | (fd_is_socket ? BIT_FD_REDIRECT : 0));
        alert.extra = (u64)fd_is_socket;
        emit_alert(&alert);

        if (fd_is_socket) {
            /* Strict invariant: shell + socket stdio == reverse shell. */
            maybe_kill(cg, 'A');
        } else {
            /* Plain shell exec — could be admin. Gate on trust. */
            maybe_kill(cg, 'X');
        }
    }

    return 0;
}

/* ================================================================== */
/*  HANDLER: file — sensitive file access detection                    */
/* ================================================================== */

/* Shared: emit SENSITIVE_FILE alert. Called after path identified.
 * bit_type: 2=BIT_SENSITIVE_FILE, 3=BIT_NS_PROBE */
static int _emit_file_alert(u64 cg, u64 now, int bit_type) {
    struct behavior_state *state = container_behavior.lookup(&cg);
    if (state) {
        if (bit_type == 3) {
            state->flags |= BIT_NS_PROBE;
            state->bit_ts[3] = now;
        } else {
            state->flags |= BIT_SENSITIVE_FILE;
            state->bit_ts[2] = now;
        }
    }
    struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
    alert.type = ALERT_SENSITIVE_FILE;
    alert.pid = bpf_get_current_pid_tgid() >> 32;
    alert.cgroup_id = cg;
    alert.timestamp = now;
    alert.flags = state ? state->flags : BIT_SENSITIVE_FILE;
    emit_alert(&alert);
    return 0;
}

/* Path matching: if/else-if tree so the verifier can prune paths linearly.
 * Independent `if` blocks cause verifier state explosion (>1M explored insns).
 * Returns: 0=not sensitive, 2=BIT_SENSITIVE_FILE, 3=BIT_NS_PROBE */
static int _classify_path(const char *p) {
    /* All sensitive paths start with '/' */
    if (p[0] != 0x2f) return 0;
    /* Discriminate on p[1] */
    if (p[1] == 0x65) {
        /* 'e' → /etc/shadow */
        if (p[2]==0x74 && p[3]==0x63 && p[4]==0x2f &&
            p[5]==0x73 && p[6]==0x68 && p[7]==0x61)
            return 2;
    } else if (p[1] == 0x70) {
        /* 'p' → /proc/ prefix */
        if (p[2]==0x72 && p[3]==0x6f && p[4]==0x63 && p[5]==0x2f) {
            /* /proc/1/ → namespace probe */
            if (p[6]==0x31 && p[7]==0x2f)
                return 3;
            /* /proc/self/environ → env harvesting */
            if (p[6]==0x73 && p[7]==0x65 && p[8]==0x6c &&
                p[9]==0x66 && p[10]==0x2f && p[11]==0x65)
                return 2;
        }
    } else if (p[1] == 0x76) {
        /* 'v' → /var/run/secrets */
        if (p[2]==0x61 && p[3]==0x72 && p[4]==0x2f &&
            p[5]==0x72 && p[6]==0x75 && p[7]==0x6e &&
            p[8]==0x2f && p[9]==0x73 && p[10]==0x65 && p[11]==0x63)
            return 2;
    }
    return 0;
}

/* openat(2) (syscall 257): pathname is 2nd arg → regs->si */
int handle_file(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    long __path_raw = 0;
    bpf_probe_read_kernel(&__path_raw, sizeof(__path_raw), &regs->si);

    char path[64]; path[0] = 0;
    bpf_probe_read_user_str(path, sizeof(path), (void *)__path_raw);

    int bit = _classify_path(path);
    if (!bit) return 0;

    u64 cg = bpf_get_current_cgroup_id();
    u64 now = bpf_ktime_get_ns();
    return _emit_file_alert(cg, now, bit);
    /* No maybe_kill(): Tier 3 decides response from compound behavior. */
}

/* open(2) (syscall 2): pathname is 1st arg → regs->di */
int handle_file_open(struct bpf_raw_tracepoint_args *ctx) {
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    long __path_raw = 0;
    bpf_probe_read_kernel(&__path_raw, sizeof(__path_raw), &regs->di);

    char path[64]; path[0] = 0;
    bpf_probe_read_user_str(path, sizeof(path), (void *)__path_raw);

    int bit = _classify_path(path);
    if (!bit) return 0;

    u64 cg = bpf_get_current_cgroup_id();
    u64 now = bpf_ktime_get_ns();
    return _emit_file_alert(cg, now, bit);
}

/* ================================================================== */
/*  HANDLER: privesc — setuid/unshare/setns/ptrace                     */
/* ================================================================== */

int handle_privesc(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_nr = ctx->args[1];
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    long __priv_arg1 = 0;
    bpf_probe_read_kernel(&__priv_arg1, sizeof(__priv_arg1), &regs->di);

    u64 cg = bpf_get_current_cgroup_id();
    u64 now = bpf_ktime_get_ns();

    /* unshare (272) */
    if (syscall_nr == 272) {
        long flags_val = __priv_arg1;

        /* CLONE_NEWCGROUP: register for behavior inheritance only — do NOT alert/kill */
        if (flags_val & MY_CLONE_NEWCGROUP) {
            u64 pid_tgid = bpf_get_current_pid_tgid();
            pending_cgroup_inherit.update(&pid_tgid, &cg);
        }

        /* CLONE_NEWNS (0x00020000) or CLONE_NEWUSER (0x10000000): namespace escape */
        if (flags_val & 0x00020000 || flags_val & 0x10000000) {
            struct behavior_state *state = container_behavior.lookup(&cg);
            if (state) {
                state->flags |= BIT_PRIVESC;
                state->bit_ts[4] = now;
            }
            struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
            alert.type = ALERT_PRIVESC;
            alert.pid = bpf_get_current_pid_tgid() >> 32;
            alert.cgroup_id = cg;
            alert.timestamp = now;
            alert.flags = state ? state->flags : BIT_PRIVESC;
            alert.extra = syscall_nr;
            emit_alert(&alert);
            /* unshare(CLONE_NEWNS|CLONE_NEWUSER) is a strict invariant —
             * no production container workload does namespace-escape mid-serving. */
            maybe_kill(cg, 'A');
        }
        return 0;
    }

    /* setns (308), ptrace (101): always suspicious in container context */
    if (syscall_nr == 308 || syscall_nr == 101) {
        struct behavior_state *state = container_behavior.lookup(&cg);
        if (state) {
            state->flags |= BIT_PRIVESC;
            state->bit_ts[4] = now;
        }

        struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
        alert.type = ALERT_PRIVESC;
        alert.pid = bpf_get_current_pid_tgid() >> 32;
        alert.cgroup_id = cg;
        alert.timestamp = now;
        alert.flags = state ? state->flags : BIT_PRIVESC;
        alert.extra = syscall_nr;
        emit_alert(&alert);
        /* setns/ptrace inside a container is a strict invariant — no
         * legitimate web workload does cross-namespace tracing or jumping. */
        maybe_kill(cg, 'A');
        return 0;
    }

    /* setuid (105) — privilege escalation */
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 current_uid = (u32)uid_gid;
    if (current_uid == 0) return 0;  /* already root */

    long target_id = __priv_arg1;
    if (target_id != 0) return 0;

    struct behavior_state *state = container_behavior.lookup(&cg);
    if (state) {
        state->flags |= BIT_PRIVESC;
        state->bit_ts[4] = now;
    }

    struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
    alert.type = ALERT_PRIVESC;
    alert.pid = bpf_get_current_pid_tgid() >> 32;
    alert.cgroup_id = cg;
    alert.timestamp = now;
    alert.flags = state ? state->flags : BIT_PRIVESC;
    alert.extra = syscall_nr;
    emit_alert(&alert);

    /* setuid(0) from a non-root uid is a strict invariant bypass —
     * no legitimate container workload self-escalates to root mid-request. */
    maybe_kill(cg, 'A');
    return 0;
}

/* ================================================================== */
/*  PROBE B: tcp_v4_connect — connection tracking + two-hop detection  */
/* ================================================================== */

int trace_connect_entry(struct pt_regs *ctx) {
    /* Kernel 6.17 verifier rejects direct ctx->di access (offset 112 > 104).
     * Read the first argument via bpf_probe_read_kernel from the pt_regs. */
    u64 sk_raw = 0;
    bpf_probe_read_kernel(&sk_raw, sizeof(sk_raw), &ctx->di);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_key sk_k; sk_k.k = pid_tgid;
    struct sk_val sk_v; sk_v.v = sk_raw;
    connect_sk_stash.update(&sk_k, &sk_v);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_key sk_k; sk_k.k = pid_tgid;
    struct sk_val *skp = connect_sk_stash.lookup(&sk_k);
    if (!skp) return 0;

    struct sock *sk = (struct sock *)skp->v;
    connect_sk_stash.delete(&sk_k);

    u32 dst_addr = 0;
    u16 dst_port = 0;
    bpf_probe_read_kernel(&dst_addr, sizeof(dst_addr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sk->__sk_common.skc_dport);
    dst_port = ntohs(dst_port);

    u64 *dst_cg_ptr = ip_to_cgroup.lookup(&dst_addr);
    if (!dst_cg_ptr) return 0;
    u64 dst_cg = *dst_cg_ptr;

    u64 src_cg = bpf_get_current_cgroup_id();
    u64 now = bpf_ktime_get_ns();

    /* Update lateral connect bit */
    struct behavior_state *src_state = container_behavior.lookup(&src_cg);
    if (src_state) {
        src_state->flags |= BIT_LATERAL_CONNECT;
        src_state->bit_ts[1] = now;
        src_state->conn_dst_cg = dst_cg;
        src_state->conn_port = dst_port;

        /* Two-hop check: per-bit timestamp lazy expiry */
        /* Check bit0 (shell) and bit6 (fd_redirect) */
        int should_kill = 0;

        if (src_state->flags & BIT_SHELL_SPAWN) {
            if (now - src_state->bit_ts[0] < TWOHOP_WINDOW_NS) {
                should_kill = 1;
            } else {
                src_state->flags &= ~BIT_SHELL_SPAWN;  /* lazy expiry */
            }
        }

        if (src_state->flags & BIT_FD_REDIRECT) {
            if (now - src_state->bit_ts[6] < TWOHOP_WINDOW_NS) {
                should_kill = 1;
            } else {
                src_state->flags &= ~BIT_FD_REDIRECT;
            }
        }

        if (should_kill) {
            struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
            alert.type = ALERT_TWO_HOP;
            alert.pid = bpf_get_current_pid_tgid() >> 32;
            alert.cgroup_id = src_cg;
            alert.timestamp = now;
            alert.flags = src_state->flags;
            alert.extra = dst_cg;
            emit_alert(&alert);

            /* Two-hop = shell/FD-redirect bit + lateral connect within 5 s.
             * This is already a compound confirmation, treated as strict. */
            maybe_kill(src_cg, 'A');
        }
    }

    /* Connection event -> telemetry_rb (NOT alerts_rb) */
    struct alert_t conn; __builtin_memset(&conn, 0, sizeof(conn));
    conn.type = EVENT_CONNECTION;
    conn.pid = bpf_get_current_pid_tgid() >> 32;
    conn.cgroup_id = src_cg;
    conn.timestamp = now;
    conn.extra = ((u64)dst_addr << 32) | (u64)dst_port;
    conn.flags = dst_cg;
    emit_telemetry(&conn);

    return 0;
}

/* ================================================================== */
/*  ACCEPT TRACKING — populate cgroup_current_client for trust gating  */
/* ================================================================== */
/*
 * inet_csk_accept returns the newly-accepted struct sock*, whose skc_daddr
 * field already holds the peer (client) IPv4. We record that IP under the
 * accepting container's cgroup so maybe_kill() can look up per-IP trust when
 * a suspect syscall fires inside the same container.
 *
 * Attribution is best-effort: multi-threaded servers may have several
 * concurrent accepts. cgroup_current_client only remembers the most recent
 * peer — enough for the typical request→response flow where one inbound IP
 * drives the syscalls the handlers see. Trust promotion in Tier 3 is
 * idempotent per IP, so occasional misattribution at the edge is harmless.
 */
int trace_accept_return(struct pt_regs *ctx) {
    /* Retrieve struct sock* via return register (rax at offset 80 — within
     * the verifier's 104-byte ceiling, but read via probe to stay defensive). */
    u64 sk_raw = 0;
    bpf_probe_read_kernel(&sk_raw, sizeof(sk_raw), &ctx->ax);
    if (!sk_raw) return 0;

    struct sock *sk = (struct sock *)sk_raw;

    u32 peer_addr = 0;
    bpf_probe_read_kernel(&peer_addr, sizeof(peer_addr), &sk->__sk_common.skc_daddr);
    if (!peer_addr) return 0;

    u64 cg = bpf_get_current_cgroup_id();
    cgroup_current_client.update(&cg, &peer_addr);

    /* Per-TID attribution: the thread that did the accept() is almost always
     * the thread that then runs the request handler (per-connection-worker
     * model). Propagates to forked workers via sched_process_fork. */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    tid_client_ip.update(&pid_tgid, &peer_addr);

    /* Best-effort connection-context entry for Tier 3 L4-stability trust
     * promotion. Keyed by sock pointer so later recvmsg/sendmsg hooks (added
     * in Phase 3) can accumulate bytes_in / bytes_out against it. */
    struct conn_context cc;
    __builtin_memset(&cc, 0, sizeof(cc));
    cc.client_ip = peer_addr;
    cc.cgroup = cg;
    cc.established_ns = bpf_ktime_get_ns();
    cc.last_active_ns = cc.established_ns;
    connection_context.update(&sk_raw, &cc);

    return 0;
}

/* ================================================================== */
/*  L4 STABILITY — bytes_in / bytes_out accumulation                   */
/* ================================================================== */
/*
 * Tier 3 promotes a client IP from OBSERVED to CALIBRATED only after a
 * single flow accumulates ≥TRUST_BYTES_MIN bytes AND runs for
 * ≥TRUST_DURATION_NS. "A single flow" = one entry in connection_context,
 * keyed by sock pointer. Both hooks below are on the hot TCP path and
 * are intentionally minimal: lookup + two u64 updates.
 *
 * Why not do promotion in kernel: the policy (≥5120 B + ≥1 s) is cheap
 * to compute in userspace once per cycle, and centralising it in Tier 3
 * keeps the trust rule auditable and trivially reconfigurable.
 */

int trace_tcp_sendmsg(struct pt_regs *ctx) {
    /* tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size) */
    u64 sk_raw = 0;
    bpf_probe_read_kernel(&sk_raw, sizeof(sk_raw), &ctx->di);
    if (!sk_raw) return 0;

    u64 size_raw = 0;
    bpf_probe_read_kernel(&size_raw, sizeof(size_raw), &ctx->dx);

    struct conn_context *cc = connection_context.lookup(&sk_raw);
    if (!cc) return 0;

    cc->bytes_out += size_raw;
    cc->last_active_ns = bpf_ktime_get_ns();
    return 0;
}

int trace_tcp_recvmsg_entry(struct pt_regs *ctx) {
    /* Stash sock pointer keyed by pid_tgid so the return probe can attribute
     * the returned byte count to the right connection_context entry. */
    u64 sk_raw = 0;
    bpf_probe_read_kernel(&sk_raw, sizeof(sk_raw), &ctx->di);
    if (!sk_raw) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_key rk; rk.k = pid_tgid;
    struct sk_val sv; sv.v = sk_raw;
    tcp_recvmsg_stash.update(&rk, &sv);
    return 0;
}

int trace_tcp_recvmsg_return(struct pt_regs *ctx) {
    /* Return value is the number of bytes actually received (or -errno). */
    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ax);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sk_key rk; rk.k = pid_tgid;
    struct sk_val *skp = tcp_recvmsg_stash.lookup(&rk);
    if (!skp) return 0;
    u64 sk_raw = skp->v;
    tcp_recvmsg_stash.delete(&rk);

    if (ret <= 0) return 0;

    struct conn_context *cc = connection_context.lookup(&sk_raw);
    if (!cc) return 0;

    cc->bytes_in += (u64)ret;
    cc->last_active_ns = bpf_ktime_get_ns();
    return 0;
}

/* ================================================================== */
/*  PROBE C: sched_process_exec — process exec tracking                */
/* ================================================================== */

TRACEPOINT_PROBE(sched, sched_process_exec) {
    u64 cg = bpf_get_current_cgroup_id();
    u64 now = bpf_ktime_get_ns();

    /* Set shell_spawn bit on any exec (Probe C is broad) */
    /* handler_execve does the actual binary name matching */
    /* Probe C just records the lineage event for Tier 3 */

    struct alert_t evt; __builtin_memset(&evt, 0, sizeof(evt));
    evt.type = EVENT_CONNECTION + 1;  /* EVENT_EXEC = 101 */
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.cgroup_id = cg;
    evt.timestamp = now;
    emit_telemetry(&evt);

    return 0;
}

/* ================================================================== */
/*  INHERITED SIN — parent's behavior bits propagate to forked child   */
/* ================================================================== */
/*
 * When a task forks, the child may end up in a new cgroup if the clone was
 * issued with CLONE_NEWCGROUP, or the child may drop into a fresh cgroup via
 * a later unshare. In either case, if the parent already had any behavior
 * bits set (e.g., BIT_SHELL_SPAWN from an earlier execve), those bits must
 * propagate so the child can't reset its record by forking.
 *
 * Mechanism: stash the parent's cgroup keyed by the child's future pid_tgid.
 * When the child issues its first syscall, the dispatcher (step 4) sees the
 * pending entry and — if child cg ≠ parent cg — copies the parent's
 * behavior_state into the child's container_behavior record. Same-cgroup
 * forks are no-ops because behavior_state is already keyed by cgroup.
 */

TRACEPOINT_PROBE(sched, sched_process_fork) {
    u64 parent_cg = bpf_get_current_cgroup_id();
    u64 parent_pid_tgid = bpf_get_current_pid_tgid();

    /* Child's TID == TGID at birth; reconstruct the full pid_tgid key the
     * dispatcher uses. args->child_pid is the per-tracepoint child TID field. */
    u32 child_tid = args->child_pid;
    u64 child_pid_tgid = ((u64)child_tid << 32) | (u64)child_tid;

    /* 1. Inherited Sin: copy behavior flags if parent has any. */
    struct behavior_state *parent_state = container_behavior.lookup(&parent_cg);
    if (parent_state && parent_state->flags != 0) {
        pending_cgroup_inherit.update(&child_pid_tgid, &parent_cg);
    }

    /* 2. Client-IP inheritance: if parent had a per-TID client-IP attribution,
     * copy it to the child. Keeps attribution correct across fork-exec worker
     * patterns (e.g., Python multiprocessing, CGI-style spawn). */
    u32 *parent_ip = tid_client_ip.lookup(&parent_pid_tgid);
    if (parent_ip) {
        u32 ip = *parent_ip;
        tid_client_ip.update(&child_pid_tgid, &ip);
    }

    return 0;
}

/* ================================================================== */
/*  TC DROP CLASSIFIERS — attached to container veths                  */
/* ================================================================== */
/*
 * Program type: BPF_PROG_TYPE_SCHED_CLS (loader calls b.load_func with
 * BPF.SCHED_CLS). Attached via `tc filter add dev <veth> ingress/egress
 * bpf da fd <fd>` or equivalent pyroute2 call.
 *
 * Packet layout: [ETH][IP][TCP|UDP|...]. We only need ETH+IP for the drop
 * decision; deeper inspection would multiply verifier cost with no benefit.
 *
 * TTL semantics: each drop_ip_list entry has CLOCK_MONOTONIC expiry. The TC
 * program checks now < expire_ns; if the TTL has elapsed, packets pass
 * through again (self-healing). Tier 3 may also proactively evict entries.
 */

#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

static int __always_inline tc_drop_core(struct __sk_buff *skb, int is_egress) {
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Ethernet header */
    if (data + sizeof(struct ethhdr) > data_end) return TC_ACT_OK;
    struct ethhdr *eth = data;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    /* IPv4 header */
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
    struct iphdr *iph = data + sizeof(struct ethhdr);

    /* Ingress matches on source (attacker IP sending in);
     * egress matches on destination (container replying out). */
    u32 target_ip = is_egress ? iph->daddr : iph->saddr;

    /* Packet-seen counter */
    u32 seen_idx = is_egress ? TCSTAT_PKTS_SEEN_OUT : TCSTAT_PKTS_SEEN_IN;
    u64 *seen = tc_stats.lookup(&seen_idx);
    if (seen) __sync_fetch_and_add(seen, 1);

    u64 *expire = drop_ip_list.lookup(&target_ip);
    if (!expire) return TC_ACT_OK;

    u64 now = bpf_ktime_get_ns();
    if (now > *expire) {
        /* TTL elapsed — fall through. Cleanup happens lazily (Tier 3 evicts). */
        return TC_ACT_OK;
    }

    /* Drop counter */
    u32 drop_idx = is_egress ? TCSTAT_PKTS_DROPPED_OUT : TCSTAT_PKTS_DROPPED_IN;
    u64 *dropped = tc_stats.lookup(&drop_idx);
    if (dropped) __sync_fetch_and_add(dropped, 1);

    return TC_ACT_SHOT;
}

int tc_drop_ingress(struct __sk_buff *skb) {
    return tc_drop_core(skb, 0);
}

int tc_drop_egress(struct __sk_buff *skb) {
    return tc_drop_core(skb, 1);
}

/* ================================================================== */
/*  ENFORCEMENT KPROBES — surgical syscall denial                      */
/* ================================================================== */
/*
 * These kprobe programs use bpf_override_return() to make specific syscalls
 * return error codes WITHOUT killing the process. The container keeps running;
 * only the malicious operation fails.
 *
 * bpf_override_return() requires:
 *   - CONFIG_BPF_KPROBE_OVERRIDE=y (verified)
 *   - Function listed in error_injection/list (verified for all targets)
 *   - Kprobe (not raw tracepoint) program type
 *
 * Why separate from the raw tracepoint handlers:
 *   - Raw tracepoints can't use bpf_override_return()
 *   - Kprobes on __x64_sys_* can
 *   - The enforcement maps are populated asynchronously by Tier 3
 *   - These kprobes fire on every syscall — they must be fast (map lookup only)
 */

/* Helper: check if container is in enforcement mode and rules haven't expired */
static int __always_inline is_enforcing(u64 cg, u32 min_level) {
    struct enforce_state *es = enforce_level_map.lookup(&cg);
    if (!es) return 0;
    if (es->level < min_level) return 0;
    /* Check TTL */
    u64 now = bpf_ktime_get_ns();
    if (es->expire_ns > 0 && now > es->expire_ns) {
        /* Expired — daemon will clean up, but stop enforcing now */
        return 0;
    }
    return 1;
}

/* ── Enforce connect() — deny novel destinations, rate limit bursts ── */
int enforce_connect(struct pt_regs *ctx) {
#if ENFORCE_MODE
    u64 cg = bpf_get_current_cgroup_id();

    /* Fast path: no enforcement for this container */
    struct enforce_state *es = enforce_level_map.lookup(&cg);
    if (!es) return 0;

    u64 now = bpf_ktime_get_ns();

    /* Check TTL */
    if (es->expire_ns > 0 && now > es->expire_ns) return 0;

    /* Extract destination from sockaddr argument.
     * __x64_sys_connect(int fd, struct sockaddr *uservaddr, int addrlen)
     * sockaddr_in at offset: sin_family(2) + sin_port(2) + sin_addr(4) */
    long uaddr_raw = 0;
    bpf_probe_read_kernel(&uaddr_raw, sizeof(uaddr_raw), &ctx->si);
    if (!uaddr_raw) return 0;

    u16 sin_family = 0;
    bpf_probe_read_user(&sin_family, sizeof(sin_family), (void *)uaddr_raw);
    if (sin_family != 2) return 0;  /* AF_INET only */

    u16 sin_port = 0;
    bpf_probe_read_user(&sin_port, sizeof(sin_port), (void *)(uaddr_raw + 2));
    sin_port = ntohs(sin_port);

    u32 sin_addr = 0;
    bpf_probe_read_user(&sin_addr, sizeof(sin_addr), (void *)(uaddr_raw + 4));

    u64 dst_packed = ((u64)sin_addr << 32) | ((u64)sin_port << 16);

    /* Level 1 (DENY): check deny_connect_map for specific blocked destinations */
    if (es->level >= ENFORCE_DENY) {
        struct deny_connect_key dk = { .cgroup_id = cg, .dst_packed = dst_packed };
        struct deny_connect_val *dv = deny_connect_map.lookup(&dk);
        if (dv) {
            if (dv->expire_ns == 0 || now < dv->expire_ns) {
                /* Emit enforcement alert */
                struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
                alert.type = ALERT_ENFORCE_DENY;
                alert.pid = bpf_get_current_pid_tgid() >> 32;
                alert.cgroup_id = cg;
                alert.timestamp = now;
                alert.flags = dst_packed;
                alert.extra = (u64)(unsigned int)(-(dv->errno_val));
                emit_alert(&alert);

                bpf_override_return(ctx, (unsigned long)dv->errno_val);
                return 0;
            }
        }
    }

    /* Level 3 (THROTTLE): rate-limit connections to specific destinations */
    if (es->level >= ENFORCE_THROTTLE) {
        struct rate_limit_key rk = { .cgroup_id = cg, .dst_packed = dst_packed };
        struct rate_limit_val *rv = rate_limit_map.lookup(&rk);
        if (rv && rv->max_per_sec > 0) {
            if (rv->expire_ns > 0 && now > rv->expire_ns) goto skip_throttle;

            u64 window = 1000000000ULL; /* 1 second */
            if (now - rv->window_start > window) {
                rv->current_count = 1;
                rv->window_start = now;
            } else {
                rv->current_count += 1;
            }

            if (rv->current_count > rv->max_per_sec) {
                struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
                alert.type = ALERT_ENFORCE_THROTTLE;
                alert.pid = bpf_get_current_pid_tgid() >> 32;
                alert.cgroup_id = cg;
                alert.timestamp = now;
                alert.flags = dst_packed;
                alert.extra = rv->current_count;
                emit_alert(&alert);

                bpf_override_return(ctx, (unsigned long)(-11)); /* -EAGAIN */
                return 0;
            }
        }
    }
skip_throttle:

    /* Level 4 (FIREWALL): only calibrated destinations allowed */
    if (es->level >= ENFORCE_FIREWALL) {
        struct fw_allow_key fk = { .cgroup_id = cg, .dst_packed = dst_packed };
        u32 *allowed = fw_allow_map.lookup(&fk);
        if (!allowed) {
            struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
            alert.type = ALERT_ENFORCE_DENY;
            alert.pid = bpf_get_current_pid_tgid() >> 32;
            alert.cgroup_id = cg;
            alert.timestamp = now;
            alert.flags = dst_packed;
            alert.extra = 111; /* ECONNREFUSED */
            emit_alert(&alert);

            bpf_override_return(ctx, (unsigned long)(-111)); /* -ECONNREFUSED */
            return 0;
        }
    }

    /* Level 6 (QUARANTINE): block ALL outbound connections */
    if (es->level >= ENFORCE_QUARANTINE) {
        bpf_override_return(ctx, (unsigned long)(-101)); /* -ENETUNREACH */
        return 0;
    }
#endif
    return 0;
}

/* ── Enforce openat() — deny sensitive file reads ── */
int enforce_openat(struct pt_regs *ctx) {
#if ENFORCE_MODE
    u64 cg = bpf_get_current_cgroup_id();

    struct enforce_state *es = enforce_level_map.lookup(&cg);
    if (!es || es->level < ENFORCE_DENY) return 0;

    u64 now = bpf_ktime_get_ns();
    if (es->expire_ns > 0 && now > es->expire_ns) return 0;

    /* Read path from second argument (openat: dirfd, pathname, flags, mode) */
    long path_raw = 0;
    bpf_probe_read_kernel(&path_raw, sizeof(path_raw), &ctx->si);
    if (!path_raw) return 0;

    char path[32];
    __builtin_memset(path, 0, sizeof(path));
    bpf_probe_read_user_str(path, sizeof(path), (void *)path_raw);

    /* Simple hash of first 16 bytes for map lookup */
    u64 h = 14695981039346656037ULL; /* FNV-1a offset basis */
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        h ^= (u64)(unsigned char)path[i];
        h *= 1099511628211ULL; /* FNV prime */
    }

    struct deny_open_key dk = { .cgroup_id = cg, .path_hash = h };
    struct deny_open_val *dv = deny_open_map.lookup(&dk);
    if (dv) {
        if (dv->expire_ns == 0 || now < dv->expire_ns) {
            struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
            alert.type = ALERT_ENFORCE_DENY;
            alert.pid = bpf_get_current_pid_tgid() >> 32;
            alert.cgroup_id = cg;
            alert.timestamp = now;
            alert.flags = h;
            alert.extra = (u64)(unsigned int)(-(dv->errno_val));
            emit_alert(&alert);

            bpf_override_return(ctx, (unsigned long)dv->errno_val);
            return 0;
        }
    }
#endif
    return 0;
}

/* ── Enforce execve() — deny suspicious binary execution ── */
int enforce_execve(struct pt_regs *ctx) {
#if ENFORCE_MODE
    u64 cg = bpf_get_current_cgroup_id();

    struct enforce_state *es = enforce_level_map.lookup(&cg);
    if (!es || es->level < ENFORCE_DENY) return 0;

    u64 now = bpf_ktime_get_ns();
    if (es->expire_ns > 0 && now > es->expire_ns) return 0;

    /* Read filename from first argument */
    long fname_raw = 0;
    bpf_probe_read_kernel(&fname_raw, sizeof(fname_raw), &ctx->di);
    if (!fname_raw) return 0;

    char path[32];
    __builtin_memset(path, 0, sizeof(path));
    bpf_probe_read_user_str(path, sizeof(path), (void *)fname_raw);

    /* FNV-1a hash of first 16 bytes */
    u64 h = 14695981039346656037ULL;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        h ^= (u64)(unsigned char)path[i];
        h *= 1099511628211ULL;
    }

    struct deny_exec_key dk = { .cgroup_id = cg, .path_hash = h };
    struct deny_exec_val *dv = deny_exec_map.lookup(&dk);
    if (dv) {
        if (dv->expire_ns == 0 || now < dv->expire_ns) {
            struct alert_t alert; __builtin_memset(&alert, 0, sizeof(alert));
            alert.type = ALERT_ENFORCE_DENY;
            alert.pid = bpf_get_current_pid_tgid() >> 32;
            alert.cgroup_id = cg;
            alert.timestamp = now;
            alert.flags = h;
            alert.extra = (u64)(unsigned int)(-(dv->errno_val));
            emit_alert(&alert);

            bpf_override_return(ctx, (unsigned long)dv->errno_val);
            return 0;
        }
    }
#endif
    return 0;
}
