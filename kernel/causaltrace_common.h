// causaltrace_common.h
// ─── REQUIRED INCLUDES ────────────────────────────────────────────────
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── CONSTANTS ────────────────────────────────────────────────────────
#define MAX_CONTAINERS     256
#define CMS_ROWS           4           // Count-Min Sketch hash rows
#define CMS_COLS           128         // Must be power of 2 for fast masking
#define CMS_COL_MASK       (CMS_COLS - 1)   // = 0x7F — verifier bound
#define TOP_SYSCALLS       25          // 24 tracked + 1 "other" bucket
#define MAX_BIGRAMS        (TOP_SYSCALLS * TOP_SYSCALLS)  // = 625
#define WINDOW_NS          (5ULL * 1000000000ULL)   // 5-second CMS window
#define MAX_FD             1024        // fd bound for verifier
#define TWOHOP_WINDOW_NS   (5ULL * 1000000000ULL)   // 5s for two-hop detection

// ─── ALERT TYPE CODES ─────────────────────────────────────────────────
#define ALERT_FORK_BOMB       1
#define ALERT_REVERSE_SHELL   2
#define ALERT_SENSITIVE_FILE  3
#define ALERT_PRIVESC         4
#define ALERT_FD_REDIRECT     5
#define ALERT_FORK_ACCEL      6
#define ALERT_TWO_HOP         7
#define ALERT_NS_ESCAPE       8
#define EVENT_CONNECTION    100   // telemetry only (not a security alert)

// ─── VERDICT CODES ────────────────────────────────────────────────────
#define VERDICT_ALLOW  0
#define VERDICT_KILL   1

// ─── BEHAVIOR BITFIELD DEFINITIONS ────────────────────────────────────
#define BIT_SHELL_SPAWN     (1ULL << 0)
#define BIT_LATERAL_CONNECT (1ULL << 1)
#define BIT_SENSITIVE_FILE  (1ULL << 2)
#define BIT_NS_PROBE        (1ULL << 3)
#define BIT_PRIVESC         (1ULL << 4)
#define BIT_LARGE_TRANSFER  (1ULL << 5)
#define BIT_FD_REDIRECT     (1ULL << 6)   // INVARIANT: socket→stdin/stdout/stderr
#define BIT_FORK_ACCEL      (1ULL << 7)   // INVARIANT: exponential fork acceleration

// ─── STRUCTS ──────────────────────────────────────────────────────────

// Per-container behavioral state — 8 flag bits + 8 per-bit timestamps
// IMPORTANT: bit_ts[i] stores the timestamp when bit i was last set.
// This prevents stale-bit false positives (the single-ts design bug).
struct behavior_state {
    __u64 flags;         // 64-bit behavior bitfield (only bits 0-7 used)
    __u64 bit_ts[8];     // per-bit timestamps (ns from bpf_ktime_get_ns())
    __u64 conn_dst_cg;   // last lateral connect() destination cgroup_id
    __u16 conn_port;     // last lateral connect() destination port
    __u16 _pad[3];       // alignment padding
    // sizeof = 8 + 64 + 8 + 2 + 6 = 88 bytes
};

// Fork rate tracking — three-window history for acceleration detection
struct rate_state {
    __u64 window_start;    // ns timestamp of current window start
    __u64 count;           // fork count in current 1s window
    __u64 prev_count;      // fork count in previous 1s window
    __u64 prev_prev_count; // fork count two windows ago
    // sizeof = 32 bytes
};

// Bigram Count-Min Sketch — one per container
// Tracks (syscall_i → syscall_{i+1}) transition counts
struct bigram_sketch {
    __u32 counters[CMS_ROWS][CMS_COLS];  // 4 × 128 = 512 entries × 4B = 2048B
    __u32 prev_idx;    // index of last tracked syscall (0-24); NOT updated for noise syscalls
    __u32 _pad;        // alignment
    __u64 total_count; // total bigrams observed in current window
    __u64 window_start; // ns timestamp of current window start
    // sizeof = 2048 + 4 + 4 + 8 + 8 = 2072 bytes
};

// Alert/event record — written to ring buffers
struct alert_t {
    __u32 type;        // ALERT_* or EVENT_CONNECTION constant
    __u32 pid;         // pid (upper 32 bits of pid_tgid)
    __u64 cgroup_id;   // source container
    __u64 timestamp;   // bpf_ktime_get_ns()
    __u64 flags;       // behavior bitfield snapshot at alert time
    __u64 extra;       // type-specific context:
                       //   FD_REDIRECT: (oldfd << 32) | newfd
                       //   FORK_ACCEL: current fork rate
                       //   TWO_HOP: dst_cgroup_id
                       //   CONNECTION: (dst_ip << 32) | dst_port
    // sizeof = 40 bytes
};

// ─── CMS HASH CONSTANTS ───────────────────────────────────────────────
// Different primes for each row to minimize hash collisions
// These are compile-time constants — the verifier sees them as proven bounds
static const __u32 CMS_PRIMES[CMS_ROWS] = {
    2654435761U, 2246822519U, 3266489917U, 668265263U
};
static const __u32 CMS_SEEDS[CMS_ROWS] = {1, 7, 13, 31};

// ─── SYSCALL INDEX MAPPING ────────────────────────────────────────────
// Maps syscall numbers to [0..24] indices for bigram CMS.
// 24 tracked syscalls + index 24 for "everything else".
// SECURITY NOTE: Dangerous syscalls are explicitly tracked (not in "other"):
//   ptrace, mount, unshare, setns, memfd_create, bpf, io_uring_enter
static __always_inline __u32 syscall_to_idx(__u32 nr) {
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
        case 101: return 16;  // ptrace      ← security-critical: explicitly tracked
        case 165: return 17;  // mount       ← container escape vector
        case 272: return 18;  // unshare     ← namespace manipulation
        case 308: return 19;  // setns       ← namespace transition
        case 319: return 20;  // memfd_create ← fileless malware
        case 321: return 21;  // bpf         ← attacker eBPF abuse
        case 426: return 22;  // io_uring_enter ← io_uring bypass
        case 59:  return 23;  // execve      ← always track
        default:  return 24;  // other
    }
}

// ─── NOISE SYSCALL FILTER ─────────────────────────────────────────────
// Returns 1 if the syscall should be skipped for bigram purposes.
// These syscalls have no side effects and are used for obfuscation.
// IMPORTANT: tail-call dispatch still fires for these (Tier 1 invariants
//   are NOT skipped). Only the bigram prev_idx update is skipped.
// SECURITY: If attacker uses non-noise syscalls to break bigrams,
//   those syscalls inflate their bigram counts → sheaf detects distribution shift.
static __always_inline int is_noise_syscall(__u32 nr) {
    switch (nr) {
        case 39:   // getpid
        case 102:  // getuid
        case 186:  // gettid
        case 110:  // getppid
        case 201:  // time
        case 228:  // clock_gettime
            return 1;
        default:
            return 0;
    }
}
