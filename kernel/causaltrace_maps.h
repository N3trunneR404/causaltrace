// causaltrace_maps.h
// All maps are declared here and pinned to the BPF filesystem.
// Maps are shared across all eBPF programs via BCC pinning.

// ─── CORE CONTROL MAPS ────────────────────────────────────────────────

// Host mount namespace inode — used to identify host processes vs. container processes
// Written once by loader at startup. Read by every syscall handler.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);   // host ns inum from /proc/self/ns/mnt
} host_ns SEC(".maps");

// Tail-call dispatch table — maps syscall_nr → eBPF program fd
// Written by loader (attaches handler programs). Read by dispatcher.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 512);
    __type(key, __u32);     // syscall number
    __type(value, __u32);   // program fd
} prog_array SEC(".maps");

// ─── TIER 3 → TIER 1 FEEDBACK ─────────────────────────────────────────
// Written by Tier 3 Python daemon with verdict for known-bad containers.
// Read by dispatcher on EVERY syscall — instant kill without userspace round-trip.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);     // cgroup_id
    __type(value, __u32);   // VERDICT_ALLOW or VERDICT_KILL
} verdict_map SEC(".maps");

// ─── TIER 1 STATE MAPS ────────────────────────────────────────────────

// Fork rate tracking — three consecutive 1-second windows per container
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);                  // cgroup_id
    __type(value, struct rate_state);
} rate_map SEC(".maps");

// Per-container behavioral bitfield + per-bit timestamps
// CRITICAL: bit_ts[i] is the timestamp when bit i was last set.
// Lazy expiry: bits older than TWOHOP_WINDOW_NS are cleared on read.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);                     // cgroup_id
    __type(value, struct behavior_state);   // 88 bytes
} container_behavior SEC(".maps");

// ─── TIER 2 STATE MAPS ────────────────────────────────────────────────

// IP → cgroup_id: populated by Docker event listener (user-space)
// Read by Probe B to resolve dst_ip → dst_cgroup_id
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u32);     // IPv4 address (network byte order)
    __type(value, __u64);   // cgroup_id of container with this IP
} ip_to_cgroup SEC(".maps");

// Bigram Count-Min Sketch — one entry per container
// PRE-POPULATED by Docker event listener with zeroed entries to avoid cold-path stack overflow.
// Updated by dispatcher on every container syscall.
// Read by Tier 3 daemon every detection cycle.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONTAINERS);
    __type(key, __u64);                     // cgroup_id
    __type(value, struct bigram_sketch);    // 2072 bytes
} bigram_sketch_map SEC(".maps");

// tcp_v4_connect sk-stash: entry → return probe communication
// LRU to prevent map exhaustion under SYN flood attacks.
// Increased to 4096 entries for headroom.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);   // LRU not HASH (prevents exhaustion)
    __uint(max_entries, 4096);
    __type(key, __u64);    // pid_tgid
    __type(value, __u64);  // struct sock * (stored as u64)
} connect_sk_stash SEC(".maps");

// Cgroup inheritance: tracks PIDs that called unshare(CLONE_NEWCGROUP)
// Written by privesc handler, read and cleared by dispatcher
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    // pid_tgid
    __type(value, __u64);  // old cgroup_id (before unshare)
} pending_cgroup_inherit SEC(".maps");

// ─── RING BUFFERS — SPLIT BY PRIORITY ────────────────────────────────
// CRITICAL: Split prevents telemetry floods from starving security alerts.

// High-priority alerts from Tier 1 handlers ONLY (ALERT_* events)
// Low volume (one entry per attack event), high priority
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);     // 64KB
} alerts_rb SEC(".maps");

// Tier 2 connection tracking events (EVENT_CONNECTION)
// Higher volume (one entry per inter-container connection)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    // 256KB
} telemetry_rb SEC(".maps");

// ─── STATISTICS ───────────────────────────────────────────────────────
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");
// Index definitions: [0]=total_syscalls, [1]=container_syscalls,
// [2]=alerts_fired, [3]=kills_issued, [4]=novel_edges
