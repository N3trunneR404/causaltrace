// probe_c_lineage.bpf.c
#include "causaltrace_common.h"
#include "causaltrace_maps.h"

// Track shell spawns via exec events
SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx) {
    // Get filename from tracepoint args
    unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
    char *fname = (char *)ctx + fname_off;

    // Check if this is a shell binary
    // Same matching logic as handler_execve but via tracepoint (not kprobe)
    char ch0 = 0, ch1 = 0, ch2 = 0;
    bpf_probe_read_kernel(&ch0, 1, fname);
    bpf_probe_read_kernel(&ch1, 1, fname + 1);
    bpf_probe_read_kernel(&ch2, 1, fname + 2);

    int is_shell = 0;
    if (ch0=='s' && ch1=='h' && ch2=='\0') is_shell = 1;
    if (ch0=='b' && ch1=='a' && ch2=='s') is_shell = 1;  // bash
    if (ch0=='d' && ch1=='a' && ch2=='s') is_shell = 1;  // dash
    if (ch0=='n' && ch1=='c' && ch2=='\0') is_shell = 1; // nc

    if (is_shell) {
        __u64 cg = bpf_get_current_cgroup_id();
        __u64 now = bpf_ktime_get_ns();

        struct behavior_state *state = bpf_map_lookup_elem(&container_behavior, &cg);
        if (state) {
            state->flags |= BIT_SHELL_SPAWN;
            state->bit_ts[0] = now;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
