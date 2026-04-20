# tier3/calibrate_runner.py
"""
Calibration Runner — collects live BPF data during normal operation
and produces the restriction maps, thresholds, and PCA model.

Invoked by: sudo python3 loader.py --calibrate
Duration: 30-60 minutes (controlled by CALIBRATION_DURATION_S)

What it does:
  1. Every SAMPLE_INTERVAL seconds, reads bigram_sketch_map from BPF
  2. Reads connection events from telemetry_rb
  3. After duration completes, calls SheafCalibrator.calibrate()
  4. Saves all calibration artifacts to CALIBRATION_DIR

Pre-requisites:
  - docker compose up -d (containers running)
  - bash scripts/generate_normal_traffic.sh (running in another terminal)
  - loader.py is already running with probes attached (BPF maps are live)
"""
import os, time, ctypes, logging, json
from collections import defaultdict
from pathlib import Path
from bcc import BPF

try:
    from signal_extractor import BigramSketch
except ImportError:
    from .signal_extractor import BigramSketch
import numpy as np

CALIBRATION_DIR = "calibration"
CALIBRATION_DURATION_S = int(os.environ.get("CAUSALTRACE_CALIBRATION_S", 600))  # env overridable
SAMPLE_INTERVAL = 5.0            # read BPF maps every 5 seconds (one CMS window)

log = logging.getLogger("causaltrace.calibrate")


# ─── BPF Struct mirrors ───────────────────────────────────────────────
# These must EXACTLY match the C structs in causaltrace_common.h.
# Field order, sizes, and padding must be identical.
# Use ctypes to read raw BPF map values.

import ctypes

class CBigramSketch(ctypes.Structure):
    """Mirror of struct bigram_sketch from causaltrace_common.h.
    BCC 0.31 mishandles 2D arrays, so C uses flat counters[CMS_ROWS*CMS_COLS]."""
    _fields_ = [
        ("counters", ctypes.c_uint32 * (4 * 128)),   # flat [r*128+c]
        ("prev_idx", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("total_count", ctypes.c_uint64),
        ("window_start", ctypes.c_uint64),
    ]
    # sizeof = 2048 + 4 + 4 + 8 + 8 = 2072 bytes

class CBehaviorState(ctypes.Structure):
    """Mirror of struct behavior_state from causaltrace_common.h."""
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("bit_ts", ctypes.c_uint64 * 8),
        ("conn_dst_cg", ctypes.c_uint64),
        ("conn_port", ctypes.c_uint16),
        ("_pad", ctypes.c_uint16 * 3),
    ]
    # sizeof = 8 + 64 + 8 + 2 + 6 = 88 bytes

class CAlertT(ctypes.Structure):
    """Mirror of struct alert_t from causaltrace_common.h."""
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("cgroup_id", ctypes.c_uint64),
        ("timestamp", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
        ("extra", ctypes.c_uint64),
    ]
    # sizeof = 40 bytes


def read_bigram_sketches(bpf_obj: BPF) -> dict:
    """
    Read all bigram sketches from BPF map.
    Returns: {cgroup_id (int): BigramSketch}
    """
    sketches = {}
    bigram_map = bpf_obj.get_table("bigram_sketch_map")

    for key, value in bigram_map.items():
        cg_id = key.value

        # Reconstruct numpy counters array from BCC map value.
        # BCC represents u32 counters[4][128] as a nested ctypes array
        # (c_uint32 * 128) * 4, so correct access is value.counters[r][c].
        counters = np.zeros((4, 128), dtype=np.uint32)
        for r in range(4):
            for c in range(128):
                counters[r, c] = value.counters[r * 128 + c]

        sketches[cg_id] = BigramSketch(
            counters=counters,
            prev_idx=int(value.prev_idx),
            total_count=int(value.total_count),
            window_start=int(value.window_start),
        )

    return sketches


def drain_connection_events(bpf_obj, event_buffer):
    """Poll telemetry ring buffer. Ring buffer must already be open."""
    bpf_obj.ring_buffer_poll(timeout=200)



def run_calibration(bpf_obj: BPF,
                    duration_s: int = CALIBRATION_DURATION_S,
                    sample_interval: float = SAMPLE_INTERVAL):
    """
    Main calibration entry point. Called from loader.py --calibrate.

    Algorithm:
      Every SAMPLE_INTERVAL seconds:
        - Read current bigram_sketch_map snapshot
        - Collect connection events from telemetry_rb
        - Store both in growing lists

      After duration_s:
        - Run SheafCalibrator.calibrate() on collected data
        - Save artifacts to CALIBRATION_DIR
    """
    log.info(f"Starting calibration ({duration_s // 60} minutes).")

    # Open telemetry ring buffer ONCE (cannot reopen)
    connection_events = []
    _conn_buf_ref = connection_events  # closure reference
    EVENT_CONNECTION = 100
    def _handle_telemetry(ctx, data, size):
        import ctypes
        class AlertT(ctypes.Structure):
            _fields_ = [
                ("type", ctypes.c_uint32), ("pid", ctypes.c_uint32),
                ("cgroup_id", ctypes.c_uint64), ("timestamp", ctypes.c_uint64),
                ("flags", ctypes.c_uint64), ("extra", ctypes.c_uint64),
            ]
        try:
            evt = ctypes.cast(data, ctypes.POINTER(AlertT)).contents
            if evt.type == EVENT_CONNECTION:
                _conn_buf_ref.append({
                    'src_cg': int(evt.cgroup_id),
                    'dst_cg': int(evt.flags),
                    'dst_port': int(evt.extra & 0xFFFF),
                    'timestamp': int(evt.timestamp),
                })
        except Exception:
            pass
    try:
        bpf_obj["telemetry_rb"].open_ring_buffer(_handle_telemetry)
    except Exception as e:
        log.warning(f"Could not open telemetry ring buffer: {e}")
        log.warning("Connection events will not be collected (sheaf edges may be empty)")
    log.info("Ensure normal traffic is running: bash scripts/generate_normal_traffic.sh")
    log.info("")

    # Collected data
    bigram_traces  = defaultdict(list)   # cg_id → [BigramSketch, ...]
    # connection_events already initialized above

    start = time.monotonic()
    samples_collected = 0
    last_report = start

    while True:
        elapsed = time.monotonic() - start
        if elapsed >= duration_s:
            break

        # Progress report every 60 seconds
        if time.monotonic() - last_report >= 60:
            mins = int(elapsed // 60)
            total_mins = duration_s // 60
            log.info(f"  [{mins}/{total_mins} min] "
                     f"{samples_collected} samples, "
                     f"{len(connection_events)} connections")
            last_report = time.monotonic()

        # Read BPF maps
        sketches = read_bigram_sketches(bpf_obj)
        drain_connection_events(bpf_obj, connection_events)

        for cg_id, sketch in sketches.items():
            if sketch.total_count > 0:   # skip empty windows
                bigram_traces[cg_id].append(sketch)

        samples_collected += 1
        time.sleep(sample_interval)

    # ── Calibration ───────────────────────────────────────────────────
    log.info("")
    log.info(f"Calibration data collection complete.")
    log.info(f"  Containers observed: {list(bigram_traces.keys())}")
    log.info(f"  Samples per container: "
             f"{[len(v) for v in bigram_traces.values()]}")
    log.info(f"  Connection events: {len(connection_events)}")

    if not bigram_traces:
        log.error("No bigram data collected. Is normal traffic running?")
        return

    if len(bigram_traces) < 2:
        log.error("Only 1 container observed. Need ≥2 for sheaf edges.")
        return

    min_samples = min(len(v) for v in bigram_traces.values())
    if min_samples < 60:
        log.warning(f"Only {min_samples} samples for some containers. "
                    f"Need ≥60 (5 minutes) for stable CCA. "
                    f"Consider running longer.")

    # Run the full calibration pipeline
    from calibrate import SheafCalibrator
    cal = SheafCalibrator(d=74, k=15)
    cal.calibrate(
        bigram_traces=dict(bigram_traces),
        connection_events=connection_events,
        duration_minutes=duration_s / 60,
    )

    # Save artifacts
    Path(CALIBRATION_DIR).mkdir(parents=True, exist_ok=True)
    cal.save(CALIBRATION_DIR)

    log.info("")
    log.info(f"Calibration complete. Artifacts saved to {CALIBRATION_DIR}/")
    log.info("Restart loader in --mode enforce to enable detection.")
