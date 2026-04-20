#!/bin/bash
# install.sh — idempotent bootstrap for CausalTrace.
#
# Safe to run multiple times. Does not replace an existing venv and
# does not re-apt-install packages that are already present. Root is
# required for the apt and BPF-filesystem steps; the venv step drops
# to the invoking user if SUDO_USER is set.
#
# Usage:
#   sudo bash install.sh
#
# What it does:
#   1. Detect the distro; on Ubuntu/Debian, install BCC toolchain +
#      clang + docker + iproute2 + bpftool + kernel headers.
#   2. Mount /sys/fs/bpf if not mounted (needed for map/prog pinning).
#   3. Create /sys/fs/bpf/causaltrace for phase-2 TC filter pins.
#   4. Create the Python venv (./venv) and pip-install requirements.txt.
#   5. Print next-steps so the operator knows what to do.

set -u

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

ok()   { printf '  [ok]   %s\n' "$*"; }
info() { printf '  [info] %s\n' "$*"; }
warn() { printf '  [warn] %s\n' "$*"; }
fail() { printf '  [FAIL] %s\n' "$*"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
    fail "install.sh must run as root (needs apt + BPF fs). Try: sudo bash install.sh"
fi

echo "CausalTrace installer"
echo "----------------------------------------"

# 1. apt packages
if command -v apt-get >/dev/null; then
    info "distro: apt-based; installing system packages"
    APT_PKGS=(
        bpfcc-tools
        python3-bcc
        clang
        llvm
        "linux-headers-$(uname -r)"
        docker.io
        docker-compose-v2
        iproute2
        linux-tools-common
        linux-tools-generic
        python3-venv
        python3-pip
        ca-certificates
    )
    # Install only those not already present, to stay idempotent.
    TO_INSTALL=()
    for p in "${APT_PKGS[@]}"; do
        if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
            TO_INSTALL+=("$p")
        fi
    done
    if [ "${#TO_INSTALL[@]}" -eq 0 ]; then
        ok "all apt packages already installed"
    else
        info "installing: ${TO_INSTALL[*]}"
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            "${TO_INSTALL[@]}" || fail "apt-get install failed"
        ok "apt packages installed"
    fi
else
    warn "non-apt distro detected; install BCC/clang/docker/iproute2 manually"
fi

# 2. BPF filesystem mount
if mount | grep -q 'type bpf'; then
    ok "BPF fs already mounted"
else
    info "mounting /sys/fs/bpf"
    mount -t bpf bpf /sys/fs/bpf || fail "could not mount BPF fs"
    # Persist across reboots.
    if ! grep -q 'bpf /sys/fs/bpf' /etc/fstab 2>/dev/null; then
        echo 'bpf /sys/fs/bpf bpf defaults 0 0' >> /etc/fstab
        ok "added persistent mount to /etc/fstab"
    fi
fi

# 3. pin directory for TC drop (phase 2)
if [ ! -d /sys/fs/bpf/causaltrace ]; then
    mkdir -p /sys/fs/bpf/causaltrace
    chmod 0700 /sys/fs/bpf/causaltrace
    ok "created /sys/fs/bpf/causaltrace"
else
    ok "pin dir /sys/fs/bpf/causaltrace already exists"
fi

# 4. Python venv. Drop to the invoking user so the venv isn't root-owned.
TARGET_USER="${SUDO_USER:-root}"
VENV_DIR="${REPO_ROOT}/venv"
if [ ! -d "$VENV_DIR" ]; then
    info "creating venv at $VENV_DIR as user $TARGET_USER"
    sudo -u "$TARGET_USER" python3 -m venv "$VENV_DIR" \
        || fail "venv creation failed"
fi
info "pip-install requirements.txt"
sudo -u "$TARGET_USER" "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
sudo -u "$TARGET_USER" "$VENV_DIR/bin/pip" install -r "$REPO_ROOT/requirements.txt" \
    || fail "pip install failed"
ok "venv ready"

# 5. Docker service up
if systemctl list-unit-files 2>/dev/null | grep -q '^docker.service'; then
    if ! systemctl is-active --quiet docker; then
        systemctl enable --now docker >/dev/null 2>&1 || \
            warn "could not enable dockerd; you may need to start it manually"
    fi
    ok "dockerd active"
fi

# 6. logrotate config (optional, best-effort)
if [ -d /etc/logrotate.d ] && [ -f "$REPO_ROOT/config/causaltrace.logrotate" ]; then
    cp -f "$REPO_ROOT/config/causaltrace.logrotate" /etc/logrotate.d/causaltrace
    chmod 0644 /etc/logrotate.d/causaltrace
    ok "installed /etc/logrotate.d/causaltrace"
fi

echo "----------------------------------------"
echo "Install complete."
echo ""
echo "Next steps:"
echo "  1. Start the testbed:       docker compose up -d"
echo "  2. Run preflight:           bash scripts/preflight.sh"
echo "  3. Calibrate (10 min):      sudo ./venv/bin/python loader.py --calibrate"
echo "  4. Validate calibration:    ./venv/bin/python -m tier3.calibration_driver ./calibration"
echo "  5. Start the daemon:        sudo ./venv/bin/python supervisor.py -- --mode enforce"
echo ""
