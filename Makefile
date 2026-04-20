# CausalTrace — convenience targets for the 20-container Phase-12 testbed.
# Usage: `make help` lists every target. Invoke with a real shell; this is
# plain GNU make, nothing fancy.

.PHONY: help up down preflight routes calibrate minirun attack user monitor \
        marathon figures clean status

SHELL          := /bin/bash
VENV_PYTHON    := ./venv/bin/python
CALIBRATION_S  ?= 1800
PROJECT_DIR    := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

help:                 ## Show every target with its one-line description
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	 | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

up:                   ## Bring up the 20-container mesh and configure routes
	docker compose up -d
	@echo "waiting for containers to settle..."
	@sleep 8
	sudo bash scripts/setup_routes.sh
	bash scripts/test_connectivity.sh || true
	docker ps --format '{{.Names}}' | sort

down:                 ## Stop and remove the mesh
	docker compose down

preflight:            ## Run preflight checks (kernel, BCC, bridges, cgroups)
	bash scripts/preflight.sh

routes:               ## Re-apply cross-bridge routing (idempotent)
	sudo bash scripts/setup_routes.sh

calibrate:            ## Fresh calibration: traffic driver + loader --calibrate (CALIBRATION_S=$(CALIBRATION_S))
	@echo "────── calibration start, duration=$(CALIBRATION_S)s ──────"
	@rm -rf $(PROJECT_DIR)/calibration && mkdir -p $(PROJECT_DIR)/calibration
	@( python3 scripts/calibration_driver.py --duration $(CALIBRATION_S) \
	       --workers 8 --period 0.4 \
	       --report $(PROJECT_DIR)/calibration/driver_report.json \
	       2>&1 | sed 's/^/[driver] /' ) & \
	 DRIVER=$$!; \
	 sudo CAUSALTRACE_CALIBRATION_S=$(CALIBRATION_S) \
	      $(PROJECT_DIR)/venv/bin/python loader.py --calibrate \
	      2>&1 | sed 's/^/[loader] /'; \
	 wait $$DRIVER || true
	$(VENV_PYTHON) -m tier3.calibration_driver ./calibration

minirun:              ## Quick 50-run shakedown (~10 min) with pass/fail gates
	sudo bash scripts/minirun.sh

attack:               ## Drop into the attacker shell (source IP 10.88.1.100)
	bash scripts/attacker_shell.sh

user:                 ## Drop into a legitimate-user shell (source IP 10.88.0.200)
	bash scripts/user_shell.sh

monitor:              ## Watch live CausalTrace verdicts in colour
	bash scripts/watch_alerts.sh

marathon:             ## Launch the full marathon run (150-attack permutation × 3 tools)
	sudo setsid bash scripts/marathon.sh < /dev/null &
	@sleep 2
	@echo "marathon launched; tail results/marathon/marathon.log to follow"

figures:              ## Regenerate the paper figures from the latest results
	$(VENV_PYTHON) generate_astar_plots.py

clean:                ## Wipe results/, calibration/, and stray BPF pin files
	rm -rf results/marathon/*.jsonl results/marathon/*.json results/marathon/*.log 2>/dev/null || true
	rm -rf calibration/* 2>/dev/null || true
	rm -f /tmp/ct_heartbeat /tmp/cgroup_snapshot_*.txt 2>/dev/null || true

status:               ## Quick status: containers, pinned BPF, calibration state
	@echo "── containers ──" && docker ps --format '{{.Names}}\t{{.Status}}' | sort
	@echo "── pinned BPF ──" && sudo ls -la /sys/fs/bpf/causaltrace/ 2>/dev/null || echo "  (not pinned)"
	@echo "── calibration ──" && ls -la calibration/ 2>/dev/null || echo "  (empty)"
