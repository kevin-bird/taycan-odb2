#!/usr/bin/env python3
"""
Taycan Investigation Runner

Orchestrates a sequence of DID sweeps across multiple ECUs to discover
new data. Runs sweeps in priority order, saves each to its own JSON
file, and shows overall progress and time estimates.

Typical throughput: ~80 DIDs/second with 0.3s timeout.

Usage:
    python run_investigation.py                  # run full investigation
    python run_investigation.py --priority 1     # priority 1 only
    python run_investigation.py --list           # just list the plan
    python run_investigation.py --skip-existing  # skip already-done sweeps
"""

import os
import sys
import time
import subprocess
import json
import click

# ANSI colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
RED = "\033[31m"
MAGENTA = "\033[35m"

# Estimated rate: ~80 DIDs/sec (based on earlier sweeps)
DIDS_PER_SEC = 80

# Output directory for research scans
RESEARCH_DIR = os.path.join(os.path.dirname(__file__), "research_scans")


# ─── Investigation Plan ──────────────────────────────────────────────────

INVESTIGATION_PLAN = [
    # (priority, ecu_addr, ecu_name, start_did, end_did, notes)
    (1, "0x407B", "Battery (BECM)", "0x2000", "0x4FFF",
     "Finish BECM — unexplored upper range"),
    (1, "0x407C", "Front Inverter", "0x0100", "0x1FFF",
     "Motor RPM, torque, phase current, stator temp"),
    (1, "0x40B8", "Rear Inverter", "0x0100", "0x1FFF",
     "Motor RPM, torque, phase current, stator temp"),

    (2, "0x4044", "On-Board Charger (OBC)", "0x0100", "0x1FFF",
     "Grid voltage, input current, charge state"),
    (2, "0x40B7", "DC-DC Converter", "0x0100", "0x1FFF",
     "12V bus voltage, input/output current, efficiency"),
    (2, "0x40C7", "HV Booster", "0x0100", "0x1FFF",
     "DC fast charge boost telemetry"),

    (3, "0x4042", "Thermal Management", "0x0100", "0x1FFF",
     "Coolant temps, pump speeds, valve positions"),
    (3, "0x4013", "Brakes (ESP)", "0x0100", "0x1FFF",
     "Wheel speeds, brake pressure, yaw rate"),
    (3, "0x4014", "Instrument Cluster", "0x0100", "0x1FFF",
     "Odometer, trip, ambient temp, range"),

    (4, "0x4076", "Powertrain (VCU)", "0x0100", "0x1FFF",
     "Drive mode, torque request, efficiency"),
    (4, "0x4080", "Air Suspension", "0x0100", "0x1FFF",
     "Ride height, pressure, level sensors"),
    (4, "0x4012", "Power Steering (EPS)", "0x0100", "0x1FFF",
     "Steering angle, assist torque"),
]


def estimate_time(start_hex: str, end_hex: str) -> int:
    """Return estimated seconds for a sweep."""
    count = int(end_hex, 16) - int(start_hex, 16) + 1
    return max(1, int(count / DIDS_PER_SEC))


def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    mins = seconds // 60
    secs = seconds % 60
    return f"{mins}m{secs:02d}s"


def sweep_filename(ecu: str, start: str, end: str) -> str:
    """Filename for a sweep result."""
    return f"{ecu}_{start}_{end}.json"


def already_done(ecu: str, start: str, end: str) -> bool:
    """Check if this sweep already has a result file."""
    path = os.path.join(RESEARCH_DIR, sweep_filename(ecu, start, end))
    return os.path.exists(path)


def print_plan(plan, show_status: bool = False):
    """Pretty-print the investigation plan."""
    total_dids = 0
    total_time = 0

    print(f"\n{BOLD}{CYAN}Taycan Investigation Plan{RESET}\n")
    print(f"{BOLD}{'Pri':<4}{'ECU':<10}{'Name':<25}{'Range':<18}"
          f"{'DIDs':<8}{'ETA':<10}{'Notes':<40}{RESET}")
    print(f"{DIM}{'-' * 115}{RESET}")

    current_pri = None
    for priority, ecu, name, start, end, notes in plan:
        if priority != current_pri:
            current_pri = priority
            print()

        count = int(end, 16) - int(start, 16) + 1
        eta = estimate_time(start, end)
        total_dids += count
        total_time += eta

        status = ""
        if show_status:
            if already_done(ecu, start, end):
                status = f" {GREEN}✓{RESET}"
            else:
                status = f" {DIM}·{RESET}"

        print(f"  {priority}  {ecu:<8}  {name:<23}  "
              f"{start}→{end:<10}  "
              f"{count:<6}  "
              f"{format_duration(eta):<8}  "
              f"{DIM}{notes}{RESET}{status}")

    print(f"{DIM}{'-' * 115}{RESET}")
    print(f"  {BOLD}Total:  {total_dids:,} DIDs  ≈ {format_duration(total_time)}"
          f"{RESET}  (estimate at ~{DIDS_PER_SEC} DIDs/sec)\n")


def run_sweep(ecu, name, start, end) -> tuple[bool, int, int]:
    """
    Run a single sweep via taycan_sweep.py subprocess.
    Returns (success, hit_count, duration_s).
    """
    os.makedirs(RESEARCH_DIR, exist_ok=True)
    output_path = os.path.join(RESEARCH_DIR, sweep_filename(ecu, start, end))

    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), "taycan_sweep.py"),
        "--ecu", ecu,
        "--start", start,
        "--end", end,
        "--extended",
        "--quiet",
        "--output", output_path,
    ]

    print(f"\n{BOLD}{CYAN}▶ {name} ({ecu}){RESET}")
    print(f"  {DIM}Range: {start} → {end}{RESET}")

    start_time = time.time()
    try:
        result = subprocess.run(cmd, check=False)
        duration = int(time.time() - start_time)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Interrupted by user{RESET}")
        return (False, 0, 0)
    except Exception as e:
        print(f"\n{RED}  Sweep failed: {e}{RESET}")
        return (False, 0, 0)

    # Read result count from JSON
    hit_count = 0
    if os.path.exists(output_path):
        try:
            with open(output_path) as f:
                data = json.load(f)
                hit_count = data.get("hit_count", 0)
        except Exception:
            pass

    if result.returncode == 0:
        print(f"  {GREEN}✓ Done{RESET}  "
              f"{hit_count} hits in {format_duration(duration)}")
        return (True, hit_count, duration)
    else:
        print(f"  {RED}✗ Failed{RESET}")
        return (False, hit_count, duration)


# ─── CLI ────────────────────────────────────────────────────────────────

@click.command()
@click.option("--priority", "-p", type=int, default=None,
              help="Run only this priority level (1-4)")
@click.option("--list", "-l", "list_only", is_flag=True,
              help="List the plan without running")
@click.option("--skip-existing", is_flag=True,
              help="Skip sweeps that already have result files")
@click.option("--yes", "-y", is_flag=True,
              help="Skip confirmation prompt")
def main(priority, list_only, skip_existing, yes):
    """Run the Taycan investigation plan."""

    # Filter plan by priority
    plan = INVESTIGATION_PLAN
    if priority is not None:
        plan = [p for p in plan if p[0] == priority]
        if not plan:
            print(f"{RED}No items at priority {priority}{RESET}")
            sys.exit(1)

    print_plan(plan, show_status=True)

    if list_only:
        return

    # Filter already-done if requested
    if skip_existing:
        plan = [p for p in plan
                if not already_done(p[1], p[3], p[4])]
        if not plan:
            print(f"{GREEN}All sweeps already done.{RESET}")
            return
        print(f"{DIM}Running {len(plan)} pending sweeps...{RESET}\n")

    # Confirm
    if not yes:
        total_time = sum(estimate_time(p[3], p[4]) for p in plan)
        print(f"{YELLOW}About to run {len(plan)} sweeps. "
              f"Estimated time: {format_duration(total_time)}.{RESET}")
        answer = input("Continue? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return

    # Run sweeps
    overall_start = time.time()
    total_hits = 0
    successful = 0
    failed = 0

    for priority_level, ecu, name, start, end, notes in plan:
        success, hits, duration = run_sweep(ecu, name, start, end)
        if success:
            successful += 1
            total_hits += hits
        else:
            failed += 1
            # If we failed, prompt to continue
            if not yes:
                answer = input(f"\n{YELLOW}Continue with remaining sweeps? [y/N] {RESET}").strip().lower()
                if answer != "y":
                    break

    overall_duration = int(time.time() - overall_start)

    # Summary
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}Investigation Summary{RESET}")
    print(f"  Duration:    {format_duration(overall_duration)}")
    print(f"  Successful:  {GREEN}{successful}{RESET}")
    print(f"  Failed:      {RED if failed else DIM}{failed}{RESET}")
    print(f"  Total hits:  {CYAN}{total_hits}{RESET}")
    print(f"\n  Results in {DIM}{RESEARCH_DIR}{RESET}\n")


if __name__ == "__main__":
    main()
