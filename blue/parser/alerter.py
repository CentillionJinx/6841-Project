#!/usr/bin/env python3
"""
PRISM Blue Team — Alerter
Formats detections into human-readable alerts and Palantir ADS structures.
"""

import json
import sys
import os
import datetime

def generate_alerts(detections_file):
    """Reads raw detections and outputs formatted alerts."""
    if not os.path.exists(detections_file):
        print(f"[Alerter] No detections file found at {detections_file}")
        return

    with open(detections_file, 'r') as f:
        detections = json.load(f)

    if not detections:
        print("[Alerter] No anomalous activity found. Environment is clean.")
        return

    print("\n" + "="*60)
    print("      PRISM SECURITY ALERTS - HIGH PRIORITY")
    print("="*60)
    
    for idx, d in enumerate(detections, 1):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{idx}] ALERT TRIGGERED AT {timestamp}")
        print(f"    -> Rule ID:      {d['rule']}")
        print(f"    -> Severity:     {d['severity']}")
        print(f"    -> Description:  {d['description']}")
        print(f"    -> Audit Trace:  {d['audit_id']}")
        print("-" * 60)
        
    print(f"[Alerter] Generated {len(detections)} total alerts.\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 alerter.py <path_to_detections.json>")
        sys.exit(1)
        
    generate_alerts(sys.argv[1])
