#!/usr/bin/env python3
"""
PRISM Blue Team — Log Parser
Consumes raw /var/log/audit/audit.log lines and normalizes them into JSON.
"""

import re
import json
import os
import sys

# Standard paths based on project structure
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../logs/parsed")
os.makedirs(LOG_DIR, exist_ok=True)

def parse_audit_line(line):
    """
    Parses a single audit line into a dictionary.
    Extracts timestamp, audit_id, and dynamically extracts all key=value pairs.
    """
    # Extract timestamp and audit ID: node=... type=... msg=audit(timestamp:id):
    event_match = re.search(r'audit\((\d+\.\d+):(\d+)\):', line)
    if not event_match:
        return None

    timestamp = event_match.group(1)
    audit_id = event_match.group(2)
    
    # Extract event type
    type_match = re.search(r'type=(\w+)', line)
    event_type = type_match.group(1) if type_match else "UNKNOWN"

    # Parse all key=value pairs
    fields = {}
    
    # Handle quoted strings and normal values
    for pair in re.findall(r'(\w+)=(?:"([^"]*)"|([^"\s]+))', line):
        key = pair[0]
        # pair[1] is the matched quoted value, pair[2] is the unquoted value
        val = pair[1] if pair[1] else pair[2]
        fields[key] = val

    # Resolve encoded arguments (like a0, a1) if they exist (simplistic hex decoding for paths)
    for k, v in fields.items():
        if k in ('name', 'exe', 'comm') and v.isalnum() and len(v) > 2 and not v.isdigit():
            try:
                # If it's pure hex, it might be an encoded string in audit logs
                decoded = bytes.fromhex(v).decode('utf-8')
                fields[k] = decoded
            except ValueError:
                pass

    return {
        'timestamp': timestamp,
        'audit_id': audit_id,
        'event_type': event_type,
        'data': fields,
        'raw': line.strip()
    }

def process_log_file(filepath):
    """Parses a full audit log file and groups events by their audit_id."""
    parsed_events = {}
    
    if not os.path.exists(filepath):
        print(f"[Parser] Error: Log file {filepath} not found.", file=sys.stderr)
        return {}

    with open(filepath, 'r') as f:
        for line in f:
            parsed = parse_audit_line(line)
            if parsed:
                aid = parsed['audit_id']
                if aid not in parsed_events:
                    parsed_events[aid] = []
                parsed_events[aid].append(parsed)
                
    return parsed_events

def normalize_transaction(events):
    """Flattens a list of related audit events (same ID) into a single transaction object."""
    transaction = {
        'timestamp': events[0]['timestamp'],
        'audit_id': events[0]['audit_id'],
        'event_types': [],
        'keys': [],
        'exe': None,
        'comm': None,
        'syscall': None,
        'name': None,
        'paths': []
    }
    
    for event in events:
        transaction['event_types'].append(event['event_type'])
        data = event['data']
        
        if 'key' in data and data['key'] not in transaction['keys']:
            transaction['keys'].append(data['key'].strip('"'))
            
        if 'exe' in data:
            transaction['exe'] = data['exe'].strip('"')
            
        if 'comm' in data:
            transaction['comm'] = data['comm'].strip('"')
            
        if 'syscall' in data:
            transaction['syscall'] = data['syscall']
            
        if 'name' in data:
            val = data['name'].strip('"')
            transaction['name'] = val
            if val not in transaction['paths']:
                transaction['paths'].append(val)
                
    return transaction

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 log_parser.py <path_to_audit.log>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    
    print(f"[Parser] Ingesting {input_file}...")
    grouped_events = process_log_file(input_file)
    
    normalized_transactions = []
    for aid, events in grouped_events.items():
        # Only care about PRISM tagged events
        is_prism_event = any('key' in e['data'] and 'prism' in e['data']['key'] for e in events)
        if is_prism_event:
            normalized_transactions.append(normalize_transaction(events))
            
    output_file = os.path.join(LOG_DIR, "parsed_telemetry.json")
    with open(output_file, 'w') as f:
        json.dump(normalized_transactions, f, indent=4)
        
    print(f"[Parser] Extracted {len(normalized_transactions)} PRISM transactions.")
    print(f"[Parser] Output written to {output_file}")

if __name__ == "__main__":
    main()
