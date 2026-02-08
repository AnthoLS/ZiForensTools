#!/usr/bin/env python3
import json
from dateutil import parser
from pathlib import PureWindowsPath

INPUT_FILES = [
    "data/usn_raw.json",
    "data/artefacts_raw.json"
]

OUTPUT_FILE = "data/events_normalized.json"
normalized = []

for file in INPUT_FILES:
    with open(file, "r", encoding="utf-8") as f:
        events = json.load(f)

    for e in events:
        ts = e.get("timestamp")
        normalized.append({
            "timestamp": parser.parse(ts).isoformat() if ts else None,
            "action": e.get("action") or e.get("reason"),
            "path": str(PureWindowsPath(e.get("path"))) if e.get("path") else e.get("name"),
            "source": e.get("source"),
            "user": e.get("user")
        })

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(normalized, f, indent=2)

print(f"[+] Events normalized: {len(normalized)} records")
