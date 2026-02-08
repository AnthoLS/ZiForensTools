#!/usr/bin/env python3
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path

OUTPUT_FILE = "data/usn_raw.json"
events = []

try:
    # Use Windows fsutil to read USN Journal
    result = subprocess.run(
        ['fsutil', 'usn', 'readjournal', 'C:'],
        capture_output=True,
        text=True,
        shell=True
    )
    
    if result.returncode == 0:
        # Parse fsutil output
        for line in result.stdout.split('\n'):
            if 'Usn' in line or 'FileName' in line or 'Reason' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    key, value = parts[0].strip(), parts[1].strip()
                    events.append({
                        "source": "USN",
                        "timestamp": datetime.now().isoformat(),
                        "key": key,
                        "value": value
                    })
    else:
        print(f"[!] Warning: Could not read USN Journal - {result.stderr}")
        
except Exception as e:
    print(f"[!] Warning: USN Journal extraction failed - {str(e)}")

# Alternative: Extract from Windows.edb (Windows Search Database)
try:
    edb_path = os.path.expanduser(r'~\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat')
    if os.path.exists(edb_path):
        events.append({
            "source": "WebCache",
            "file": edb_path,
            "timestamp": datetime.fromtimestamp(os.path.getmtime(edb_path)).isoformat()
        })
except Exception as e:
    print(f"[!] Warning: WebCache extraction failed - {str(e)}")

# Extract from $Recycle.Bin metadata
try:
    recyclebin_path = os.path.expanduser(r'~\$Recycle.bin')
    if os.path.exists(recyclebin_path):
        for item in Path(recyclebin_path).rglob('$I*'):
            events.append({
                "source": "RecycleBin",
                "file": str(item),
                "timestamp": datetime.fromtimestamp(item.stat().st_mtime).isoformat()
            })
except Exception as e:
    print(f"[!] Warning: Recycle.bin extraction failed - {str(e)}")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(events, f, indent=2)

print(f"[+] File access events extracted: {len(events)} records")
