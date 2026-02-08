#!/usr/bin/env python3
import json
import pandas as pd

INPUT_FILE = "data/events_normalized.json"
OUTPUT_FILE = "data/timeline.csv"

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    events = json.load(f)

df = pd.DataFrame(events)
df = df.dropna(subset=["timestamp"])
df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
df = df.sort_values("timestamp")

df.to_csv(OUTPUT_FILE, index=False)

print(f"[+] Timeline created: {OUTPUT_FILE}")
