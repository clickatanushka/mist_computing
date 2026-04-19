# Multi-Attack Adaptive IDS — MIST Computing Simulation

A hierarchical Intrusion Detection System (IDS) simulated in **OMNeT++**, implementing adaptive multi-layer attack detection across an IoT → Edge → MIST → Fog → Cloud architecture.

## What This Project Does

This simulation models a real-world IoT network where a **Central Controller** monitors traffic, detects attack patterns, switches the global threat mode, and instructs all layers to tighten their detection thresholds accordingly.

Three attack types are simulated simultaneously:

| Attack | Node | Starts | Signature |
|--------|------|--------|-----------|
| DDoS (flooding) | `iot[0]` | t = 5s | High packet rate (10x normal) |
| SQL Injection | `iot[1]` | t = 15s | Oversized payload (1200 bytes) |
| Man-in-the-Middle | `iot[2]` | t = 25s | Artificially delayed packets (500ms fake age) |

Each layer independently inspects every packet and drops malicious traffic based on the active threat mode.

## Architecture

```
IoT[0..4]
    ↓  (5ms delay)
Edge[0..2]  ←──── Central Controller (global mode switching)
    ↓  (50ms)            ↑
MIST[0..1]  ────── EdgeReports every 1s
    ↓  (100ms)
Fog
    ↓  (200ms)
Cloud
```

**Central Controller** receives traffic reports from Edge nodes every second, detects the dominant attack signature, and broadcasts the new `ThreatMode` to all layers simultaneously.

## Detection Logic

Each layer runs three checks on every packet regardless of current mode:

- **Rate check** → detects DDoS (packet flood)
- **Payload check** → detects SQLi (oversized packets)
- **Latency check** → detects MitM (replayed/delayed packets)

Mode changes the **thresholds**, not which checks run. This ensures all three attacks are caught even when they overlap.

## Project Structure

```
mist_4_study/
├── simulation.cc       # All node logic (IoT, Edge, MIST, Fog, Cloud, Controller)
├── simulation.ned      # Network topology and connections
├── omnetpp.ini         # Simulation configs and run parameters
├── ids_profiles.json   # Trained detection thresholds (from Python trainer)
└── train_ids_classifier.py  # ML trainer using CIC-IDS2017 dataset
```

## Requirements

- OMNeT++ 6.x ([download](https://omnetpp.org/download/))
- Python 3.8+ (for the ML trainer only)
- Python packages: `pip install pandas scikit-learn joblib numpy`

## How to Run

### Step 1 — Generate detection profiles (optional, fallback profiles included)

```bash
cd path/to/project
python train_ids_classifier.py
```

This reads the CIC-IDS2017 dataset and writes `ids_profiles.json`. If you skip this, hardcoded fallback thresholds are used automatically.

### Step 2 — Open in OMNeT++ IDE

```bash
cd /path/to/omnetpp-6.x
source setenv
omnetpp
```

Import the project: **File → Open Projects from File System** → select project folder.

### Step 3 — Build

Right-click project → **Build Project**

### Step 4 — Run

Right-click `omnetpp.ini` → **Run As → OMNeT++ Simulation**

Select a config from the dropdown:

| Config | What it tests | Duration |
|--------|--------------|----------|
| `DDoS-Only` | Flood attack detection | 15s |
| `SQLi-Only` | Payload attack detection | 20s |
| `MitM-Only` | Latency attack detection | 25s |
| `Mixed-Attack` | All 3 attacks simultaneously | 30s |

Or run from terminal:

```bash
./mist_4_study -u Cmdenv -n . -c Mixed-Attack omnetpp.ini
```

## What to Observe in the Logs

```
t=5:   ATTACKER[DDoS] flood — Edge/MIST/Fog/Cloud drop rate packets
t=6:   ★★★ GLOBAL MODE SWITCH: NORMAL → DDOS
t=15:  ATTACKER[SQLi] large-payload — Edge drops payload=1200 > 200
t=16:  ★★★ GLOBAL MODE SWITCH: DDOS → SQLI
t=25:  ATTACKER[MitM] replay — Edge drops latency=0.5 > 0.1
t=26:  ★★★ GLOBAL MODE SWITCH: SQLI → MITM
```

## Result Metrics

At the end of simulation, each layer records:

- Total / dropped / accepted packets
- DDoS drops, SQLi drops, MitM drops
- Drop rate and detection rate
- Average latency and jitter
- Throughput (total and accepted)

Results are saved to `results/ids_results.sca` and viewable in OMNeT++ Analysis tool.

## Dataset (for ML trainer)

Download **CIC-IDS2017** from the University of New Brunswick:
[https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html)

Extract into:
```
project/
└── CIC-IDS2017-CSV/
    └── MachineLearningCVE/
        ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
        ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
        └── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
```

## Tech Stack

- **OMNeT++ 6.x** — discrete event simulation
- **C++** — node and IDS logic
- **Python + scikit-learn** — offline ML classifier training
- **CIC-IDS2017** — real-world network intrusion dataset

## Author

Anushka Joshi — [GitHub](https://github.com/clickatanushka)
