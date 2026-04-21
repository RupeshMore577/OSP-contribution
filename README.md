# OSP-contribution
A space for my open-source practice and contributions as I learn and grow.

## Real-life solution: Network Booster Advisor (Python)
This repository now includes a practical tool that helps people improve slow or unstable internet connections by diagnosing bottlenecks and giving clear actions.

### What problem it solves
When internet feels slow, many users do not know whether the issue is DNS, packet drops, or latency. This script checks all of these and gives a simple action plan.

### File
- `network_booster.py`

### Features
- Benchmarks popular public DNS servers (Cloudflare, Google, Quad9, OpenDNS)
- Tests network stability and latency using repeated TCP connection probes
- Suggests the fastest reliable DNS for your network
- Generates platform-specific commands to update DNS settings (Linux/macOS/Windows)
- Supports both human-readable and JSON output

### Run
```bash
python3 network_booster.py
```

### Example options
```bash
python3 network_booster.py --attempts 5 --timeout 2.5
python3 network_booster.py --domain github.com --json
```

### Why this is useful in real life
- Speeds up website/app loading by identifying better DNS
- Helps spot unstable Wi-Fi conditions before meetings/classes
- Gives non-technical users direct steps to improve network quality quickly
