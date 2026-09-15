# Network Traffic Analyser (NTA)

A Python project I'm building to learn Python properly while applying what I'm studying on my Cybersecurity and Forensics degree. It captures live network traffic and is gradually being built out to flag suspicious-looking patterns, rather than just printing packets to a terminal.

## Why this project

I wanted a project that would actually push my Python skills instead of just following tutorials, so I picked something with real-world relevance to what I'm studying. Starting point was a basic packet sniffer; from there I'm building it out step by step — adding storage, then working towards basic detection logic like spotting port scans or unusual repeated connections. It's as much about learning to plan, build, and debug a real tool as it is about the security side.

## Features

- **Live packet capture** using Scapy, with TCP/UDP/ALL protocol filtering
- **Graceful capture control** — signal handling and a configurable timeout stop mechanism
- **Persistent storage** — captured traffic is written to a local SQLite database for later querying and analysis
- **Detection logic** *(in progress)* — starting with simple patterns like port scans and repeated/unusual connections
- **Clearer output** *(planned)* — summarising findings in a more readable way instead of raw logs

## Current status

This project is under active development. Progress so far:

- [x] **Phase 1 — Packet capture:** working Scapy-based sniffer with protocol filtering, signal handling, and timeout stop
- [x] **Phase 2 — Storage:** SQLite integration; database and schema confirmed working
- [ ] **Phase 3 — Detection:** parsing captured data and building simple pattern/anomaly detection
- [ ] **Phase 4 — Analysis:** visualising traffic data using pandas and matplotlib/plotly
- [ ] **Phase 5 — Interface:** putting it together with a basic web UI (Flask or Streamlit); stretch goal of trying some basic ML-based detection with scikit-learn

## Tech stack

- **Language:** Python 3.14
- **Packet capture:** Scapy, PyShark
- **Storage:** SQLite
- **Planned:** pandas, matplotlib/plotly, Flask or Streamlit, scikit-learn
- **Tools used in development:** Wireshark, Npcap

## Getting started

*(Setup instructions to be added as the tool nears a runnable state.)*

## Roadmap

See the phase checklist above. Longer-term, the goal is a working tool with a simple web interface for reviewing captured traffic and anything it flags — built up gradually as I learn more.
