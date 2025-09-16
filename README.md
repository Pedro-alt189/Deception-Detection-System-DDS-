# README.md (English)  

[Русская версия (Russian)](./README_ru.md)

---

# Go Honeypot

**A lightweight, pragmatic honeypot written in Go for collecting telemetry from network scanners and simple automated attacks.**

This repository contains a single-file honeypot implementation designed for fast deployment on a workstation or VM. It combines passive packet capture with basic TCP/UDP listeners, simple service emulation (banners), and heuristic-based detection. The honeypot never executes incoming payloads — it analyzes, hashes, and stores metadata only.

---

## Advantages

- **Low friction deployment**: single binary, minimal dependencies, easy to build and run.
- **Hybrid telemetry**: active listeners (TCP/UDP) + passive pcap capture on a network interface — gives broader visibility into attacker behaviour.
- **Focused on data collection**: hashes and metadata stored, with optional Elasticsearch bulk ingestion for later analysis.
- **Safety-first design**: no execution of payloads, truncation of large payloads, and signature-based filtering to avoid accidental exploitation.
- **Respectful coexistence**: attempts to bind configured ports but will not hijack ports where real services are already running.
- **Simple in-memory defenses**: quick blocklist and best-effort `iptables` insertion to reduce noise and repeated probes.
- **Runtime admin console**: simple stdin-based commands for status, graceful shutdown and ad-hoc logging.

---

## Features

- Listening on configurable TCP and UDP ports.
- Passive pcap capture with gopacket when an interface is specified.
- Heuristic-based scan detection:
  - Sliding time window analysis
  - Distinct port threshold
  - SYN-only rate detection
  - Null-payload probe detection
- Signature checks for common RCE/payload patterns and simple binary heuristics (NOP-sled, high non-ASCII ratio).
- In-memory blocklist with configurable TTL and optional firewall insertion.
- Elasticsearch bulk logging with fallback to stdout/file.
- Sturdy, minimal runtime administration via stdin.

---

## Limitations and trade-offs

- **Not a full IDS/IPS**: This project is designed for telemetry and deception, not for replacing production-grade IDS solutions.
- **Heuristic blind spots**: Advanced scanners and evasion techniques (slow scans, randomization, obfuscation) will likely bypass simple heuristics.
- **Resource considerations**: Each incoming connection or captured packet may spawn a goroutine. Under extreme load, this can exhaust system resources.
- **Blocklist persistence**: The default blocklist is in-memory and expires (default TTL 10 minutes). For longer-term blocking, integrate with external firewall/blacklist.
- **Platform differences**: `iptables` commands are Linux-specific; Windows users must rely on the in-memory blocklist and pcap behavior.

---

## Quick Start

### Build

```bash
go build -o honeypot main.go
```

### Example `config.json`
Edit the interface , cause on Windows it's Ethernet, on Linux it's eth0
```json
{
  "interface": "",
  "ports": [22, 80, 443, 12345],
  "log_file": "honeypot.log",
  "snaplen": 65535,
  "promisc": true,
  "timeout_ms": 500,
  "elastic_url": "http://127.0.0.1:9200",
  "elastic_index": "honeypot",
  "max_payload": 4096,
  "scan_window_s": 30,
  "scan_port_thresh": 10
}
```

### Run

```bash
./honeypot -config config.json
```

While running, the process accepts simple stdin commands:
- `status` — emits a runtime status event to logs
- `q` / `quit` / `exit` — graceful shutdown
- any other line is logged as `admin_cmd` for traceability

---

## Usage notes and recommendations

- Run the binary with appropriate privileges if you expect to bind to low ports or insert firewall rules.
- If using pcap on Linux, ensure the running user has permission to capture packets (CAP_NET_RAW) or run as root.
- Tune `scan_window_s` and `scan_port_thresh` to match your environment; default values are conservative for small-scale testing.
- Configure `elastic_url` to enable bulk logging; otherwise logs fall back to file/stdout.

---

## Extension ideas (non-exhaustive)

- **Active deception module**: after detecting a scanner, serve progressively more detailed fake data to entice the scanner to reveal tools/behaviour.
- **Persistent blocklist**: integrate with local firewall or external blocklist service for long-term blocking.
- **Sandboxed payload analysis**: capture suspicious payloads and forward them to an isolated sandbox for deeper inspection (requires strict containment).
- **Rate limiting and worker pool**: add bounded worker pools for connection handling to prevent resource exhaustion.
- **Protocol emulation plugins**: simple emulators for HTTP, FTP, SSH that provide richer telemetry.

---

## Security considerations

- Never run this honeypot on a host with sensitive services unless you fully isolate it (separate VM, strict firewall rules).
- Do not forward captured payload contents to untrusted systems; store only metadata and hashes when possible.
- Be mindful of legal and ethical boundaries when interacting with third-party scanners and hosts.

---

## License

MIT License 

---

