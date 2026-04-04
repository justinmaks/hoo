# hoo

Real-time network traffic monitor for the terminal. Think `htop` meets `tcpdump`.

Built for engineers and security practitioners who need instant visibility into what their machine, dev environment, or server is talking to — without standing up infrastructure.

## Features

- **Network map** — radial visualizer with your machine at center, remote hosts color-coded by protocol, anomalous connections flagged in red
- **7 live views** — bandwidth sparkline, connection table, protocol breakdown, top talkers, open ports, inbound table, outbound table
- **Security visibility** — see unexpected connections, port scans, DNS spikes, and connection floods as they happen
- **Packet capture** — libpcap (all platforms) and AF_PACKET (Linux, higher performance) backends with BPF kernel filters
- **Reverse DNS** — async hostname resolution with in-memory LRU cache, hostnames shown alongside IPs everywhere
- **Anomaly detection** — port scan, DNS volume spike, connection flood, unexpected protocol alerts with configurable thresholds
- **CSV export** — three schemas (connections, time-series stats, per-flow) with append mode for continuous logging
- **Report generation** — Markdown and JSON session reports with protocol breakdown, top hosts, and flagged anomalies
- **Headless mode** — run without TUI for scripts, cron jobs, and CI pipelines
- **Zero config** — auto-detects interface, works out of the box with `sudo hoo`

## Installation

### Build from source

```bash
git clone https://github.com/justinmaks/hoo.git
cd hoo
make build
# binary at bin/hoo
```

**Dependencies:** `libpcap-dev` on Linux, Xcode command line tools on macOS.

```bash
# Linux
sudo apt install libpcap-dev   # Debian/Ubuntu
sudo dnf install libpcap-devel # Fedora/RHEL

# macOS (libpcap is included with Xcode tools)
xcode-select --install
```

### Go install

```bash
go install github.com/justinmaks/hoo/cmd/hoo@latest
```

## Privileges

Raw packet capture requires elevated privileges on all platforms.

**Linux:**
```bash
# Option 1: sudo (simplest)
sudo hoo

# Option 2: grant capabilities once (recommended for regular use)
sudo setcap cap_net_raw,cap_net_admin=eip $(which hoo)
hoo  # no sudo needed after this
```

**macOS:**
```bash
sudo hoo
```

## Usage

```bash
# Launch dashboard on auto-detected interface
sudo hoo

# Specify interface
sudo hoo -i eth0

# Apply a BPF filter (tcpdump syntax)
sudo hoo --filter "tcp port 443"
sudo hoo --filter "not port 53"

# Use AF_PACKET backend for higher performance (Linux only)
sudo hoo --backend afpacket

# Only show inbound or outbound traffic
sudo hoo --direction inbound
sudo hoo --direction outbound

# List available interfaces
hoo --list-interfaces

# Headless: capture for 5 minutes and export CSV
sudo hoo --headless --duration 5m --export connections.csv

# Headless: append stats every 30 seconds indefinitely
sudo hoo --headless --export stats.csv --export-type stats --interval 30s --append

# Headless: capture and generate a report
sudo hoo --headless --duration 10m --report report.md --report-format json
```

## Views

Press the number key to focus a view. Press it again to return to the default layout.

| Key | View | Description |
|-----|------|-------------|
| `1` | Bandwidth | Scrolling TX/RX sparkline with session totals |
| `2` | Connections | Sortable table of all active connections |
| `3` | Protocols | Horizontal bar chart of traffic by protocol |
| `4` | Network map | Radial map — your machine at center, remote hosts orbiting by protocol |
| `5` | Open ports | Your local ports receiving connections, grouped with peer tree |
| `6` | Inbound | All traffic arriving at your machine |
| `7` | Outbound | All traffic your machine is sending out |

The **network map** (view 4) is the default. Anomalous connections appear with `⚠` borders and red highlighting. Line style indicates bandwidth: `─` for normal, `═` for high-volume, `!` for flagged.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `1`–`7` | Switch view (press again to return to default layout) |
| `↑` / `↓` / `j` / `k` | Scroll table |
| `s` | Cycle sort column |
| `S` | Reverse sort order |
| `/` | Search/filter connections by IP, hostname, or port |
| `Escape` | Clear search / close help |
| `p` | Pause/resume capture |
| `e` | Export CSV snapshot (timestamped filename) |
| `r` | Generate report (timestamped filename) |
| `?` | Toggle help overlay |
| `q` | Quit |

Export and report confirmations appear in the status bar for 5 seconds.

## Anomaly Detection

hoo watches for these patterns and surfaces alerts in the status bar and reports:

| Alert | Default Threshold | Description |
|-------|-------------------|-------------|
| Port scan | 10 ports in 60s | Single source sending SYN-only packets to many distinct ports |
| DNS spike | 10× baseline over 30s | Sudden surge in DNS query volume vs rolling 5-min average |
| Connection flood | 50 new conns in 10s | Single source opening many connections rapidly |
| Unexpected protocol | Not in allowlist | Traffic on a port not in the configured allowlist |

Alerts are advisory only — hoo never blocks traffic.

## Configuration

Optional config file at `~/.config/hoo/config.yaml` (XDG-compliant). CLI flags always override config file values.

```yaml
interface: eth0
filter: "not port 53"
backend: libpcap        # or "afpacket" (Linux only)
direction: both         # inbound | outbound | both
tick_rate: 1            # TUI refresh rate in Hz (1-10)

anomaly:
  port_scan_ports: 10
  port_scan_window: 60s
  dns_spike_multiplier: 10
  dns_spike_window: 30s
  conn_flood_count: 50
  conn_flood_window: 10s
  allowed_ports: [80, 443, 53, 22]
```

## All Flags

```
-i, --interface       Network interface (auto-detect if omitted)
    --filter          BPF filter expression (tcpdump syntax)
    --backend         Capture backend: libpcap (default) or afpacket (Linux)
    --direction       Traffic direction: inbound | outbound | both (default)
    --headless        Run without TUI
    --duration        Capture time limit (e.g. 5m, 1h); 0 = unlimited
    --list-interfaces List available interfaces and exit

    --export          Write CSV to this path
    --export-type     CSV schema: connections (default) | stats | flows
    --append          Append to existing CSV instead of overwriting
    --overwrite       Overwrite existing export/report files
    --interval        Periodic export interval for headless mode (e.g. 30s)

    --report          Write report to this path
    --report-format   Report format: markdown (default) | json

    --tick-rate       TUI refresh rate in Hz, 1–10 (default 1)
    --version         Print version and exit
```

## Export Schemas

All CSV files include a schema version comment as the first line and a header row.

### connections (default)
`timestamp, protocol, local_addr, remote_addr, remote_hostname, bytes_in, bytes_out, packets_in, packets_out, state, duration_ms`

### stats — 1-second bandwidth buckets
`timestamp, bytes_in, bytes_out, packets_in, packets_out, active_connections, new_connections, closed_connections`

### flows — per-flow records
`start_time, end_time, protocol, local_addr, remote_addr, remote_hostname, bytes_in, bytes_out, packets_in, packets_out, tcp_flags_seen`

## Reports

Reports include: session metadata, total bytes in/out, protocol distribution table, top remote hosts, and an anomalies section (if any were detected). Generated on demand with `r` in the TUI, or automatically in headless mode via `--report`.

```bash
sudo hoo --headless --duration 5m --report report.md
sudo hoo --headless --duration 5m --report report.json --report-format json
```

## Security Notes

- **Read-only** — hoo captures packets only, never injects or modifies traffic
- **No outbound connections** — all DNS resolution is local reverse lookups only
- **No telemetry** — nothing leaves your machine
- **BPF filters** — compiled and validated by libpcap before application; the compiled program runs in-kernel with OS-enforced safety guarantees
- **Privilege surface** — only requires `CAP_NET_RAW` and `CAP_NET_ADMIN` on Linux; use `setcap` to avoid running as root

## License

Apache 2.0. See [LICENSE](LICENSE).
