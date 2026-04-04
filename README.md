# hoo

Real-time network traffic monitor for the terminal. Think htop meets tcpdump.

## Features

- **Network map visualizer** — radial map with your machine at center, remote hosts orbiting by protocol, anomalous connections highlighted in red
- **Live TUI dashboard** — bandwidth sparkline, connection table, protocol breakdown, top talkers
- **Packet capture** — libpcap and AF_PACKET backends with BPF kernel-level filters
- **Connection tracking** — 5-tuple tracking with TCP state machine and rolling bandwidth stats
- **Reverse DNS** — async hostname resolution with LRU cache
- **Anomaly detection** — port scan, DNS spike, connection flood, unexpected protocol alerts
- **Security visibility** — see exactly what your dev environment or server is talking to, flag unexpected connections
- **CSV export** — connections, stats, and flows schemas with append mode
- **Report generation** — Markdown and JSON session reports
- **Headless mode** — for scripts, cron jobs, and CI pipelines

## Installation

### From source

```bash
go install github.com/justinmaks/hoo/cmd/hoo@latest
```

### Build from source

```bash
git clone https://github.com/justinmaks/hoo.git
cd hoo
make build
```

Requires `libpcap-dev` (Linux) or Xcode command line tools (macOS).

## Privileges

hoo requires elevated privileges for raw packet capture:

**Linux:**
```bash
# Option 1: Run with sudo
sudo hoo

# Option 2: Grant capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip $(which hoo)
```

**macOS:**
```bash
# Run with sudo
sudo hoo
```

## Usage

```bash
# Auto-detect interface and launch dashboard
hoo

# Specify interface
hoo -i eth0

# Apply BPF filter
hoo --filter "tcp port 443"

# Headless mode with CSV export
hoo --headless --duration 5m --export traffic.csv

# Periodic export every 30 seconds
hoo --headless --export stats.csv --export-type stats --interval 30s --append

# Generate a report
hoo --headless --duration 1m --report report.md

# List interfaces
hoo --list-interfaces

# Filter by direction
hoo --direction inbound
```

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `q` | Quit |
| `?` | Toggle help overlay |
| `p` | Pause/resume capture |
| `s` | Cycle sort column |
| `S` | Reverse sort order |
| `/` | Search/filter connections |
| `1` | Focus bandwidth view |
| `2` | Focus connections view |
| `3` | Focus protocols view |
| `4` | Network map visualizer |
| `5` | Open ports (what's talking to you) |
| `6` | Inbound traffic table |
| `7` | Outbound traffic table |
| `e` | Export CSV snapshot |
| `r` | Generate report |
| `↑`/`↓`/`j`/`k` | Scroll connection table |

## Configuration

Optional config file at `~/.config/hoo/config.yaml`:

```yaml
interface: eth0
filter: "tcp"
tick_rate: 2
direction: both

anomaly:
  port_scan_ports: 10
  port_scan_window: 60s
  dns_spike_multiplier: 10
  dns_spike_window: 30s
  conn_flood_count: 50
  conn_flood_window: 10s
  allowed_ports: [80, 443, 53, 22]
```

CLI flags override config file values, which override defaults.

## Export Schemas

### connections (default)
`timestamp, protocol, local_addr, remote_addr, remote_hostname, bytes_in, bytes_out, packets_in, packets_out, state, duration_ms`

### stats
`timestamp, bytes_in, bytes_out, packets_in, packets_out, active_connections, new_connections, closed_connections`

### flows
`start_time, end_time, protocol, local_addr, remote_addr, remote_hostname, bytes_in, bytes_out, packets_in, packets_out, tcp_flags_seen`

## License

Apache 2.0. See [LICENSE](LICENSE).
