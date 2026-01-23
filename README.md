# Network Recon Agent

Autonomous network reconnaissance agent for the Gibson framework. Discovers hosts, ports, services, and subdomains using a three-phase approach.

## Overview

The network-recon agent performs comprehensive network reconnaissance through three configurable phases:

1. **Discover** - Host discovery via nmap ping scan
2. **Probe** - Port scanning against live hosts
3. **Domain** - Subdomain enumeration

## Installation

```bash
gibson agent install github.com/zero-day-ai/network-recon
```

## Usage

### Via Gibson CLI

```bash
gibson agent run network-recon \
  --config subnet=192.168.1.0/24 \
  --config max_hosts=50 \
  --goal "Discover all hosts and services"
```

### Via Mission Workflow

```yaml
phases:
  - name: reconnaissance
    agents:
      - name: network-recon
        config:
          subnet: 192.168.1.0/24
          domains:
            - example.com
          skip_phases: []
          generate_intelligence: true
          max_hosts: 25
          scan_timeout: 5m
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `subnet` | string | auto-detect | Target subnet in CIDR notation |
| `domains` | []string | [] | Domain names for reconnaissance |
| `skip_phases` | []string | [] | Phases to skip: "discover", "probe", "domain" |
| `generate_intelligence` | bool | true | Run LLM analysis on results |
| `max_hosts` | int | 25 | Maximum hosts to scan |
| `scan_timeout` | duration | 5m | Timeout for scan operations |
| `demo_mode` | bool | false | Skip network calls for testing |
| `verbose` | bool | false | Enable verbose logging |

## Execution Phases

### Phase 1: Discover

Uses nmap ping scan (-sn) to discover live hosts on the network:

```go
nmapReq := &pb.NmapRequest{
    Target: subnet,
    Flags:  []string{"-sn"},
}
```

**Output**: List of live hosts with IP addresses and hostnames.

### Phase 2: Probe

Performs port scanning against discovered hosts:

```go
nmapReq := &pb.NmapRequest{
    Target: hosts,
    Ports:  "1-65535",
    Flags:  []string{"-sV", "-sC", "-T4"},
}
```

**Output**: Open ports, services, and versions.

### Phase 3: Domain

Enumerates subdomains for specified domains:

- Uses subfinder for passive subdomain enumeration
- Uses amass for active enumeration
- Resolves discovered subdomains to IP addresses

**Output**: Subdomain list with resolved IPs.

## LLM Slots

| Slot | Description | Required | Constraints |
|------|-------------|----------|-------------|
| `primary` | Main reasoning LLM | Yes | min_context: 8000, features: json_mode |

## Tools Used

| Tool | Phase | Purpose |
|------|-------|---------|
| nmap | Discover, Probe | Host/port scanning |
| httpx | Probe | HTTP probing |
| subfinder | Domain | Passive subdomain enum |
| amass | Domain | Active subdomain enum |

## Output

### Discovery Result

```go
type DiscoveryResult struct {
    Hosts     []Host     // Discovered hosts
    Ports     []Port     // Open ports
    Endpoints []Endpoint // Web endpoints
    Domains   []Domain   // Discovered subdomains
    Metadata  Metadata   // Scan metadata
}
```

### GraphRAG Integration

Results are automatically stored in the GraphRAG knowledge graph for cross-mission intelligence.

## Development

### Build

```bash
make build
```

### Test

```bash
make test
make test-race
```

### Run Locally

```bash
./network-recon
# Starts gRPC server on port 50051
```

## Directory Structure

```
network-recon/
├── main.go           # Entry point
├── config.go         # Configuration parsing
├── execute.go        # Execution logic
├── component.yaml    # Component metadata
├── internal/
│   ├── network/      # Network utilities
│   ├── recon/        # Three-phase runner
│   └── intelligence/ # LLM analysis
└── Makefile
```

## Repository

- **GitHub**: https://github.com/zero-day-ai/network-recon
- **Module**: `github.com/zero-day-ai/network-recon`

## Related Agents

- [tech-stack-fingerprinting](../tech-stack-fingerprinting/) - Runs after network-recon to identify technologies
