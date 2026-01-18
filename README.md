# Network Recon

**Network Reconnaissance Agent**

Network Recon is a lightweight network reconnaissance agent that discovers hosts, services, and technologies on target networks. It performs host discovery, port scanning, HTTP probing, and domain enumeration, writing all discoveries to the GraphRAG knowledge graph.

## Overview

Network Recon provides automated network discovery capabilities for security assessments. It operates autonomously, discovering infrastructure and building a comprehensive knowledge graph of the target environment.

### Key Capabilities

- **Host Discovery**: Identify live hosts on target subnets using ICMP ping sweeps, ARP scanning, and TCP SYN probes
- **Port Scanning**: Discover open ports (1-1000 by default) with service version detection
- **Service Detection**: Fingerprint services running on discovered ports via banner grabbing
- **Technology Fingerprinting**: Identify web technologies, frameworks, and server software
- **Domain Enumeration**: Discover subdomains via passive and active enumeration techniques

### Supported Target Types

| Type | Description | Example |
|------|-------------|---------|
| `network` | IP range or CIDR block | `192.168.1.0/24` |
| `subnet` | Subnet specification | `10.0.0.0/16` |
| `domain` | Domain name for enumeration | `example.com` |

## Requirements

### System Dependencies

The following tools must be installed and available in your PATH:

| Tool | Required | Purpose | Installation |
|------|----------|---------|--------------|
| **nmap** | Yes | Host discovery and port scanning | `apt install nmap` / `brew install nmap` |
| **httpx** | Yes | HTTP probing and technology detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **subfinder** | No | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **amass** | No | Comprehensive DNS enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| **masscan** | No | Fast port scanning fallback | `apt install masscan` / `brew install masscan` |

### Gibson Platform

- Gibson v0.20.0 or later
- SDK v0.20.0 or later

### Optional: LLM Provider

For intelligence generation features, configure an LLM provider:
- Anthropic Claude (recommended)
- OpenAI GPT-4

## Architecture

```
+----------------------------------------------------------+
|                    Network Recon                          |
|              Network Reconnaissance Agent                 |
+----------------------------------------------------------+
|                                                           |
|  +---------------------------------------------------+   |
|  |               Configuration                        |   |
|  | - Subnet auto-discovery                           |   |
|  | - Domain targets                                  |   |
|  | - Demo mode support                               |   |
|  +---------------------------------------------------+   |
|                          |                                |
|                          v                                |
|  +---------------------------------------------------+   |
|  |              Reconnaissance Runner                 |   |
|  |  - Phase-based execution                          |   |
|  |  - Tool orchestration                             |   |
|  |  - GraphRAG node creation                         |   |
|  +---------------------------------------------------+   |
|           |              |              |                 |
|           v              v              v                 |
|  +-------------+ +-------------+ +-------------+         |
|  | Host        | | Port        | | HTTP        |         |
|  | Discovery   | | Scanning    | | Probing     |         |
|  +-------------+ +-------------+ +-------------+         |
|                          |                                |
|                          v                                |
|  +---------------------------------------------------+   |
|  |            Intelligence Generator                  |   |
|  | - LLM-powered analysis (optional)                 |   |
|  | - Summary generation                              |   |
|  +---------------------------------------------------+   |
|                          |                                |
|                          v                                |
|  +---------------------------------------------------+   |
|  |                GraphRAG Store                      |   |
|  | - Host nodes                                      |   |
|  | - Port nodes                                      |   |
|  | - Service nodes                                   |   |
|  | - HAS_PORT / RUNS_SERVICE relationships           |   |
|  +---------------------------------------------------+   |
+----------------------------------------------------------+
```

## Quick Start

```bash
# 1. Install the agent
gibson agent install git@github.com:zero-day-ai/network-recon-agent.git

# 2. Create a target
gibson target add my-network --type network --connection '{"address":"192.168.1.0/24"}'

# 3. Run reconnaissance
gibson agent run network-recon --target my-network
```

## Installation

### Using Gibson CLI (Recommended)

```bash
gibson agent install git@github.com:zero-day-ai/network-recon-agent.git
```

### From Source

```bash
git clone git@github.com:zero-day-ai/network-recon-agent.git
cd network-recon
make build
gibson agent build .
```

## Usage

### Via Gibson CLI (Recommended)

```bash
# Run against a configured target
gibson agent run network-recon --target my-network

# Run as part of a mission
gibson mission run -f recon-mission.yaml --target my-network
```

### Creating Targets

```bash
# Network/subnet target
gibson target add home-network --type network --connection '{"address":"192.168.50.0/24"}'

# Domain target
gibson target add example-domain --type domain --connection '{"domain":"example.com"}'
```

### Running as Standalone gRPC Service (Development)

```bash
# Start with default port (50051)
./network-recon

# Specify custom port
./network-recon --port 50053

# Or via environment variable
AGENT_PORT=50053 ./network-recon
```

## Configuration

### LLM Slots

Network Recon uses one optional LLM slot for intelligence generation:

| Slot | Purpose | Min Context | Features |
|------|---------|-------------|----------|
| `primary` | Intelligence generation and analysis | 8K | - |

Configure in `~/.gibson/config.yaml`:

```yaml
agents:
  network-recon:
    slots:
      primary:
        provider: anthropic
        model: claude-sonnet-4-20250514
```

### Task Configuration

```yaml
# Mission task configuration
subnet: "192.168.1.0/24"    # Optional - auto-discovered if not provided
domains:
  - example.com
  - api.example.com
demo_mode: false
verbose: true
generate_intelligence: true
```

## Reconnaissance Phases

### Phase 1: Host Discovery
- ICMP ping sweep
- ARP scanning (local networks)
- TCP SYN probes

### Phase 2: Port Scanning
- Top ports scanning
- Service version detection
- Banner grabbing

### Phase 3: HTTP Probing
- HTTP/HTTPS endpoint discovery
- Technology fingerprinting
- Response analysis

### Phase 4: Domain Enumeration
- DNS record lookup
- Subdomain discovery
- Certificate transparency

## GraphRAG Integration

Network Recon writes discoveries to the GraphRAG knowledge graph:

### Node Types
- `host` - Discovered hosts with IP addresses
- `port` - Open ports with service information
- `service` - Identified services and versions

### Relationships
- `HAS_PORT` - Host to port relationship
- `RUNS_SERVICE` - Port to service relationship

## Project Structure

```
network-recon/
├── main.go              # Entry point with SDK builder pattern
├── config.go            # Configuration parsing
├── execute.go           # Execution logic
├── component.yaml       # Gibson component manifest
├── Makefile             # Build automation
└── internal/
    ├── network/         # Network discovery utilities
    ├── recon/           # Reconnaissance runner and phases
    ├── resolve/         # DNS resolution
    ├── scan/            # Port scanning
    └── intelligence/    # LLM-powered intelligence generation
```

## Development

```bash
# Build
make build

# Run tests
make test

# Run all checks (fmt, vet, lint, test)
make check

# See all available targets
make help

# Run via Gibson (PREFERRED)
gibson agent run network-recon --target <target-id>

# Build and run locally (development only)
make run
```

## Output Format

Network Recon provides both human-readable and machine-parseable output:

```
=== Network Reconnaissance Report ===
Subnet: 192.168.1.0/24
Duration: 2m30s

=== Summary ===
Hosts Discovered: 15
Ports Discovered: 47
HTTP Endpoints: 8
Phases Executed: 4

=== Phase: host_discovery ===
Tools Run: [ping_sweep arp_scan]
Nodes Created: 15
Relationships Created: 0
Duration: 45s
Errors: 0

--- JSON Output ---
{
  "subnet": "192.168.1.0/24",
  "total_hosts": 15,
  "total_ports": 47,
  "total_endpoints": 8
}
```

## Security Considerations

- **Authorization Required**: Only scan networks you're authorized to test
- **Rate Limiting**: Scans are rate-limited to avoid network disruption
- **Stealth Options**: Configure scanning intensity for sensitive environments
- **Audit Logging**: All scan activities are logged

## License

Proprietary - Gibson Security Team

## Support

For issues or questions, contact the Gibson Security Team.
