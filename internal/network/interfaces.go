// Package network provides network discovery capabilities for local subnet and domain detection.
//
// This package enables the debug agent to automatically discover its local network environment
// including subnet CIDR ranges, local IP addresses, default gateways, and domain mappings from
// the system's hosts file. These discoveries are used to configure reconnaissance tools with
// appropriate targets for network scanning and enumeration.
//
// The primary use case is automated local network reconnaissance where the agent needs to
// determine what networks and domains to scan without manual configuration.
package network

import "context"

// NetworkDiscovery defines the interface for discovering local network configuration and domain mappings.
// Implementations should use system network interfaces and hosts file data to determine reconnaissance targets.
type NetworkDiscovery interface {
	// DiscoverLocalSubnet returns the local network CIDR notation (e.g., "192.168.1.0/24").
	// This is derived from the local machine's network interface configuration, typically
	// selecting the primary private network interface. The returned CIDR can be used as
	// the target for network scanning tools like nmap and masscan.
	//
	// Returns an error if no suitable network interface is found or if the CIDR cannot be determined.
	DiscoverLocalSubnet(ctx context.Context) (string, error)

	// GetDomainMappings returns hostname to IP address mappings from /etc/hosts (or equivalent).
	// The map keys are hostnames, and values are slices of IP addresses associated with each hostname.
	// This supports hosts with multiple IP addresses (common in load-balanced or multi-homed environments).
	//
	// Example return:
	//   map[string][]string{
	//     "internal.example.local": {"192.168.1.10"},
	//     "app.example.com": {"10.0.1.5", "10.0.1.6"},
	//   }
	//
	// Returns an error if the hosts file cannot be read or parsed.
	GetDomainMappings(ctx context.Context) (map[string][]string, error)
}

// DiscoveryResult contains comprehensive network discovery information for reconnaissance targeting.
// This structure aggregates all discovered network information that reconnaissance tools need.
type DiscoveryResult struct {
	// CIDR represents the local network in CIDR notation (e.g., "192.168.1.0/24").
	// This is the primary target for network scanning operations.
	CIDR string

	// LocalIP is the machine's IP address on the discovered network (e.g., "192.168.1.50").
	// This helps identify which hosts are on the same network segment.
	LocalIP string

	// Gateway is the network's default gateway IP address (e.g., "192.168.1.1").
	// This is typically the router or firewall device for the network.
	Gateway string

	// DomainMappings contains hostname to IP address mappings from the system hosts file.
	// Keys are hostnames, values are slices of IP addresses. This enables domain-based
	// reconnaissance tools like subfinder and amass to enumerate known internal domains.
	DomainMappings map[string][]string

	// Domains contains unique domain suffixes extracted from DomainMappings (e.g., [".local", ".internal"]).
	// These represent the organization's internal DNS zones and are useful for targeted
	// domain enumeration and subdomain brute-forcing operations.
	Domains []string
}
