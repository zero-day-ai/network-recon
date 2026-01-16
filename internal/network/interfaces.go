// Package network provides network discovery capabilities for local subnet detection.
//
// This package enables the network-recon agent to automatically discover its local network
// environment including subnet CIDR ranges, local IP addresses, and default gateways.
// These discoveries are used to configure reconnaissance tools with appropriate targets
// for network scanning and enumeration.
//
// The primary use case is automated local network reconnaissance where the agent needs to
// determine what networks to scan without manual configuration.
package network

import "context"

// NetworkDiscovery defines the interface for discovering local network configuration.
// Implementations should use system network interfaces to determine reconnaissance targets.
type NetworkDiscovery interface {
	// DiscoverLocalSubnet returns the local network CIDR notation (e.g., "192.168.1.0/24").
	// This is derived from the local machine's network interface configuration, typically
	// selecting the primary private network interface. The returned CIDR can be used as
	// the target for network scanning tools like nmap and masscan.
	//
	// Returns an error if no suitable network interface is found or if the CIDR cannot be determined.
	DiscoverLocalSubnet(ctx context.Context) (string, error)
}

// DiscoveryResult contains network discovery information for reconnaissance targeting.
// This structure aggregates discovered network information that reconnaissance tools need.
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
}
