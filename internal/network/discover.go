package network

import (
	"context"
	"fmt"
	"log"
	"net"
)

// discoverer implements the NetworkDiscovery interface using the standard
// library net package to inspect network interfaces and system files.
type discoverer struct{}

// NewNetworkDiscovery creates a new NetworkDiscovery implementation.
func NewNetworkDiscovery() NetworkDiscovery {
	return &discoverer{}
}

// DiscoverLocalSubnet detects the local network CIDR by examining available
// network interfaces. It prefers private IP ranges in the following order:
// 1. 192.168.x.x/24 (Class C private)
// 2. 10.x.x.x/8 (Class A private)
// 3. 172.16-31.x.x/16 (Class B private)
//
// Returns the network CIDR (e.g., "192.168.1.0/24"), not the host IP.
func (d *discoverer) DiscoverLocalSubnet(ctx context.Context) (string, error) {
	log.Println("[network-discovery] Starting local subnet discovery")

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	log.Printf("[network-discovery] Found %d network interfaces", len(interfaces))

	// Track candidates by preference level
	var class192 *net.IPNet // 192.168.x.x - highest priority
	var class10 *net.IPNet  // 10.x.x.x - medium priority
	var class172 *net.IPNet // 172.16-31.x.x - lowest priority

	// Examine each interface
	for _, iface := range interfaces {
		// Skip interfaces that are down or loopback
		if iface.Flags&net.FlagUp == 0 {
			log.Printf("[network-discovery] Skipping interface %s (down)", iface.Name)
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			log.Printf("[network-discovery] Skipping interface %s (loopback)", iface.Name)
			continue
		}

		// Get addresses for this interface
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("[network-discovery] Failed to get addresses for interface %s: %v", iface.Name, err)
			continue
		}

		// Check each address
		for _, addr := range addrs {
			// Parse the address
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Only consider IPv4 addresses
			ip := ipNet.IP.To4()
			if ip == nil {
				log.Printf("[network-discovery] Skipping non-IPv4 address %s on interface %s", ipNet.IP, iface.Name)
				continue
			}

			log.Printf("[network-discovery] Examining IP %s on interface %s", ip, iface.Name)

			// Classify by private IP range
			if isClass192(ip) {
				log.Printf("[network-discovery] Found Class C private IP %s on %s", ip, iface.Name)
				if class192 == nil {
					class192 = ipNet
				}
			} else if isClass10(ip) {
				log.Printf("[network-discovery] Found Class A private IP %s on %s", ip, iface.Name)
				if class10 == nil {
					class10 = ipNet
				}
			} else if isClass172(ip) {
				log.Printf("[network-discovery] Found Class B private IP %s on %s", ip, iface.Name)
				if class172 == nil {
					class172 = ipNet
				}
			} else {
				log.Printf("[network-discovery] Skipping non-private IP %s on %s", ip, iface.Name)
			}
		}
	}

	// Select the best candidate based on preference order
	var selected *net.IPNet
	var selectedType string

	if class192 != nil {
		selected = class192
		selectedType = "192.168.x.x (Class C)"
	} else if class10 != nil {
		selected = class10
		selectedType = "10.x.x.x (Class A)"
	} else if class172 != nil {
		selected = class172
		selectedType = "172.16-31.x.x (Class B)"
	}

	if selected == nil {
		return "", fmt.Errorf("no suitable private IP network found on any interface")
	}

	// Extract the network CIDR (not the host IP)
	networkCIDR := getNetworkCIDR(selected)
	log.Printf("[network-discovery] Selected network: %s (type: %s)", networkCIDR, selectedType)

	return networkCIDR, nil
}

// GetDomainMappings is implemented in hosts.go.
// See hosts.go for the full implementation that parses /etc/hosts.

// isClass192 checks if an IP is in the 192.168.0.0/16 range.
func isClass192(ip net.IP) bool {
	return ip[0] == 192 && ip[1] == 168
}

// isClass10 checks if an IP is in the 10.0.0.0/8 range.
func isClass10(ip net.IP) bool {
	return ip[0] == 10
}

// isClass172 checks if an IP is in the 172.16.0.0/12 range (172.16-31.x.x).
func isClass172(ip net.IP) bool {
	return ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31
}

// getNetworkCIDR calculates the network CIDR from an IPNet.
// It masks the IP address with the network mask to get the network address.
func getNetworkCIDR(ipNet *net.IPNet) string {
	// Get the network address by applying the mask
	ip := ipNet.IP.To4()
	mask := ipNet.Mask
	network := make(net.IP, 4)

	for i := 0; i < 4; i++ {
		network[i] = ip[i] & mask[i]
	}

	// Calculate prefix length
	ones, _ := mask.Size()

	// Return as CIDR notation
	return fmt.Sprintf("%s/%d", network.String(), ones)
}
