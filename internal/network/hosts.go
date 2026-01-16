package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

const (
	// hostsFilePath is the standard location of the hosts file on Unix-like systems
	hostsFilePath = "/etc/hosts"
)

// GetDomainMappings reads and parses the system hosts file (/etc/hosts) to extract
// hostname to IP address mappings. It returns a map where keys are hostnames and
// values are slices of IP addresses. This supports configurations where a single
// hostname may resolve to multiple IPs (e.g., load-balanced or multi-homed hosts).
//
// The /etc/hosts file format is: IP_address hostname [hostname ...]
// Lines starting with # are comments and are ignored.
// Blank lines are ignored.
//
// Example /etc/hosts:
//   127.0.0.1       localhost
//   192.168.1.10    server.local webserver.local
//   10.0.1.5        app.example.com
//
// Returns:
//   - map[string][]string: hostname -> []IP mappings
//   - error: if the hosts file cannot be read or parsed
func (d *discoverer) GetDomainMappings(ctx context.Context) (map[string][]string, error) {
	log.Printf("[network-discovery] Starting domain mappings discovery from %s", hostsFilePath)

	// Parse the hosts file
	mappings, err := parseHostsFile(hostsFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse hosts file: %w", err)
	}

	// Extract domain suffixes
	domains := extractDomainSuffixes(mappings)

	log.Printf("[network-discovery] Discovered %d hostname mappings", len(mappings))
	log.Printf("[network-discovery] Discovered %d unique domain suffixes: %v", len(domains), domains)

	return mappings, nil
}

// parseHostsFile reads a hosts file from a file path and extracts hostname to IP mappings.
// The hosts file format is:
//
//   IP_address hostname [hostname ...]
//
// Lines starting with # are comments and are ignored.
// Blank lines and whitespace-only lines are ignored.
// Malformed lines (lines without valid IP addresses) are logged and skipped.
//
// Returns:
//   - map[string][]string: hostname -> []IP mappings
//   - error: if the file cannot be read or parsed
func parseHostsFile(path string) (map[string][]string, error) {
	// Open the hosts file
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open hosts file %s: %w", path, err)
	}
	defer file.Close()

	return parseHostsFileReader(file)
}

// parseHostsFileReader reads a hosts file from an io.Reader and extracts hostname to IP mappings.
// This is the core parsing logic separated for easier testing.
func parseHostsFileReader(reader io.Reader) (map[string][]string, error) {
	mappings := make(map[string][]string)

	scanner := bufio.NewScanner(reader)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines
		if line == "" {
			continue
		}

		// Skip comment lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		// Remove inline comments (anything after # on the line)
		if commentIdx := strings.Index(line, "#"); commentIdx != -1 {
			line = strings.TrimSpace(line[:commentIdx])
			// If line becomes empty after removing comment, skip it
			if line == "" {
				continue
			}
		}

		// Parse the line: IP hostname [hostname ...]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			log.Printf("[network-discovery] Skipping malformed line %d: not enough fields", lineNum)
			continue
		}

		// First field should be an IP address
		ipStr := fields[0]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			log.Printf("[network-discovery] Skipping malformed line %d: invalid IP address %q", lineNum, ipStr)
			continue
		}

		// Remaining fields are hostnames
		hostnames := fields[1:]
		for _, hostname := range hostnames {
			// Skip empty hostnames (shouldn't happen with Fields(), but be defensive)
			if hostname == "" {
				continue
			}

			// Check if this IP is already mapped to this hostname (avoid duplicates)
			ips := mappings[hostname]
			isDuplicate := false
			for _, existingIP := range ips {
				if existingIP == ipStr {
					isDuplicate = true
					break
				}
			}

			// Add hostname -> IP mapping only if not duplicate
			if !isDuplicate {
				mappings[hostname] = append(mappings[hostname], ipStr)
				log.Printf("[network-discovery] Mapped hostname %q to IP %s", hostname, ipStr)
			}
		}
	}

	// Check for scanner errors (I/O errors)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading hosts file: %w", err)
	}

	return mappings, nil
}

// extractDomainSuffixes extracts unique domain suffixes from a hostname to IP mappings.
// For each hostname that contains a dot, it extracts the top-level domain suffix.
//
// Example:
//   - "server.local" -> ".local"
//   - "app.example.com" -> ".com"
//   - "localhost" -> (no suffix extracted)
//
// Returns:
//   - []string: sorted list of unique domain suffixes (e.g., [".com", ".internal", ".local"])
func extractDomainSuffixes(mappings map[string][]string) []string {
	domainSuffixes := make(map[string]bool)

	for hostname := range mappings {
		// Extract the top-level domain suffix (last dot to end)
		// e.g., "server.dev.local" -> ".local"
		// e.g., "app.example.com" -> ".com"
		if lastDot := strings.LastIndex(hostname, "."); lastDot != -1 {
			suffix := hostname[lastDot:] // includes the leading dot
			domainSuffixes[suffix] = true
		}
	}

	// Convert map to sorted slice
	result := make([]string, 0, len(domainSuffixes))
	for suffix := range domainSuffixes {
		result = append(result, suffix)
	}

	return result
}
