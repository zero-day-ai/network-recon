package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zero-day-ai/sdk/agent"

	"github.com/zero-day-ai/agents/network-recon/internal/intelligence"
	"github.com/zero-day-ai/agents/network-recon/internal/network"
	"github.com/zero-day-ai/agents/network-recon/internal/recon"
)

// executeRecon is the main execution function for the network-recon agent.
// It performs network reconnaissance using the configured phases and tools.
func executeRecon(ctx context.Context, h agent.Harness, task agent.Task) (agent.Result, error) {
	logger := h.Logger()
	logger.InfoContext(ctx, "starting network-recon agent",
		"task_id", task.ID,
		"mission_id", h.Mission().ID,
	)

	// Parse configuration
	cfg, err := ParseConfig(task)
	if err != nil {
		logger.ErrorContext(ctx, "failed to parse configuration", "error", err)
		return agent.NewFailedResult(err), nil
	}

	logger.InfoContext(ctx, "parsed configuration",
		"subnet", cfg.Subnet,
		"domain_count", len(cfg.Domains),
		"demo_mode", cfg.DemoMode,
		"verbose", cfg.Verbose,
	)

	// Auto-discover subnet if not provided
	if cfg.Subnet == "" {
		logger.InfoContext(ctx, "auto-discovering local subnet")
		discovery := network.NewNetworkDiscovery()
		subnet, err := discovery.DiscoverLocalSubnet(ctx)
		if err != nil {
			logger.WarnContext(ctx, "failed to auto-discover subnet", "error", err)
			// Continue without subnet - some phases may still work
		} else {
			cfg.Subnet = subnet
			logger.InfoContext(ctx, "discovered local subnet", "subnet", subnet)
		}
	}

	// Auto-discover domains from /etc/hosts if not provided
	if len(cfg.Domains) == 0 {
		logger.InfoContext(ctx, "auto-discovering domains from /etc/hosts")
		discovery := network.NewNetworkDiscovery()
		mappings, err := discovery.GetDomainMappings(ctx)
		if err != nil {
			logger.WarnContext(ctx, "failed to get domain mappings", "error", err)
		} else {
			cfg.Domains = extractDomainNames(mappings)
			logger.InfoContext(ctx, "discovered domains", "count", len(cfg.Domains))
		}
	}

	// Create reconnaissance runner
	runner := recon.NewReconRunner(h)

	// Run all reconnaissance phases
	logger.InfoContext(ctx, "running reconnaissance phases",
		"subnet", cfg.Subnet,
		"domain_count", len(cfg.Domains),
	)

	reconResult, err := runner.RunAll(ctx, cfg.Subnet, cfg.Domains)
	if err != nil {
		logger.ErrorContext(ctx, "reconnaissance failed", "error", err)
		return agent.NewFailedResult(err), nil
	}

	// Generate intelligence analysis if enabled
	var intel *intelligence.Intelligence
	if cfg.GenerateIntelligence {
		logger.InfoContext(ctx, "generating intelligence analysis")
		gen := intelligence.NewIntelligenceGenerator(h)
		intel, err = gen.GenerateSummary(ctx, h.Mission().ID)
		if err != nil {
			logger.WarnContext(ctx, "intelligence generation failed", "error", err)
			// Continue without intelligence - not a fatal error
		}
	}

	// Build output
	output := formatReconOutput(reconResult, intel, cfg)

	// Build metadata
	metadata := map[string]any{
		"hosts_discovered":     reconResult.TotalHosts,
		"ports_discovered":     reconResult.TotalPorts,
		"endpoints_discovered": reconResult.TotalEndpoints,
		"phases_executed":      len(reconResult.Phases),
		"duration":             reconResult.Duration.String(),
	}

	logger.InfoContext(ctx, "reconnaissance complete",
		"total_hosts", reconResult.TotalHosts,
		"total_ports", reconResult.TotalPorts,
		"total_endpoints", reconResult.TotalEndpoints,
		"duration", reconResult.Duration.String(),
	)

	return agent.Result{
		Status:   agent.StatusSuccess,
		Output:   output,
		Metadata: metadata,
	}, nil
}

// extractDomainNames extracts unique domain names from hostname-to-IP mappings.
func extractDomainNames(mappings map[string][]string) []string {
	seen := make(map[string]bool)
	var domains []string

	for hostname := range mappings {
		// Skip localhost and simple hostnames without dots
		if hostname == "localhost" || !containsDot(hostname) {
			continue
		}

		// Extract the domain suffix (everything after first dot)
		// e.g., "server.example.local" -> "example.local"
		firstDot := indexOfDot(hostname)
		if firstDot != -1 && firstDot < len(hostname)-1 {
			domain := hostname[firstDot+1:]
			if !seen[domain] && containsDot(domain) {
				seen[domain] = true
				domains = append(domains, domain)
			}
		}
	}

	return domains
}

// containsDot returns true if the string contains a dot character.
func containsDot(s string) bool {
	for _, c := range s {
		if c == '.' {
			return true
		}
	}
	return false
}

// indexOfDot returns the index of the first dot, or -1 if not found.
func indexOfDot(s string) int {
	for i, c := range s {
		if c == '.' {
			return i
		}
	}
	return -1
}

// formatReconOutput generates the output string for the reconnaissance results.
func formatReconOutput(result *recon.ReconResult, intel *intelligence.Intelligence, cfg *ReconConfig) string {
	output := fmt.Sprintf(`
=== Network Reconnaissance Report ===
Subnet: %s
Duration: %s

=== Summary ===
Hosts Discovered: %d
Ports Discovered: %d
HTTP Endpoints: %d
Phases Executed: %d
`,
		cfg.Subnet,
		result.Duration.String(),
		result.TotalHosts,
		result.TotalPorts,
		result.TotalEndpoints,
		len(result.Phases),
	)

	// Add phase details
	for _, phase := range result.Phases {
		output += fmt.Sprintf(`
=== Phase: %s ===
Tools Run: %v
Nodes Created: %d
Relationships Created: %d
Duration: %s
Errors: %d
`,
			phase.Phase,
			phase.ToolsRun,
			phase.NodesCreated,
			phase.RelationsCreated,
			phase.Duration.String(),
			len(phase.Errors),
		)
	}

	// Add intelligence summary if available
	if intel != nil {
		output += fmt.Sprintf(`
=== Intelligence Analysis ===
%s
`, intel.Summary)
	}

	// Add JSON output for machine parsing
	jsonOutput, _ := json.MarshalIndent(map[string]any{
		"subnet":              cfg.Subnet,
		"duration":            result.Duration.String(),
		"total_hosts":         result.TotalHosts,
		"total_ports":         result.TotalPorts,
		"total_endpoints":     result.TotalEndpoints,
		"phases":              len(result.Phases),
		"has_intelligence":    intel != nil,
	}, "", "  ")

	output += fmt.Sprintf(`
--- JSON Output ---

%s
`, string(jsonOutput))

	return output
}
