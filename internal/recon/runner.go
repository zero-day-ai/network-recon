package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/agent"
)

// DefaultReconRunner implements the ReconRunner interface using the agent harness
// for tool execution and knowledge graph storage.
type DefaultReconRunner struct {
	harness   agent.Harness
	extractor TaxonomyExtractor
}

// NewReconRunner creates a new reconnaissance runner that uses the provided harness
// for tool execution and knowledge graph operations.
func NewReconRunner(harness agent.Harness) ReconRunner {
	return &DefaultReconRunner{
		harness:   harness,
		extractor: NewTaxonomyExtractor(harness),
	}
}

// RunPhase executes a single reconnaissance phase with the specified targets.
// It selects appropriate tools based on the phase, invokes them via the harness,
// and returns statistics about execution and entity creation.
func (r *DefaultReconRunner) RunPhase(ctx context.Context, phase Phase, targets []string) (*PhaseResult, error) {
	startTime := time.Now()
	logger := r.harness.Logger()

	result := &PhaseResult{
		Phase:    phase,
		ToolsRun: []string{},
		Errors:   []error{},
	}

	logger.InfoContext(ctx, "starting reconnaissance phase",
		"phase", phase,
		"target_count", len(targets),
	)

	// Execute phase-specific tools
	switch phase {
	case PhaseDiscover:
		r.runDiscoverPhase(ctx, targets, result)
	case PhaseProbe:
		r.runProbePhase(ctx, targets, result)
	case PhaseDomain:
		r.runDomainPhase(ctx, targets, result)
	default:
		return nil, fmt.Errorf("unknown phase: %s", phase)
	}

	result.Duration = time.Since(startTime)

	logger.InfoContext(ctx, "completed reconnaissance phase",
		"phase", phase,
		"tools_run", len(result.ToolsRun),
		"nodes_created", result.NodesCreated,
		"relations_created", result.RelationsCreated,
		"duration_ms", result.Duration.Milliseconds(),
		"error_count", len(result.Errors),
	)

	return result, nil
}

// runDiscoverPhase executes the discover phase:
// 1. First runs nmap ping scan (-sn) to find live hosts
// 2. Then runs nmap port scan only against live hosts
func (r *DefaultReconRunner) runDiscoverPhase(ctx context.Context, targets []string, result *PhaseResult) {
	logger := r.harness.Logger()

	for _, target := range targets {
		// Step 1: Nmap ping scan to find live hosts (fast host discovery)
		logger.InfoContext(ctx, "running nmap ping scan for host discovery", "target", target)

		pingInput := map[string]any{
			"target":    target,
			"scan_type": "ping", // Uses nmap -sn for host discovery only
			"timing":    4,      // Aggressive timing for ping scan
		}

		pingOutput, err := r.harness.CallTool(ctx, "nmap", pingInput)
		if err != nil {
			logger.ErrorContext(ctx, "nmap ping scan failed", "error", err)
			result.Errors = append(result.Errors, fmt.Errorf("nmap ping scan failed: %w", err))
			continue
		}
		result.ToolsRun = append(result.ToolsRun, "nmap-ping")

		// Extract live hosts from nmap ping output
		liveHosts := extractLiveHostsFromNmap(pingOutput)
		if len(liveHosts) == 0 {
			logger.WarnContext(ctx, "no live hosts found in ping scan", "target", target)
			continue
		}

		logger.InfoContext(ctx, "ping scan complete", "target", target, "live_hosts", len(liveHosts))

		// Step 2: Run nmap port scan only against live hosts
		for _, host := range liveHosts {
			logger.InfoContext(ctx, "running nmap port scan on live host", "host", host)

			input := map[string]any{
				"target":            host,
				"ports":             "1-1000",
				"scan_type":         "connect",
				"service_detection": true,
				"timing":            4, // Aggressive timing since we know host is up
			}

			output, err := r.harness.CallTool(ctx, "nmap", input)
			var toolUsed string
			if err != nil {
				logger.ErrorContext(ctx, "nmap failed, trying masscan fallback", "host", host, "error", err)
				result.Errors = append(result.Errors, fmt.Errorf("nmap failed for %s: %w", host, err))

				// Fallback: masscan
				masscanInput := map[string]any{
					"target": host,
					"ports":  "1-1000",
					"rate":   1000,
				}

				output, err = r.harness.CallTool(ctx, "masscan", masscanInput)
				if err != nil {
					logger.ErrorContext(ctx, "masscan fallback also failed", "host", host, "error", err)
					result.Errors = append(result.Errors, fmt.Errorf("masscan failed for %s: %w", host, err))
					continue
				}
				toolUsed = "masscan"
				result.ToolsRun = append(result.ToolsRun, "masscan")
			} else {
				toolUsed = "nmap"
				result.ToolsRun = append(result.ToolsRun, "nmap")
			}

			// Extract entities from tool output using taxonomy extractor
			if output != nil {
				outputJSON, err := json.Marshal(output)
				if err != nil {
					logger.ErrorContext(ctx, "failed to marshal tool output", "error", err)
					result.Errors = append(result.Errors, fmt.Errorf("failed to marshal output: %w", err))
					continue
				}

				nodes, rels, err := r.extractor.Extract(ctx, toolUsed, outputJSON)
				if err != nil {
					logger.ErrorContext(ctx, "failed to extract entities", "tool", toolUsed, "error", err)
					result.Errors = append(result.Errors, fmt.Errorf("extraction failed: %w", err))
				} else {
					result.NodesCreated += nodes
					result.RelationsCreated += rels
					logger.InfoContext(ctx, "extracted entities from tool output",
						"tool", toolUsed,
						"host", host,
						"nodes", nodes,
						"relations", rels)
				}
			}
		}
	}
}

// extractLiveHostsFromNmap parses nmap output and returns a list of live host IPs
func extractLiveHostsFromNmap(output any) []string {
	if output == nil {
		return nil
	}

	var hosts []string

	// nmap output format: {"hosts": [{"ip": "x.x.x.x", "state": "up", ...}], ...}
	if m, ok := output.(map[string]any); ok {
		if hostsArr, ok := m["hosts"].([]any); ok {
			for _, h := range hostsArr {
				if hostMap, ok := h.(map[string]any); ok {
					// Check if host state is "up"
					state, _ := hostMap["state"].(string)
					if state == "up" {
						if ip, ok := hostMap["ip"].(string); ok && ip != "" {
							hosts = append(hosts, ip)
						}
					}
				}
			}
		}
	}

	return hosts
}

// runProbePhase executes the probe phase using httpx.
func (r *DefaultReconRunner) runProbePhase(ctx context.Context, targets []string, result *PhaseResult) {
	logger := r.harness.Logger()

	if len(targets) == 0 {
		logger.WarnContext(ctx, "no targets for probe phase")
		return
	}

	logger.InfoContext(ctx, "running httpx probe", "target_count", len(targets))

	// httpx accepts a list of targets
	input := map[string]any{
		"targets":          targets,
		"tech_detect":      true,
		"follow_redirects": true,
		"threads":          10,
	}

	output, err := r.harness.CallTool(ctx, "httpx", input)
	if err != nil {
		logger.ErrorContext(ctx, "httpx failed", "error", err)
		result.Errors = append(result.Errors, fmt.Errorf("httpx failed: %w", err))
		return
	}

	result.ToolsRun = append(result.ToolsRun, "httpx")

	// Extract entities from httpx output using taxonomy extractor
	if output != nil {
		outputJSON, err := json.Marshal(output)
		if err != nil {
			logger.ErrorContext(ctx, "failed to marshal tool output", "error", err)
			result.Errors = append(result.Errors, fmt.Errorf("failed to marshal output: %w", err))
			return
		}

		nodes, rels, err := r.extractor.Extract(ctx, "httpx", outputJSON)
		if err != nil {
			logger.ErrorContext(ctx, "failed to extract entities", "tool", "httpx", "error", err)
			result.Errors = append(result.Errors, fmt.Errorf("extraction failed: %w", err))
		} else {
			result.NodesCreated += nodes
			result.RelationsCreated += rels
			logger.InfoContext(ctx, "extracted entities from tool output",
				"tool", "httpx",
				"nodes", nodes,
				"relations", rels)
		}
	}
}

// runDomainPhase executes the domain phase using subfinder and amass.
func (r *DefaultReconRunner) runDomainPhase(ctx context.Context, targets []string, result *PhaseResult) {
	logger := r.harness.Logger()

	if len(targets) == 0 {
		logger.WarnContext(ctx, "no domains for domain phase")
		return
	}

	// Run subfinder for each domain
	for _, domain := range targets {
		logger.InfoContext(ctx, "running subfinder", "domain", domain)

		input := map[string]any{
			"domain": domain,
		}

		output, err := r.harness.CallTool(ctx, "subfinder", input)
		if err != nil {
			logger.ErrorContext(ctx, "subfinder failed", "error", err, "domain", domain)
			result.Errors = append(result.Errors, fmt.Errorf("subfinder failed for %s: %w", domain, err))
			continue
		}

		result.ToolsRun = append(result.ToolsRun, "subfinder")

		// Extract entities from subfinder output using taxonomy extractor
		if output != nil {
			outputJSON, err := json.Marshal(output)
			if err != nil {
				logger.ErrorContext(ctx, "failed to marshal tool output", "error", err)
				result.Errors = append(result.Errors, fmt.Errorf("failed to marshal output: %w", err))
				continue
			}

			nodes, rels, err := r.extractor.Extract(ctx, "subfinder", outputJSON)
			if err != nil {
				logger.ErrorContext(ctx, "failed to extract entities", "tool", "subfinder", "error", err)
				result.Errors = append(result.Errors, fmt.Errorf("extraction failed: %w", err))
			} else {
				result.NodesCreated += nodes
				result.RelationsCreated += rels
				logger.InfoContext(ctx, "extracted entities from tool output",
					"tool", "subfinder",
					"nodes", nodes,
					"relations", rels)
			}
		}
	}

	// Run amass for comprehensive enumeration
	for _, domain := range targets {
		logger.InfoContext(ctx, "running amass", "domain", domain)

		input := map[string]any{
			"domain":  domain,
			"passive": true, // Use passive enumeration for speed
		}

		output, err := r.harness.CallTool(ctx, "amass", input)
		if err != nil {
			logger.ErrorContext(ctx, "amass failed", "error", err, "domain", domain)
			result.Errors = append(result.Errors, fmt.Errorf("amass failed for %s: %w", domain, err))
			continue
		}

		result.ToolsRun = append(result.ToolsRun, "amass")

		// Extract entities from amass output using taxonomy extractor
		if output != nil {
			outputJSON, err := json.Marshal(output)
			if err != nil {
				logger.ErrorContext(ctx, "failed to marshal tool output", "error", err)
				result.Errors = append(result.Errors, fmt.Errorf("failed to marshal output: %w", err))
				continue
			}

			nodes, rels, err := r.extractor.Extract(ctx, "amass", outputJSON)
			if err != nil {
				logger.ErrorContext(ctx, "failed to extract entities", "tool", "amass", "error", err)
				result.Errors = append(result.Errors, fmt.Errorf("extraction failed: %w", err))
			} else {
				result.NodesCreated += nodes
				result.RelationsCreated += rels
				logger.InfoContext(ctx, "extracted entities from tool output",
					"tool", "amass",
					"nodes", nodes,
					"relations", rels)
			}
		}
	}
}

// RunAll executes all reconnaissance phases in sequence: discover -> probe -> domain.
// Later phases use outputs from earlier phases as their inputs.
// Note: No vulnerability scanning (nuclei) - this agent focuses on discovery only.
func (r *DefaultReconRunner) RunAll(ctx context.Context, subnet string, domains []string) (*ReconResult, error) {
	startTime := time.Now()
	logger := r.harness.Logger()

	result := &ReconResult{
		Phases: []*PhaseResult{},
	}

	logger.InfoContext(ctx, "starting full reconnaissance workflow",
		"subnet", subnet,
		"domain_count", len(domains),
	)

	// Phase 1: Discover hosts and ports
	discoverResult, err := r.RunPhase(ctx, PhaseDiscover, []string{subnet})
	if err != nil {
		return nil, fmt.Errorf("discover phase failed: %w", err)
	}
	result.Phases = append(result.Phases, discoverResult)

	// Extract discovered hosts/ports for next phase
	// We query the knowledge graph to get hosts with open HTTP/HTTPS ports
	probeTargets, err := r.extractProbeTargets(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "failed to extract probe targets", "error", err)
		// Continue with empty targets rather than failing
		probeTargets = []string{}
	}

	// Phase 2: Probe HTTP endpoints
	if len(probeTargets) > 0 {
		probeResult, err := r.RunPhase(ctx, PhaseProbe, probeTargets)
		if err != nil {
			return nil, fmt.Errorf("probe phase failed: %w", err)
		}
		result.Phases = append(result.Phases, probeResult)
	}

	// Phase 3: Domain enumeration
	if len(domains) > 0 {
		domainResult, err := r.RunPhase(ctx, PhaseDomain, domains)
		if err != nil {
			return nil, fmt.Errorf("domain phase failed: %w", err)
		}
		result.Phases = append(result.Phases, domainResult)
	}

	// Aggregate statistics
	for _, phaseResult := range result.Phases {
		result.TotalHosts += countHosts(phaseResult)
		result.TotalPorts += countPorts(phaseResult)
		result.TotalEndpoints += countEndpoints(phaseResult)
	}

	result.Duration = time.Since(startTime)

	logger.InfoContext(ctx, "completed full reconnaissance workflow",
		"total_hosts", result.TotalHosts,
		"total_ports", result.TotalPorts,
		"total_endpoints", result.TotalEndpoints,
		"duration_ms", result.Duration.Milliseconds(),
	)

	return result, nil
}

// extractProbeTargets queries the knowledge graph to find hosts with HTTP/HTTPS ports.
// Returns a list of URLs to probe with httpx.
func (r *DefaultReconRunner) extractProbeTargets(ctx context.Context) ([]string, error) {
	// Query for hosts with common HTTP/HTTPS ports
	// This is a simplified implementation - a real implementation would query Neo4j
	// For now, return empty slice as we'll implement GraphRAG queries later
	return []string{}, nil
}

// Helper functions to count specific entity types from phase results

func countHosts(result *PhaseResult) int {
	if result.Phase == PhaseDiscover {
		// Approximate: NodesCreated includes both hosts and ports
		// In discover phase, roughly half are hosts (the other half are ports)
		return result.NodesCreated / 2
	}
	return 0
}

func countPorts(result *PhaseResult) int {
	if result.Phase == PhaseDiscover {
		// Approximate: roughly half of nodes created in discover are ports
		return result.NodesCreated / 2
	}
	return 0
}

func countEndpoints(result *PhaseResult) int {
	if result.Phase == PhaseProbe {
		// In probe phase, endpoints are the primary node type
		return result.NodesCreated / 2 // Approximate: half are endpoints, half are technologies
	}
	return 0
}

// marshalInput is a helper to convert input map to JSON for logging
func marshalInput(input map[string]any) string {
	b, err := json.Marshal(input)
	if err != nil {
		return fmt.Sprintf("%v", input)
	}
	return string(b)
}
