package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	"github.com/zero-day-ai/sdk/graphrag/domain"
)

// DefaultReconRunner implements the ReconRunner interface using the agent harness
// for tool execution. Entity extraction is handled automatically by Gibson's
// TaxonomyGraphEngine when tool outputs are returned via the callback service.
type DefaultReconRunner struct {
	harness agent.Harness
}

// NewReconRunner creates a new reconnaissance runner that uses the provided harness
// for tool execution.
func NewReconRunner(harness agent.Harness) ReconRunner {
	return &DefaultReconRunner{
		harness: harness,
	}
}

// RunPhase executes a single reconnaissance phase with the specified targets.
// It selects appropriate tools based on the phase, invokes them via the harness,
// and returns statistics about execution and entity creation.
func (r *DefaultReconRunner) RunPhase(ctx context.Context, phase Phase, targets []string) (*PhaseResult, error) {
	startTime := time.Now()
	logger := r.harness.Logger()

	result := &PhaseResult{
		Phase:       phase,
		ToolsRun:    []string{},
		Errors:      []error{},
		Discoveries: domain.NewDiscoveryResult(),
	}

	logger.InfoContext(ctx, "starting reconnaissance phase",
		"phase", phase,
		"target_count", len(targets),
	)

	// Execute phase-specific tools
	switch phase {
	case PhaseDiscover:
		r.runDiscoverPhase(ctx, targets, result, result.Discoveries)
	case PhaseProbe:
		r.runProbePhase(ctx, targets, result, result.Discoveries)
	case PhaseDomain:
		r.runDomainPhase(ctx, targets, result, result.Discoveries)
	default:
		return nil, fmt.Errorf("unknown phase: %s", phase)
	}

	// Count nodes created in this phase
	result.NodesCreated = result.Discoveries.NodeCount()

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
func (r *DefaultReconRunner) runDiscoverPhase(ctx context.Context, targets []string, result *PhaseResult, discoveries *domain.DiscoveryResult) {
	logger := r.harness.Logger()

	for _, target := range targets {
		// Step 1: Nmap ping scan to find live hosts (fast host discovery)
		logger.InfoContext(ctx, "running nmap ping scan for host discovery", "target", target)

		pingReq := &toolspb.NmapRequest{
			Targets:  []string{target},
			ScanType: toolspb.ScanType_SCAN_TYPE_PING,
			Timing:   toolspb.TimingTemplate_TIMING_TEMPLATE_AGGRESSIVE,
		}
		pingResp := &toolspb.NmapResponse{}

		err := r.harness.CallToolProto(ctx, "nmap", pingReq, pingResp)
		if err != nil {
			logger.ErrorContext(ctx, "nmap ping scan failed", "error", err)
			result.Errors = append(result.Errors, fmt.Errorf("nmap ping scan failed: %w", err))
			continue
		}
		result.ToolsRun = append(result.ToolsRun, "nmap-ping")

		// Extract live hosts from nmap ping output and add to discoveries
		liveHosts := extractLiveHostsFromNmapProto(pingResp)
		if len(liveHosts) == 0 {
			logger.WarnContext(ctx, "no live hosts found in ping scan", "target", target)
			continue
		}

		logger.InfoContext(ctx, "ping scan complete", "target", target, "live_hosts", len(liveHosts))

		// Step 2: Run nmap port scan only against live hosts
		for _, host := range liveHosts {
			logger.InfoContext(ctx, "running nmap port scan on live host", "host", host)

			nmapReq := &toolspb.NmapRequest{
				Targets:          []string{host},
				Ports:            "1-1000",
				ScanType:         toolspb.ScanType_SCAN_TYPE_CONNECT,
				ServiceDetection: true,
				Timing:           toolspb.TimingTemplate_TIMING_TEMPLATE_AGGRESSIVE,
			}
			nmapResp := &toolspb.NmapResponse{}

			err := r.harness.CallToolProto(ctx, "nmap", nmapReq, nmapResp)
			if err != nil {
				logger.ErrorContext(ctx, "nmap port scan failed", "host", host, "error", err)
				result.Errors = append(result.Errors, fmt.Errorf("nmap failed for %s: %w", host, err))
				// Note: masscan fallback removed - masscan lacks proto definition
				continue
			} else {
				result.ToolsRun = append(result.ToolsRun, "nmap")

				// Parse nmap proto output
				parseDiscoverOutputProto(nmapResp, discoveries)
			}
		}
	}
}

// extractLiveHostsFromNmap parses nmap output and returns a list of live host IPs (legacy map-based)
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

// extractLiveHostsFromNmapProto parses nmap proto response and returns a list of live host IPs
func extractLiveHostsFromNmapProto(resp *toolspb.NmapResponse) []string {
	if resp == nil {
		return nil
	}

	var hosts []string
	for _, host := range resp.Hosts {
		if host.State == "up" && host.Ip != "" {
			hosts = append(hosts, host.Ip)
		}
	}
	return hosts
}

// runProbePhase executes the probe phase using httpx.
func (r *DefaultReconRunner) runProbePhase(ctx context.Context, targets []string, result *PhaseResult, discoveries *domain.DiscoveryResult) {
	logger := r.harness.Logger()

	if len(targets) == 0 {
		logger.WarnContext(ctx, "no targets for probe phase")
		return
	}

	logger.InfoContext(ctx, "running httpx probe", "target_count", len(targets))

	// httpx accepts a list of targets
	httpxReq := &toolspb.HttpxRequest{
		Targets:         targets,
		TechDetect:      true,
		FollowRedirects: true,
		Threads:         10,
	}
	httpxResp := &toolspb.HttpxResponse{}

	err := r.harness.CallToolProto(ctx, "httpx", httpxReq, httpxResp)
	if err != nil {
		logger.ErrorContext(ctx, "httpx failed", "error", err)
		result.Errors = append(result.Errors, fmt.Errorf("httpx failed: %w", err))
		return
	}

	result.ToolsRun = append(result.ToolsRun, "httpx")

	// Parse httpx output and extract endpoints/technologies
	parseProbeOutputProto(httpxResp, discoveries)
}

// runDomainPhase executes the domain phase.
// Note: subfinder and amass support removed - they lack proto definitions.
// Domain enumeration will need to be added back when proto definitions are available.
func (r *DefaultReconRunner) runDomainPhase(ctx context.Context, targets []string, result *PhaseResult, discoveries *domain.DiscoveryResult) {
	logger := r.harness.Logger()

	if len(targets) == 0 {
		logger.WarnContext(ctx, "no domains for domain phase")
		return
	}

	// TODO: Re-enable when subfinder/amass proto definitions are available
	// For now, domain phase is a no-op
	logger.WarnContext(ctx, "domain phase skipped - subfinder/amass tools lack proto definitions",
		"domain_count", len(targets))
}

// RunAll executes all reconnaissance phases in sequence: discover -> probe -> domain.
// Later phases use outputs from earlier phases as their inputs.
// Note: No vulnerability scanning (nuclei) - this agent focuses on discovery only.
func (r *DefaultReconRunner) RunAll(ctx context.Context, subnet string, domains []string) (*ReconResult, error) {
	startTime := time.Now()
	logger := r.harness.Logger()

	result := &ReconResult{
		Phases:      []*PhaseResult{},
		Discoveries: domain.NewDiscoveryResult(),
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

	// Merge phase discoveries into overall result (note: RunPhase needs to return phaseDiscoveries)
	// For now, extract discovered hosts/ports for next phase from knowledge graph or memory
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

	// Aggregate statistics and discoveries from all phases
	for _, phaseResult := range result.Phases {
		result.TotalHosts += countHosts(phaseResult)
		result.TotalPorts += countPorts(phaseResult)
		result.TotalEndpoints += countEndpoints(phaseResult)

		// Merge phase discoveries into overall result
		if phaseResult.Discoveries != nil {
			result.Discoveries.Hosts = append(result.Discoveries.Hosts, phaseResult.Discoveries.Hosts...)
			result.Discoveries.Ports = append(result.Discoveries.Ports, phaseResult.Discoveries.Ports...)
			result.Discoveries.Services = append(result.Discoveries.Services, phaseResult.Discoveries.Services...)
			result.Discoveries.Endpoints = append(result.Discoveries.Endpoints, phaseResult.Discoveries.Endpoints...)
			result.Discoveries.Domains = append(result.Discoveries.Domains, phaseResult.Discoveries.Domains...)
			result.Discoveries.Subdomains = append(result.Discoveries.Subdomains, phaseResult.Discoveries.Subdomains...)
			result.Discoveries.Technologies = append(result.Discoveries.Technologies, phaseResult.Discoveries.Technologies...)
		}
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

// parseDiscoverOutput parses nmap/masscan output and extracts hosts, ports, and services (legacy map-based).
// Expected format: {"hosts": [{"ip": "x.x.x.x", "hostname": "...", "state": "up", "ports": [...]}]}
func parseDiscoverOutput(output any, discoveries *domain.DiscoveryResult) {
	if output == nil {
		return
	}

	outputMap, ok := output.(map[string]any)
	if !ok {
		return
	}

	hostsArr, ok := outputMap["hosts"].([]any)
	if !ok {
		return
	}

	for _, h := range hostsArr {
		hostMap, ok := h.(map[string]any)
		if !ok {
			continue
		}

		ip, _ := hostMap["ip"].(string)
		if ip == "" {
			continue
		}

		// Create host node
		host := &domain.Host{
			IP:       ip,
			Hostname: getStringField(hostMap, "hostname"),
			State:    getStringField(hostMap, "state"),
			OS:       getStringField(hostMap, "os"),
		}
		discoveries.Hosts = append(discoveries.Hosts, host)

		// Extract ports
		if portsArr, ok := hostMap["ports"].([]any); ok {
			for _, p := range portsArr {
				portMap, ok := p.(map[string]any)
				if !ok {
					continue
				}

				portNum := getIntField(portMap, "port")
				protocol := getStringField(portMap, "protocol")
				if portNum == 0 || protocol == "" {
					continue
				}

				// Create port node using BelongsTo pattern (SDK v0.27.0+)
				port := domain.NewPort(portNum, protocol).BelongsTo(host)
				port.State = getStringField(portMap, "state")
				discoveries.Ports = append(discoveries.Ports, port)

				// Extract service if present
				serviceName := getStringField(portMap, "service")
				if serviceName != "" {
					// Create service node using BelongsTo pattern
					service := domain.NewService(serviceName).BelongsTo(port)
					service.Version = getStringField(portMap, "version")
					service.Banner = getStringField(portMap, "banner")
					discoveries.Services = append(discoveries.Services, service)
				}
			}
		}
	}
}

// parseDiscoverOutputProto parses nmap proto response and extracts hosts, ports, and services.
func parseDiscoverOutputProto(resp *toolspb.NmapResponse, discoveries *domain.DiscoveryResult) {
	if resp == nil {
		return
	}

	for _, nmapHost := range resp.Hosts {
		if nmapHost.Ip == "" {
			continue
		}

		// Create host node
		host := &domain.Host{
			IP:       nmapHost.Ip,
			Hostname: nmapHost.Hostname,
			State:    nmapHost.State,
		}

		// Extract OS from OS matches if available
		if len(nmapHost.OsMatches) > 0 {
			host.OS = nmapHost.OsMatches[0].Name
		}

		discoveries.Hosts = append(discoveries.Hosts, host)

		// Extract ports
		for _, nmapPort := range nmapHost.Ports {
			if nmapPort.Number == 0 || nmapPort.Protocol == "" {
				continue
			}

			// Create port node using BelongsTo pattern
			port := domain.NewPort(int(nmapPort.Number), nmapPort.Protocol).BelongsTo(host)
			port.State = nmapPort.State
			discoveries.Ports = append(discoveries.Ports, port)

			// Extract service if present
			if nmapPort.Service != nil && nmapPort.Service.Name != "" {
				service := domain.NewService(nmapPort.Service.Name).BelongsTo(port)
				service.Version = nmapPort.Service.Version
				// Note: NmapService doesn't have a Banner field in proto, using Product as alternative
				if nmapPort.Service.Product != "" {
					service.Banner = nmapPort.Service.Product
				}
				discoveries.Services = append(discoveries.Services, service)
			}
		}
	}
}

// parseProbeOutput parses httpx output and extracts endpoints and technologies (legacy map-based).
// Expected format: {"results": [{"url": "...", "status_code": 200, "title": "...", "technologies": [...]}]}
func parseProbeOutput(output any, discoveries *domain.DiscoveryResult) {
	if output == nil {
		return
	}

	outputMap, ok := output.(map[string]any)
	if !ok {
		return
	}

	resultsArr, ok := outputMap["results"].([]any)
	if !ok {
		return
	}

	for _, r := range resultsArr {
		resultMap, ok := r.(map[string]any)
		if !ok {
			continue
		}

		url := getStringField(resultMap, "url")
		if url == "" {
			continue
		}

		// Note: Endpoint requires ServiceID which is a composite ID like "192.168.1.1:443:tcp:https"
		// Since httpx doesn't provide this directly, we'll skip creating endpoint nodes here.
		// Instead, we could create a simplified version or rely on the harness to handle it.
		// For now, we'll just extract technologies which are root nodes.

		// Extract technologies
		if techArr, ok := resultMap["technologies"].([]any); ok {
			for _, t := range techArr {
				if techName, ok := t.(string); ok && techName != "" {
					// Technology requires both name and version as identifying properties
					// If we don't have version, use "unknown" to satisfy the requirement
					tech := &domain.Technology{
						Name:    techName,
						Version: "unknown",
					}
					discoveries.Technologies = append(discoveries.Technologies, tech)
				}
			}
		}
	}
}

// parseProbeOutputProto parses httpx proto response and extracts endpoints and technologies.
func parseProbeOutputProto(resp *toolspb.HttpxResponse, discoveries *domain.DiscoveryResult) {
	if resp == nil {
		return
	}

	for _, result := range resp.Results {
		if result.Url == "" {
			continue
		}

		// Extract technologies
		for _, tech := range result.Technologies {
			if tech.Name == "" {
				continue
			}

			// Use version from proto, or "unknown" if empty
			version := tech.Version
			if version == "" {
				version = "unknown"
			}

			technology := &domain.Technology{
				Name:    tech.Name,
				Version: version,
			}
			discoveries.Technologies = append(discoveries.Technologies, technology)
		}
	}
}

// parseDomainOutput parses subfinder/amass output and extracts subdomains.
// Expected format: {"subdomains": ["sub1.example.com", "sub2.example.com"]} or {"results": [...]}
func parseDomainOutput(output any, parentDomain string, discoveries *domain.DiscoveryResult) {
	if output == nil {
		return
	}

	outputMap, ok := output.(map[string]any)
	if !ok {
		return
	}

	// Try multiple field names (subfinder uses "subdomains", amass might use "results")
	var subdomains []string

	if subArr, ok := outputMap["subdomains"].([]any); ok {
		for _, s := range subArr {
			if subName, ok := s.(string); ok && subName != "" {
				subdomains = append(subdomains, subName)
			}
		}
	} else if resultsArr, ok := outputMap["results"].([]any); ok {
		for _, r := range resultsArr {
			if subName, ok := r.(string); ok && subName != "" {
				subdomains = append(subdomains, subName)
			}
		}
	}

	// Create subdomain nodes
	for _, subName := range subdomains {
		subdomain := &domain.Subdomain{
			ParentDomain: parentDomain,
			Name:         subName,
			Status:       "active",
		}
		discoveries.Subdomains = append(discoveries.Subdomains, subdomain)
	}
}

// Helper functions to safely extract fields from maps

func getStringField(m map[string]any, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getIntField(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}
