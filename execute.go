package main

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
)

// executeRecon is the main execution function for the network-recon agent.
// It performs autonomous LLM-driven network reconnaissance in an iterative discovery loop.
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
		"target", cfg.Target,
		"max_iterations", cfg.MaxIterations,
		"timeout", cfg.Timeout,
		"verbose", cfg.Verbose,
	)

	// Start timing
	startTime := time.Now()

	// Phase 1: Initialize Working Memory with iteration state
	logger.InfoContext(ctx, "initializing working memory")
	h.Memory().Working().Set(ctx, "iteration", 0)
	h.Memory().Working().Set(ctx, "current_hypothesis", "Initial reconnaissance")
	h.Memory().Working().Set(ctx, "scan_history", []ScanSummary{})
	h.Memory().Working().Set(ctx, "pending_targets", []string{cfg.Target})
	h.Memory().Working().Set(ctx, "total_hosts", 0)
	h.Memory().Working().Set(ctx, "total_ports", 0)
	h.Memory().Working().Set(ctx, "total_services", 0)

	// Phase 2: Analyze target with LLM
	logger.InfoContext(ctx, "analyzing target", "target", cfg.Target)
	targetAnalysis, err := analyzeTarget(ctx, h, cfg.Target)
	if err != nil {
		logger.ErrorContext(ctx, "target analysis failed", "error", err)
		return agent.NewFailedResult(err), nil
	}

	logger.InfoContext(ctx, "target analysis complete",
		"type", targetAnalysis.TargetType,
		"network", targetAnalysis.NetworkType,
		"size", targetAnalysis.SizeEstimate,
	)

	// Phase 3: Autonomous discovery loop
	logger.InfoContext(ctx, "starting autonomous discovery loop", "max_iterations", cfg.MaxIterations)

	for {
		// Get current iteration from Working Memory
		iterationVal, _ := h.Memory().Working().Get(ctx, "iteration")
		iteration := toInt(iterationVal)

		logger.InfoContext(ctx, "loop iteration starting", "iteration", iteration)

		// Check if max iterations reached
		if iteration >= cfg.MaxIterations {
			logger.InfoContext(ctx, "max iterations reached, stopping loop",
				"iteration", iteration,
				"max", cfg.MaxIterations,
			)
			break
		}

		// Step 3a: Call planNextScan() to get ScanPlan from LLM
		logger.InfoContext(ctx, "planning next scan", "iteration", iteration)
		plan, err := planNextScan(ctx, h)
		if err != nil {
			logger.ErrorContext(ctx, "scan planning failed", "error", err)
			return agent.NewFailedResult(err), nil
		}

		logger.InfoContext(ctx, "scan plan created",
			"should_continue", plan.ShouldContinue,
			"reasoning", plan.Reasoning,
			"targets", plan.Targets,
			"args", plan.Args,
		)

		// Step 3b: Check if LLM decided to stop
		if !plan.ShouldContinue {
			logger.InfoContext(ctx, "LLM decided to stop scanning",
				"iteration", iteration,
				"reasoning", plan.Reasoning,
			)
			break
		}

		// Step 3c: Execute nmap scan via harness.CallToolProto
		logger.InfoContext(ctx, "executing nmap scan",
			"iteration", iteration,
			"targets", plan.Targets,
			"args", plan.Args,
		)

		nmapRequest := &toolspb.NmapRequest{
			Targets: plan.Targets,
			Args:    plan.Args,
		}

		nmapResponse := &toolspb.NmapResponse{}
		err = h.CallToolProto(ctx, "nmap", nmapRequest, nmapResponse)
		if err != nil {
			logger.ErrorContext(ctx, "nmap scan failed",
				"iteration", iteration,
				"error", err,
			)
			// Continue to next iteration even if scan fails
			h.Memory().Working().Set(ctx, "iteration", iteration+1)
			continue
		}

		logger.InfoContext(ctx, "nmap scan complete",
			"iteration", iteration,
			"hosts_found", nmapResponse.TotalHosts,
			"hosts_up", nmapResponse.HostsUp,
			"duration", nmapResponse.ScanDuration,
		)

		// Step 3d: Store discoveries to Neo4j via storeNodes()
		logger.InfoContext(ctx, "storing discoveries to Neo4j",
			"iteration", iteration,
			"hosts", len(nmapResponse.Hosts),
		)

		storeNodes(ctx, h, nmapResponse)

		// Update totals in Working Memory
		totalHostsVal, _ := h.Memory().Working().Get(ctx, "total_hosts")
		totalPortsVal, _ := h.Memory().Working().Get(ctx, "total_ports")
		totalServicesVal, _ := h.Memory().Working().Get(ctx, "total_services")

		hostsCount := len(nmapResponse.Hosts)
		portsCount := countPorts(nmapResponse)
		servicesCount := countServices(nmapResponse)

		h.Memory().Working().Set(ctx, "total_hosts", toInt(totalHostsVal)+hostsCount)
		h.Memory().Working().Set(ctx, "total_ports", toInt(totalPortsVal)+portsCount)
		h.Memory().Working().Set(ctx, "total_services", toInt(totalServicesVal)+servicesCount)

		// Step 3e: Build scan summary for intelligence analysis
		notable := extractNotableFindings(nmapResponse)
		summary := ScanSummary{
			Iteration:  iteration,
			Target:     formatTargets(plan.Targets),
			Args:       plan.Args,
			HostsUp:    int(nmapResponse.HostsUp),
			PortsFound: countPorts(nmapResponse),
			Notable:    notable,
		}

		// Analyze scan results and attach intelligence to nodes
		logger.InfoContext(ctx, "analyzing scan results for intelligence",
			"iteration", iteration,
		)

		intelAnalysis, err := analyzeAndAttachIntel(ctx, h, summary)
		if err != nil {
			logger.WarnContext(ctx, "intelligence analysis failed", "error", err)
			// Non-fatal - continue even if intel fails
		} else {
			logger.InfoContext(ctx, "intelligence analysis complete",
				"iteration", iteration,
				"findings", len(intelAnalysis.Findings),
				"hypothesis", intelAnalysis.NewHypothesis,
			)
		}

		// Step 3f: Add scan summary to history
		historyVal, _ := h.Memory().Working().Get(ctx, "scan_history")
		history := toScanHistory(historyVal)
		history = append(history, summary)
		h.Memory().Working().Set(ctx, "scan_history", history)

		// Step 3g: Increment iteration counter
		h.Memory().Working().Set(ctx, "iteration", iteration+1)

		logger.InfoContext(ctx, "loop iteration complete",
			"iteration", iteration,
			"next_iteration", iteration+1,
		)
	}

	// Phase 4: Generate final summary
	duration := time.Since(startTime)
	logger.InfoContext(ctx, "discovery loop complete, generating summary",
		"duration", duration,
	)

	// Get final stats from Working Memory
	totalHostsVal, _ := h.Memory().Working().Get(ctx, "total_hosts")
	totalPortsVal, _ := h.Memory().Working().Get(ctx, "total_ports")
	totalServicesVal, _ := h.Memory().Working().Get(ctx, "total_services")
	historyVal, _ := h.Memory().Working().Get(ctx, "scan_history")

	totalHosts := toInt(totalHostsVal)
	totalPorts := toInt(totalPortsVal)
	totalServices := toInt(totalServicesVal)
	history := toScanHistory(historyVal)

	// Build metadata
	metadata := map[string]any{
		"target":              cfg.Target,
		"iterations":          len(history),
		"max_iterations":      cfg.MaxIterations,
		"hosts_discovered":    totalHosts,
		"ports_discovered":    totalPorts,
		"services_discovered": totalServices,
		"duration":            duration.String(),
		"scan_history":        history,
	}

	logger.InfoContext(ctx, "reconnaissance complete",
		"target", cfg.Target,
		"iterations", len(history),
		"total_hosts", totalHosts,
		"total_ports", totalPorts,
		"total_services", totalServices,
		"duration", duration,
	)

	// Return success with metadata
	return agent.Result{
		Status:   agent.StatusSuccess,
		Output:   metadata,
		Metadata: metadata,
	}, nil
}

// Helper functions

// toInt converts an interface{} to int, handling int, int64, float64
func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	default:
		return 0
	}
}

// toScanHistory converts an interface{} to []ScanSummary
func toScanHistory(v any) []ScanSummary {
	if v == nil {
		return []ScanSummary{}
	}
	if history, ok := v.([]ScanSummary); ok {
		return history
	}
	// If stored as []any, convert each element
	if arr, ok := v.([]any); ok {
		history := make([]ScanSummary, 0, len(arr))
		for _, item := range arr {
			if m, ok := item.(map[string]any); ok {
				summary := ScanSummary{
					Iteration:  toInt(m["Iteration"]),
					Target:     toString(m["Target"]),
					HostsUp:    toInt(m["HostsUp"]),
					PortsFound: toInt(m["PortsFound"]),
				}
				if args, ok := m["Args"].([]any); ok {
					for _, a := range args {
						if s, ok := a.(string); ok {
							summary.Args = append(summary.Args, s)
						}
					}
				}
				if notable, ok := m["Notable"].([]any); ok {
					for _, n := range notable {
						if s, ok := n.(string); ok {
							summary.Notable = append(summary.Notable, s)
						}
					}
				}
				history = append(history, summary)
			}
		}
		return history
	}
	return []ScanSummary{}
}

// toString converts an interface{} to string
func toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func formatTargets(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	if len(targets) == 1 {
		return targets[0]
	}
	return fmt.Sprintf("%s (+%d more)", targets[0], len(targets)-1)
}

func countPorts(resp *toolspb.NmapResponse) int {
	count := 0
	for _, host := range resp.Hosts {
		count += len(host.Ports)
	}
	return count
}

func countServices(resp *toolspb.NmapResponse) int {
	count := 0
	for _, host := range resp.Hosts {
		for _, port := range host.Ports {
			if port.Service != nil {
				count++
			}
		}
	}
	return count
}

func extractNotableFindings(resp *toolspb.NmapResponse) []string {
	notable := []string{}

	// Count services by name
	serviceCounts := make(map[string]int)
	for _, host := range resp.Hosts {
		for _, port := range host.Ports {
			if port.Service != nil {
				serviceCounts[port.Service.Name]++
			}
		}
	}

	// Build notable list
	for service, count := range serviceCounts {
		if count > 0 {
			notable = append(notable, fmt.Sprintf("%s on %d host(s)", service, count))
		}
	}

	return notable
}
