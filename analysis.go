package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/llm"
)

// convertStructuredResult converts the map[string]interface{} result from CompleteStructured
// to the target struct type using JSON marshaling/unmarshaling
func convertStructuredResult[T any](result any) (*T, error) {
	// Marshal the map to JSON
	jsonBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	// Unmarshal to the target type
	var target T
	if err := json.Unmarshal(jsonBytes, &target); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to target type: %w", err)
	}

	return &target, nil
}

// Type conversion helpers for Working Memory values

func toIntFromAny(v any) int {
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

func toStringFromAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toStringSliceFromAny(v any) []string {
	if v == nil {
		return []string{}
	}
	if slice, ok := v.([]string); ok {
		return slice
	}
	if arr, ok := v.([]any); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return []string{}
}

func toScanHistoryFromAny(v any) []ScanSummary {
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
					Iteration:  toIntFromAny(m["Iteration"]),
					Target:     toStringFromAny(m["Target"]),
					HostsUp:    toIntFromAny(m["HostsUp"]),
					PortsFound: toIntFromAny(m["PortsFound"]),
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

// analyzeTarget uses LLM to analyze the target and determine scan approach
func analyzeTarget(ctx context.Context, h agent.Harness, target string) (*TargetAnalysis, error) {
	logger := h.Logger()

	// Query Long-Term Memory for relevant patterns
	patterns, err := h.Memory().LongTerm().Search(ctx,
		fmt.Sprintf("network reconnaissance %s", target),
		3, // topK - return up to 3 results
		nil) // no filters

	patternContext := ""
	if err == nil && len(patterns) > 0 {
		var patternStrs []string
		for _, p := range patterns {
			// Convert Value to string representation
			var content string
			if str, ok := p.Value.(string); ok {
				content = str
			} else {
				content = fmt.Sprintf("%v", p.Value)
			}
			patternStrs = append(patternStrs, fmt.Sprintf("- %s", content))
		}
		patternContext = "Relevant patterns from previous missions:\n" + strings.Join(patternStrs, "\n")
	}

	// Build prompt
	messages := []llm.Message{
		{
			Role: llm.RoleSystem,
			Content: `You are a network reconnaissance expert. Analyze the target and provide recommendations for scanning approach.
Respond with a JSON object containing:
- target_type: "subnet", "single_host", "domain", or "ip_range"
- network_type: your hypothesis about the network ("corporate_lan", "iot", "cloud", "internet_facing", "unknown")
- size_estimate: "small (<10)", "medium (10-100)", or "large (>100)"
- recommendations: array of recommended scan approaches`,
		},
		{
			Role:    llm.RoleUser,
			Content: fmt.Sprintf("Target: %s\n\n%s\n\nAnalyze this target.", target, patternContext),
		},
	}

	// Call LLM with structured output
	result, err := h.CompleteStructured(ctx, "primary", messages, TargetAnalysis{})
	if err != nil {
		return nil, fmt.Errorf("LLM analysis failed: %w", err)
	}

	// Convert map result to struct
	analysis, err := convertStructuredResult[TargetAnalysis](result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert LLM result: %w", err)
	}

	logger.InfoContext(ctx, "target analysis complete",
		"target", target,
		"type", analysis.TargetType,
		"network", analysis.NetworkType,
		"size", analysis.SizeEstimate,
	)

	// Store in Mission Memory
	err = h.Memory().Mission().Set(ctx, "target_analysis", analysis, nil)
	if err != nil {
		logger.WarnContext(ctx, "failed to store target analysis in mission memory", "error", err)
	}

	return analysis, nil
}

// planNextScan uses LLM to decide the next scan based on current knowledge
func planNextScan(ctx context.Context, h agent.Harness) (*ScanPlan, error) {
	logger := h.Logger()

	// Get context from Working Memory
	iterationVal, _ := h.Memory().Working().Get(ctx, "iteration")
	iteration := toIntFromAny(iterationVal)

	historyVal, _ := h.Memory().Working().Get(ctx, "scan_history")
	history := toScanHistoryFromAny(historyVal)

	hypothesisVal, _ := h.Memory().Working().Get(ctx, "current_hypothesis")
	hypothesis := toStringFromAny(hypothesisVal)

	pendingVal, _ := h.Memory().Working().Get(ctx, "pending_targets")
	pending := toStringSliceFromAny(pendingVal)

	// Get target analysis from Mission Memory
	analysisItem, _ := h.Memory().Mission().Get(ctx, "target_analysis")
	var analysis *TargetAnalysis
	if analysisItem != nil && analysisItem.Value != nil {
		// Convert from stored map back to struct
		analysis, _ = convertStructuredResult[TargetAnalysis](analysisItem.Value)
	}

	// Format history for prompt (keep compact)
	historyStr := formatScanHistory(history)

	// Build prompt
	messages := []llm.Message{
		{
			Role: llm.RoleSystem,
			Content: `You are planning network reconnaissance scans.
Based on what has been discovered, decide the next scan or if reconnaissance is complete.

Respond with JSON:
- should_continue: true/false
- reasoning: explain your decision
- targets: array of targets for next scan (if continuing)
- args: array of nmap arguments (if continuing)

Consider:
- What has already been scanned
- What information gaps remain
- Whether enough has been discovered`,
		},
		{
			Role: llm.RoleUser,
			Content: fmt.Sprintf(`Iteration: %d
Target Analysis: %+v
Scan History:
%s
Pending Targets: %v
Current Hypothesis: %s

What should we do next?`, iteration, analysis, historyStr, pending, hypothesis),
		},
	}

	// Call LLM
	result, err := h.CompleteStructured(ctx, "primary", messages, ScanPlan{})
	if err != nil {
		return nil, fmt.Errorf("scan planning failed: %w", err)
	}

	// Convert map result to struct
	plan, err := convertStructuredResult[ScanPlan](result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert LLM result: %w", err)
	}

	logger.InfoContext(ctx, "scan plan created",
		"should_continue", plan.ShouldContinue,
		"reasoning", plan.Reasoning,
		"targets", plan.Targets,
		"args", plan.Args,
	)

	return plan, nil
}

// formatScanHistory creates a compact string representation of scan history
func formatScanHistory(history []ScanSummary) string {
	if len(history) == 0 {
		return "No previous scans"
	}

	var lines []string
	for _, s := range history {
		lines = append(lines, fmt.Sprintf("- Iter %d: %s with %v -> %d hosts, %d ports. Notable: %v",
			s.Iteration, s.Target, s.Args, s.HostsUp, s.PortsFound, s.Notable))
	}
	return strings.Join(lines, "\n")
}

// analyzeAndAttachIntel uses LLM to analyze scan results and attach risk intelligence to discovered nodes
func analyzeAndAttachIntel(ctx context.Context, h agent.Harness, summary ScanSummary) (*IntelAnalysis, error) {
	logger := h.Logger()

	// Format summary for LLM (keep compact to minimize token usage)
	summaryStr := fmt.Sprintf(`Scan Results Summary:
Target: %s
Scan Args: %v
Hosts Up: %d
Ports Found: %d
Notable Findings: %v`, summary.Target, summary.Args, summary.HostsUp, summary.PortsFound, summary.Notable)

	// Get current hypothesis from Working Memory for context
	hypothesisVal, _ := h.Memory().Working().Get(ctx, "current_hypothesis")
	hypothesis := toStringFromAny(hypothesisVal)

	// Build prompt
	messages := []llm.Message{
		{
			Role: llm.RoleSystem,
			Content: `You are a network security analyst. Analyze scan results and provide risk intelligence.

Respond with JSON containing:
- findings: array of NodeIntel objects with:
  - node_type: "host", "port", or "service"
  - identifier: IP address, port number, or service name
  - risk_level: "critical", "high", "medium", "low", or "info"
  - risk_reasons: array of strings explaining the risk
  - notes: additional observations
- new_hypothesis: updated hypothesis about the network (build on previous if provided)
- learned_patterns: array of generalizable security patterns (NOT target-specific IPs/hostnames)

For learned_patterns, focus on generalizable observations like:
- "SSH on non-standard ports often indicates security-conscious configuration"
- "Multiple HTTP services suggest web application infrastructure"
- "Clusters of open ports 8080-8090 indicate microservices architecture"

Do NOT include target-specific patterns like:
- "192.168.1.100 has SSH open"
- "example.com uses Nginx"`,
		},
		{
			Role:    llm.RoleUser,
			Content: fmt.Sprintf("%s\n\nCurrent Hypothesis: %s\n\nAnalyze these results.", summaryStr, hypothesis),
		},
	}

	// Call LLM with structured output
	result, err := h.CompleteStructured(ctx, "primary", messages, IntelAnalysis{})
	if err != nil {
		logger.ErrorContext(ctx, "LLM analysis failed for scan intelligence",
			"target", summary.Target,
			"error", err,
		)
		return nil, fmt.Errorf("intelligence analysis failed: %w", err)
	}

	// Convert map result to struct
	intel, err := convertStructuredResult[IntelAnalysis](result)
	if err != nil {
		return nil, fmt.Errorf("failed to convert LLM result: %w", err)
	}

	logger.InfoContext(ctx, "intelligence analysis complete",
		"target", summary.Target,
		"findings_count", len(intel.Findings),
		"patterns_count", len(intel.LearnedPatterns),
		"new_hypothesis", intel.NewHypothesis,
	)

	// Update Working Memory with new hypothesis
	if intel.NewHypothesis != "" {
		err = h.Memory().Working().Set(ctx, "current_hypothesis", intel.NewHypothesis)
		if err != nil {
			logger.WarnContext(ctx, "failed to update hypothesis in working memory", "error", err)
		}
	}

	// Store generalizable patterns in Long-Term Memory
	for _, pattern := range intel.LearnedPatterns {
		if pattern == "" {
			continue
		}

		// Store pattern with metadata for semantic search
		metadata := map[string]any{
			"type":      "security_pattern",
			"source":    "network-recon",
			"target":    summary.Target, // Context, but pattern itself is generalizable
			"timestamp": fmt.Sprintf("%d", summary.Iteration),
		}

		id, err := h.Memory().LongTerm().Store(ctx, pattern, metadata)
		if err != nil {
			logger.WarnContext(ctx, "failed to store pattern in long-term memory",
				"pattern", pattern,
				"error", err,
			)
			// Continue with other patterns
		} else {
			logger.InfoContext(ctx, "stored generalizable pattern in long-term memory",
				"pattern", pattern,
				"id", id,
			)
		}
	}

	logger.InfoContext(ctx, "intelligence analysis complete",
		"findings", len(intel.Findings),
		"stored_patterns", len(intel.LearnedPatterns),
	)

	return intel, nil
}
