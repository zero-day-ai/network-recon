// Package recon provides reconnaissance orchestration capabilities for the network-recon agent.
//
// This package coordinates the execution of network reconnaissance tools through multiple phases
// (discover, probe, domain) and extracts structured entities from tool outputs into the
// knowledge graph via GraphRAG taxonomy mappings. The reconnaissance runner orchestrates tool
// execution through the agent harness, ensuring proper sequencing, error handling, and result
// aggregation across the reconnaissance lifecycle.
//
// Note: This agent focuses on network discovery only - no vulnerability scanning (nuclei).
// Vulnerability scanning should be handled by a dedicated scan agent.
package recon

import (
	"context"
	"time"

	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
)

// Phase represents a distinct stage in the reconnaissance lifecycle.
// Each phase executes specific tools and produces typed entities in the knowledge graph.
type Phase string

const (
	// PhaseDiscover performs host and port discovery using network scanning tools.
	// Tools: nmap, masscan
	// Entities: host, port nodes with HAS_PORT relationships
	PhaseDiscover Phase = "discover"

	// PhaseProbe performs HTTP endpoint probing and technology detection.
	// Tools: httpx
	// Entities: endpoint, technology nodes with EXPOSES, USES_TECHNOLOGY relationships
	PhaseProbe Phase = "probe"

	// PhaseDomain performs domain and subdomain enumeration.
	// Tools: subfinder, amass
	// Entities: domain, subdomain nodes with DNS-related relationships
	PhaseDomain Phase = "domain"
)

// ReconRunner defines the interface for orchestrating reconnaissance operations across multiple phases.
// Implementations coordinate tool execution via the agent harness, extract taxonomy-based entities
// from tool outputs, and populate the knowledge graph with discovered hosts, ports, endpoints,
// technologies, and domain information.
type ReconRunner interface {
	// RunPhase executes a single reconnaissance phase with the specified targets.
	// The phase determines which tools are executed (discover uses nmap/masscan,
	// probe uses httpx, domain uses subfinder/amass).
	//
	// Targets are phase-specific:
	// - discover: CIDR ranges (e.g., ["192.168.1.0/24"])
	// - probe: URLs or host:port pairs (e.g., ["http://192.168.1.10:8080"])
	// - domain: Domain names (e.g., ["example.local"])
	//
	// Returns a PhaseResult containing execution statistics, created entities, and any errors.
	// Errors from individual tools do not halt phase execution; all tool failures are collected
	// in the result's Errors slice.
	//
	// The implementation uses agent.Harness.CallTool() for all tool execution and
	// agent.Harness.GraphRAGStore() to persist extracted entities.
	RunPhase(ctx context.Context, phase Phase, targets []string) (*PhaseResult, error)

	// RunAll executes all reconnaissance phases in sequence: discover → probe → domain.
	// This provides a complete reconnaissance workflow where later phases use outputs from
	// earlier phases as inputs (e.g., probe uses hosts/ports from discover).
	//
	// The subnet parameter is the CIDR range for initial host discovery (e.g., "192.168.1.0/24").
	// The domains parameter is a list of domain names for enumeration (e.g., ["example.local"]).
	//
	// Returns a ReconResult aggregating statistics from all phases including total hosts discovered,
	// ports identified, HTTP endpoints probed, and overall execution duration.
	//
	// Phase failures do not halt the workflow; subsequent phases execute with available data.
	// All phase-level errors are collected in the individual PhaseResult structures.
	RunAll(ctx context.Context, subnet string, domains []string) (*ReconResult, error)
}

// PhaseResult contains the execution results and statistics for a single reconnaissance phase.
// This structure provides detailed metrics about tool execution, entity creation, and any
// errors encountered during the phase.
type PhaseResult struct {
	// Phase identifies which reconnaissance phase produced this result.
	Phase Phase

	// ToolsRun lists the names of all tools that were executed during this phase.
	// Example: ["nmap", "masscan"] for PhaseDiscover
	ToolsRun []string

	// NodesCreated is the count of knowledge graph nodes created from this phase's tool outputs.
	// This includes all node types (host, port, endpoint, technology, domain, subdomain).
	NodesCreated int

	// RelationsCreated is the count of knowledge graph relationships created from this phase's
	// tool outputs. This includes relationships like HAS_PORT, EXPOSES, USES_TECHNOLOGY.
	RelationsCreated int

	// Duration is the total wall-clock time taken to execute all tools in this phase.
	// This includes tool execution time, output parsing, and knowledge graph storage operations.
	Duration time.Duration

	// Errors contains all errors encountered during tool execution or entity extraction.
	// Individual tool failures are non-fatal; the phase continues with remaining tools.
	// A nil or empty Errors slice indicates complete success.
	Errors []error

	// Discoveries contains the proto types discovered in this phase.
	// This is aggregated into the overall ReconResult.Discoveries.
	Discoveries *graphragpb.DiscoveryResult
}

// ReconResult contains aggregated results and statistics for a complete reconnaissance operation
// spanning multiple phases. This structure provides a comprehensive view of the reconnaissance
// outcome including entity counts and execution metrics.
type ReconResult struct {
	// Phases contains the individual results for each executed phase in execution order.
	// This allows inspection of phase-specific outcomes and errors.
	Phases []*PhaseResult

	// TotalHosts is the count of unique host nodes discovered across all phases.
	// Derived from PhaseDiscover tool outputs (nmap, masscan).
	TotalHosts int

	// TotalPorts is the count of unique port nodes discovered across all phases.
	// Derived from PhaseDiscover tool outputs showing open ports on discovered hosts.
	TotalPorts int

	// TotalEndpoints is the count of unique HTTP/HTTPS endpoint nodes discovered.
	// Derived from PhaseProbe tool outputs (httpx) showing accessible web services.
	TotalEndpoints int

	// Duration is the total wall-clock time for the complete reconnaissance operation.
	// This is the sum of all phase durations plus inter-phase coordination overhead.
	Duration time.Duration

	// Discoveries contains all discovered assets as proto types.
	// This is returned to Gibson's harness for automatic graph node creation.
	Discoveries *graphragpb.DiscoveryResult
}
