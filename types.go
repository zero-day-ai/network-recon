package main

// TargetAnalysis is returned by LLM after analyzing the target
type TargetAnalysis struct {
	TargetType      string   `json:"target_type"`     // "subnet", "single_host", "domain", "ip_range"
	NetworkType     string   `json:"network_type"`    // "corporate_lan", "iot", "cloud", "internet_facing", "unknown"
	SizeEstimate    string   `json:"size_estimate"`   // "small (<10)", "medium (10-100)", "large (>100)"
	Recommendations []string `json:"recommendations"` // Initial scan recommendations
}

// ScanPlan is returned by LLM when planning the next scan
type ScanPlan struct {
	ShouldContinue bool     `json:"should_continue"` // Whether to continue scanning
	Reasoning      string   `json:"reasoning"`       // Explanation of the decision
	Targets        []string `json:"targets"`         // Targets for next scan
	Args           []string `json:"args"`            // Nmap arguments for next scan
}

// ScanSummary is a compact representation for LLM context
type ScanSummary struct {
	Iteration  int      `json:"iteration"`
	Target     string   `json:"target"`
	Args       []string `json:"args"`
	HostsUp    int      `json:"hosts_up"`
	PortsFound int      `json:"ports_found"`
	Notable    []string `json:"notable"` // e.g., ["SSH on 3 hosts", "HTTP on 5 hosts"]
}

// IntelAnalysis is returned by LLM after analyzing scan results
type IntelAnalysis struct {
	Findings        []NodeIntel `json:"findings"`
	NewHypothesis   string      `json:"new_hypothesis"`
	LearnedPatterns []string    `json:"learned_patterns"`
}

// NodeIntel represents intelligence to attach to a node
type NodeIntel struct {
	NodeType    string   `json:"node_type"`    // "host", "port", "service"
	Identifier  string   `json:"identifier"`   // IP, port ID, service ID
	RiskLevel   string   `json:"risk_level"`   // "critical", "high", "medium", "low", "info"
	RiskReasons []string `json:"risk_reasons"` // Why this risk level
	Notes       string   `json:"notes"`        // Additional observations
}
