package main

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/agent"
)

// ReconConfig holds configuration for network reconnaissance execution
type ReconConfig struct {
	// Network targeting
	Subnet  string   // CIDR notation, auto-discovered if empty
	Domains []string // Domain names, from /etc/hosts if empty

	// Phase control
	SkipPhases []string // Phases to skip: "discover", "probe", "domain"

	// Intelligence
	GenerateIntelligence bool // Run LLM analysis after recon

	// Limits
	MaxHosts    int           // Max hosts to scan
	ScanTimeout time.Duration // Per-phase timeout

	// Safety
	DemoMode bool // Skip actual network calls for testing

	// Output
	Verbose bool
}

// DefaultReconConfig returns a ReconConfig with sensible defaults
func DefaultReconConfig() *ReconConfig {
	return &ReconConfig{
		Subnet:               "", // Auto-discover if empty
		Domains:              []string{},
		SkipPhases:           []string{},
		GenerateIntelligence: true,
		MaxHosts:             25,
		ScanTimeout:          5 * time.Minute,
		DemoMode:             false,
		Verbose:              false,
	}
}

// ParseConfig extracts configuration from the agent task context
func ParseConfig(task agent.Task) (*ReconConfig, error) {
	cfg := DefaultReconConfig()

	// Merge Context and Metadata - Context takes precedence (from workflow YAML)
	configMap := make(map[string]any)
	for k, v := range task.Metadata {
		configMap[k] = v
	}
	for k, v := range task.Context {
		configMap[k] = v
	}

	// Parse configuration from merged map
	if len(configMap) == 0 {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	// Parse subnet
	if subnet, ok := configMap["subnet"].(string); ok {
		cfg.Subnet = subnet
	}

	// Parse domains
	if domains, ok := configMap["domains"].([]interface{}); ok {
		cfg.Domains = make([]string, 0, len(domains))
		for _, domain := range domains {
			if domainName, ok := domain.(string); ok {
				cfg.Domains = append(cfg.Domains, domainName)
			}
		}
	}

	// Parse skip_phases
	if skipPhases, ok := configMap["skip_phases"].([]interface{}); ok {
		cfg.SkipPhases = make([]string, 0, len(skipPhases))
		for _, phase := range skipPhases {
			if phaseName, ok := phase.(string); ok {
				cfg.SkipPhases = append(cfg.SkipPhases, phaseName)
			}
		}
	}

	// Parse generate_intelligence
	if generateIntel, ok := configMap["generate_intelligence"].(bool); ok {
		cfg.GenerateIntelligence = generateIntel
	}

	// Parse max_hosts
	if maxHosts, ok := configMap["max_hosts"].(int); ok {
		cfg.MaxHosts = maxHosts
	} else if maxHostsFloat, ok := configMap["max_hosts"].(float64); ok {
		cfg.MaxHosts = int(maxHostsFloat)
	}

	// Parse scan_timeout
	if timeout, ok := configMap["scan_timeout"].(string); ok {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.ScanTimeout = d
		} else {
			return nil, fmt.Errorf("invalid scan_timeout duration: %s", timeout)
		}
	}

	// Parse demo_mode
	if demoMode, ok := configMap["demo_mode"].(bool); ok {
		cfg.DemoMode = demoMode
	}

	// Parse verbose
	if verbose, ok := configMap["verbose"].(bool); ok {
		cfg.Verbose = verbose
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks if the configuration is valid
func (c *ReconConfig) Validate() error {
	// Validate skip_phases contains only valid phase names
	validPhases := map[string]bool{
		"discover": true,
		"probe":    true,
		"domain":   true,
	}
	for _, phase := range c.SkipPhases {
		if !validPhases[phase] {
			return fmt.Errorf("invalid phase name in skip_phases: %s (must be: discover, probe, or domain)", phase)
		}
	}

	// Validate max_hosts
	if c.MaxHosts <= 0 {
		return fmt.Errorf("max_hosts must be positive, got %d", c.MaxHosts)
	}

	// Validate scan_timeout
	if c.ScanTimeout <= 0 {
		return fmt.Errorf("scan_timeout must be positive, got %v", c.ScanTimeout)
	}

	return nil
}

// ShouldRunPhase returns true if the given reconnaissance phase should be run
func (c *ReconConfig) ShouldRunPhase(phase string) bool {
	for _, skip := range c.SkipPhases {
		if skip == phase {
			return false
		}
	}
	return true
}

// String returns a human-readable representation of the configuration
func (c *ReconConfig) String() string {
	return fmt.Sprintf("ReconConfig{subnet=%s, domains=%d, max_hosts=%d, verbose=%v}",
		c.Subnet, len(c.Domains), c.MaxHosts, c.Verbose)
}
