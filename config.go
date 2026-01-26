package main

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/agent"
)

// ReconConfig holds configuration for network reconnaissance execution
type ReconConfig struct {
	// Target specifies what to scan (CIDR notation, IP range, or hostname)
	Target string

	// MaxIterations limits the number of autonomous loop iterations
	MaxIterations int

	// Timeout is the overall execution timeout for the agent
	Timeout time.Duration

	// Verbose enables detailed logging output
	Verbose bool
}

// DefaultReconConfig returns a ReconConfig with sensible defaults
func DefaultReconConfig() *ReconConfig {
	return &ReconConfig{
		Target:        "", // Must be provided by user
		MaxIterations: 10,
		Timeout:       30 * time.Minute,
		Verbose:       false,
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

	// If no config provided, validate and return defaults
	if len(configMap) == 0 {
		if err := cfg.Validate(); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	// Parse target (with backward compatibility for "subnet")
	if target, ok := configMap["target"].(string); ok {
		cfg.Target = target
	} else if subnet, ok := configMap["subnet"].(string); ok {
		// Backward compatibility: accept "subnet" as alias for "target"
		cfg.Target = subnet
	}

	// Parse max_iterations
	if maxIter, ok := configMap["max_iterations"].(int); ok {
		cfg.MaxIterations = maxIter
	} else if maxIterFloat, ok := configMap["max_iterations"].(float64); ok {
		cfg.MaxIterations = int(maxIterFloat)
	}

	// Parse timeout
	if timeout, ok := configMap["timeout"].(string); ok {
		if d, err := time.ParseDuration(timeout); err == nil {
			cfg.Timeout = d
		} else {
			return nil, fmt.Errorf("invalid timeout duration: %s", timeout)
		}
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
	// Target is required
	if c.Target == "" {
		return fmt.Errorf("target is required (specify target subnet, IP range, or hostname)")
	}

	// Validate MaxIterations is positive
	if c.MaxIterations <= 0 {
		return fmt.Errorf("max_iterations must be positive, got %d", c.MaxIterations)
	}

	// Validate Timeout is positive
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %v", c.Timeout)
	}

	return nil
}

// String returns a human-readable representation of the configuration
func (c *ReconConfig) String() string {
	return fmt.Sprintf("ReconConfig{target=%s, max_iterations=%d, timeout=%v, verbose=%v}",
		c.Target, c.MaxIterations, c.Timeout, c.Verbose)
}
