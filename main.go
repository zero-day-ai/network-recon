package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	sdk "github.com/zero-day-ai/sdk"
	"github.com/zero-day-ai/sdk/llm"
	"github.com/zero-day-ai/sdk/serve"
)

const (
	agentName    = "network-recon"
	agentVersion = "1.0.0"
)

func main() {
	fmt.Printf("Gibson Network Recon Agent v%s\n\n", agentVersion)

	// Create the network-recon agent using SDK builder pattern
	reconAgent, err := sdk.NewAgent(
		// Basic metadata
		sdk.WithName(agentName),
		sdk.WithVersion(agentVersion),
		sdk.WithDescription("Network reconnaissance agent that discovers hosts, services, and technologies "+
			"on target networks. Performs host discovery, port scanning, HTTP probing, and domain enumeration. "+
			"Writes all discoveries to the GraphRAG knowledge graph."),

		// Target types
		sdk.WithTargetTypes(
			"network",
			"subnet",
			"domain",
		),

		// Agent capabilities
		sdk.WithCapabilities(
			"host-discovery",
			"port-scanning",
			"service-detection",
			"technology-fingerprinting",
			"domain-enumeration",
		),

		// LLM Slot - optional, only needed for intelligence generation
		sdk.WithLLMSlot("primary", llm.SlotRequirements{
			MinContextWindow: 8000,
			RequiredFeatures: []string{},
			PreferredModels:  []string{"claude-sonnet-4-5-20250929", "gpt-4o-mini"},
		}),

		// Execution function
		sdk.WithExecuteFunc(executeRecon),
	)
	if err != nil {
		log.Fatalf("Failed to create network-recon agent: %v", err)
	}

	// Parse command line flags
	// Gibson CLI passes --port flag when starting agents
	portFlag := flag.Int("port", 0, "Port to listen on (passed by Gibson CLI)")
	flag.Parse()

	// Determine port: CLI flag > environment variable > default
	port := 50051
	if *portFlag > 0 {
		port = *portFlag
	} else if portEnv := os.Getenv("AGENT_PORT"); portEnv != "" {
		fmt.Sscanf(portEnv, "%d", &port)
	}

	// Build serve options
	opts := []serve.Option{
		serve.WithPort(port),
		serve.WithGracefulShutdown(5 * time.Second),
		serve.WithRegistryFromEnv(), // Auto-register with etcd if GIBSON_REGISTRY_ENDPOINTS is set
	}

	fmt.Printf("Starting network-recon v%s on port %d...\n", agentVersion, port)

	// Serve the agent as a gRPC service
	if err := serve.Agent(reconAgent, opts...); err != nil {
		log.Fatalf("Failed to serve agent: %v", err)
	}
}
