package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/llm"
)

// DefaultIntelligenceGenerator is the production implementation of IntelligenceGenerator
// that uses the agent harness to query GraphRAG, invoke LLM completion, and store
// intelligence nodes in the knowledge graph.
type DefaultIntelligenceGenerator struct {
	// harness provides access to LLM, GraphRAG, and other SDK capabilities
	harness agent.Harness

	// llmSlot identifies which LLM slot to use for completions (typically "primary")
	llmSlot string
}

// NewIntelligenceGenerator creates a new DefaultIntelligenceGenerator.
// The harness parameter provides access to SDK capabilities (LLM, GraphRAG, logging).
// Uses "primary" as the default LLM slot.
func NewIntelligenceGenerator(harness agent.Harness) IntelligenceGenerator {
	return &DefaultIntelligenceGenerator{
		harness: harness,
		llmSlot: "primary", // Use primary LLM slot by default
	}
}

// NewIntelligenceGeneratorWithSlot creates a new DefaultIntelligenceGenerator
// with a custom LLM slot name.
func NewIntelligenceGeneratorWithSlot(harness agent.Harness, llmSlot string) IntelligenceGenerator {
	return &DefaultIntelligenceGenerator{
		harness: harness,
		llmSlot: llmSlot,
	}
}

// GenerateForPhase generates security intelligence for a specific reconnaissance phase.
// This method:
// 1. Queries the knowledge graph for phase-specific entities (hosts, ports, endpoints, findings)
// 2. Builds a prompt using BuildPhasePrompt() from prompts.go
// 3. Invokes LLM completion via harness.Complete()
// 4. Parses the response using ParseIntelligenceResponse()
// 5. Stores the intelligence node in the knowledge graph via harness.StoreGraphBatch()
// 6. Creates ANALYZES relationships to source nodes
// 7. Creates GENERATED_BY relationship to the LLM call
//
// Returns the Intelligence struct with all metadata populated, or an error if generation fails.
func (g *DefaultIntelligenceGenerator) GenerateForPhase(ctx context.Context, missionID string, phase string) (*Intelligence, error) {
	logger := g.harness.Logger()

	logger.Info("Generating intelligence for phase",
		"mission_id", missionID,
		"phase", phase,
	)

	// Step 1: Query knowledge graph for phase-specific entities
	entities, sourceNodeIDs, err := g.queryPhaseEntities(ctx, missionID, phase)
	if err != nil {
		return nil, fmt.Errorf("failed to query phase entities: %w", err)
	}

	logger.Info("Retrieved phase entities from knowledge graph",
		"phase", phase,
		"entity_count", len(sourceNodeIDs),
	)

	// Step 2: Build prompt using BuildPhasePrompt from prompts.go
	prompt, err := BuildPhasePrompt(phase, entities)
	if err != nil {
		return nil, fmt.Errorf("failed to build phase prompt: %w", err)
	}

	logger.Info("Built phase analysis prompt",
		"phase", phase,
		"prompt_length", len(prompt),
		"estimated_tokens", EstimatePromptTokens(prompt),
	)

	// Step 3: Invoke LLM completion
	messages := []llm.Message{
		{
			Role:    llm.RoleUser,
			Content: prompt,
		},
	}

	response, err := g.harness.Complete(ctx, g.llmSlot, messages)
	if err != nil {
		// LLM failure - return partial Intelligence with error
		logger.Error("LLM completion failed for phase intelligence",
			"phase", phase,
			"error", err,
		)
		return nil, fmt.Errorf("LLM completion failed: %w", err)
	}

	logger.Info("LLM completion succeeded",
		"phase", phase,
		"input_tokens", response.Usage.InputTokens,
		"output_tokens", response.Usage.OutputTokens,
		"response_length", len(response.Content),
	)

	// Step 4: Parse LLM response using ParseIntelligenceResponse
	intel, err := ParseIntelligenceResponse(response.Content)
	if err != nil {
		// Parsing failed - return error
		logger.Error("Failed to parse LLM response",
			"phase", phase,
			"error", err,
			"response_preview", truncate(response.Content, 200),
		)
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	// Populate intelligence metadata
	intel.MissionID = missionID
	intel.Phase = phase
	intel.SourceNodeCount = len(sourceNodeIDs)
	intel.Model = g.llmSlot // Use slot name as model identifier
	intel.Timestamp = time.Now()

	logger.Info("Parsed intelligence from LLM response",
		"phase", phase,
		"confidence", intel.Confidence,
		"attack_paths", len(intel.AttackPaths),
		"recommendations", len(intel.Recommendations),
	)

	// Step 5: Store intelligence node in knowledge graph
	intelligenceNodeID, err := g.storeIntelligenceNode(ctx, intel, sourceNodeIDs, "")
	if err != nil {
		// Log error but return the intelligence anyway (it's still valuable even if storage fails)
		logger.Error("Failed to store intelligence node in knowledge graph",
			"phase", phase,
			"error", err,
		)
		return intel, fmt.Errorf("intelligence generated but storage failed: %w", err)
	}

	intel.SourceLLMCallID = "" // LLM call ID not available in current SDK

	logger.Info("Stored intelligence node in knowledge graph",
		"phase", phase,
		"intelligence_node_id", intelligenceNodeID,
		"source_nodes", len(sourceNodeIDs),
	)

	return intel, nil
}

// GenerateSummary generates mission-wide security intelligence synthesizing findings
// across all reconnaissance phases.
// This method:
// 1. Queries the knowledge graph for entities from all phases
// 2. Builds a prompt using BuildSummaryPrompt() from prompts.go
// 3. Invokes LLM completion via harness.Complete()
// 4. Parses the response using ParseIntelligenceResponse()
// 5. Stores the summary intelligence node in the knowledge graph
//
// Returns the Intelligence struct with mission-wide analysis.
func (g *DefaultIntelligenceGenerator) GenerateSummary(ctx context.Context, missionID string) (*Intelligence, error) {
	logger := g.harness.Logger()

	logger.Info("Generating mission-wide intelligence summary",
		"mission_id", missionID,
	)

	// Step 1: Query knowledge graph for all phases
	entitiesByPhase, sourceNodeIDs, completedPhases, err := g.queryAllPhaseEntities(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to query mission entities: %w", err)
	}

	logger.Info("Retrieved mission entities from knowledge graph",
		"phases_completed", len(completedPhases),
		"total_entities", len(sourceNodeIDs),
	)

	// Step 2: Build summary prompt using BuildSummaryPrompt from prompts.go
	prompt, err := BuildSummaryPrompt(missionID, completedPhases, len(sourceNodeIDs), entitiesByPhase)
	if err != nil {
		return nil, fmt.Errorf("failed to build summary prompt: %w", err)
	}

	logger.Info("Built mission summary prompt",
		"prompt_length", len(prompt),
		"estimated_tokens", EstimatePromptTokens(prompt),
	)

	// Step 3: Invoke LLM completion
	messages := []llm.Message{
		{
			Role:    llm.RoleUser,
			Content: prompt,
		},
	}

	response, err := g.harness.Complete(ctx, g.llmSlot, messages)
	if err != nil {
		// LLM failure - return error
		logger.Error("LLM completion failed for mission summary",
			"mission_id", missionID,
			"error", err,
		)
		return nil, fmt.Errorf("LLM completion failed: %w", err)
	}

	logger.Info("LLM completion succeeded for mission summary",
		"input_tokens", response.Usage.InputTokens,
		"output_tokens", response.Usage.OutputTokens,
		"response_length", len(response.Content),
	)

	// Step 4: Parse LLM response using ParseIntelligenceResponse
	intel, err := ParseIntelligenceResponse(response.Content)
	if err != nil {
		// Parsing failed - return error
		logger.Error("Failed to parse LLM response for mission summary",
			"mission_id", missionID,
			"error", err,
			"response_preview", truncate(response.Content, 200),
		)
		return nil, fmt.Errorf("failed to parse LLM response: %w", err)
	}

	// Populate intelligence metadata
	intel.MissionID = missionID
	intel.Phase = "" // Empty for mission-wide summary
	intel.SourceNodeCount = len(sourceNodeIDs)
	intel.Model = g.llmSlot // Use slot name as model identifier
	intel.Timestamp = time.Now()

	logger.Info("Parsed mission intelligence summary",
		"confidence", intel.Confidence,
		"attack_paths", len(intel.AttackPaths),
		"recommendations", len(intel.Recommendations),
	)

	// Step 5: Store intelligence node in knowledge graph
	intelligenceNodeID, err := g.storeIntelligenceNode(ctx, intel, sourceNodeIDs, "")
	if err != nil {
		// Log error but return the intelligence anyway
		logger.Error("Failed to store intelligence summary node",
			"mission_id", missionID,
			"error", err,
		)
		return intel, fmt.Errorf("intelligence generated but storage failed: %w", err)
	}

	intel.SourceLLMCallID = "" // LLM call ID not available in current SDK

	logger.Info("Stored mission intelligence summary in knowledge graph",
		"intelligence_node_id", intelligenceNodeID,
		"source_nodes", len(sourceNodeIDs),
	)

	return intel, nil
}

// queryPhaseEntities queries the knowledge graph for entities associated with a specific
// reconnaissance phase. Returns a structured map of entities and a list of source node IDs.
func (g *DefaultIntelligenceGenerator) queryPhaseEntities(ctx context.Context, missionID string, phase string) (map[string]interface{}, []string, error) {
	logger := g.harness.Logger()

	// Query for phase-specific nodes
	// Note: The exact node types depend on what each phase creates
	// This is a generic query that can be refined based on actual schema
	query := graphrag.NewQuery(fmt.Sprintf("phase:%s mission:%s", phase, missionID)).
		WithTopK(100).
		WithMinScore(0.3).
		WithNodeTypes("Host", "Port", "Endpoint", "Technology", "Finding")

	results, err := g.harness.QueryGraphRAG(ctx, *query)
	if err != nil {
		return nil, nil, fmt.Errorf("GraphRAG query failed: %w", err)
	}

	// Extract entities and node IDs
	entities := make(map[string]interface{})
	nodeIDs := make([]string, 0, len(results))

	hosts := []map[string]interface{}{}
	ports := []map[string]interface{}{}
	endpoints := []map[string]interface{}{}
	technologies := []map[string]interface{}{}
	findings := []map[string]interface{}{}

	for _, result := range results {
		nodeIDs = append(nodeIDs, result.Node.ID)

		// Organize entities by type
		switch result.Node.Type {
		case "Host":
			hosts = append(hosts, result.Node.Properties)
		case "Port":
			ports = append(ports, result.Node.Properties)
		case "Endpoint":
			endpoints = append(endpoints, result.Node.Properties)
		case "Technology":
			technologies = append(technologies, result.Node.Properties)
		case "Finding":
			findings = append(findings, result.Node.Properties)
		default:
			logger.Warn("Unknown node type in phase query",
				"type", result.Node.Type,
				"node_id", result.Node.ID,
			)
		}
	}

	entities["hosts"] = hosts
	entities["ports"] = ports
	entities["endpoints"] = endpoints
	entities["technologies"] = technologies
	entities["findings"] = findings
	entities["phase"] = phase
	entities["mission_id"] = missionID

	return entities, nodeIDs, nil
}

// queryAllPhaseEntities queries the knowledge graph for entities from all reconnaissance
// phases. Returns entities organized by phase, all source node IDs, and list of completed phases.
func (g *DefaultIntelligenceGenerator) queryAllPhaseEntities(ctx context.Context, missionID string) (map[string]interface{}, []string, []string, error) {
	phases := []string{"discover", "probe", "scan", "domain"}
	entitiesByPhase := make(map[string]interface{})
	allNodeIDs := []string{}
	completedPhases := []string{}

	for _, phase := range phases {
		phaseEntities, nodeIDs, err := g.queryPhaseEntities(ctx, missionID, phase)
		if err != nil {
			// Log error but continue with other phases
			g.harness.Logger().Warn("Failed to query phase entities",
				"phase", phase,
				"error", err,
			)
			continue
		}

		// Only include phases that have entities
		if len(nodeIDs) > 0 {
			entitiesByPhase[phase] = phaseEntities
			allNodeIDs = append(allNodeIDs, nodeIDs...)
			completedPhases = append(completedPhases, phase)
		}
	}

	return entitiesByPhase, allNodeIDs, completedPhases, nil
}

// storeIntelligenceNode stores an Intelligence struct as a node in the knowledge graph
// with ANALYZES relationships to source nodes and GENERATED_BY relationship to the LLM call.
// Returns the assigned node ID.
func (g *DefaultIntelligenceGenerator) storeIntelligenceNode(ctx context.Context, intel *Intelligence, sourceNodeIDs []string, llmCallID string) (string, error) {
	// Serialize intelligence to JSON for storage
	intelJSON, err := json.Marshal(intel)
	if err != nil {
		return "", fmt.Errorf("failed to marshal intelligence to JSON: %w", err)
	}

	// Create intelligence node
	intelligenceNode := graphrag.NewGraphNode("Intelligence").
		WithContent(intel.Summary). // Use summary as content for semantic search
		WithProperty("mission_id", intel.MissionID).
		WithProperty("phase", intel.Phase).
		WithProperty("summary", intel.Summary).
		WithProperty("risk_assessment", intel.RiskAssessment).
		WithProperty("confidence", intel.Confidence).
		WithProperty("source_node_count", intel.SourceNodeCount).
		WithProperty("source_llm_call_id", intel.SourceLLMCallID).
		WithProperty("model", intel.Model).
		WithProperty("timestamp", intel.Timestamp.Format(time.RFC3339)).
		WithProperty("full_intelligence", string(intelJSON)) // Store complete intelligence as JSON

	// Create batch with intelligence node
	batch := graphrag.NewBatch()
	batch.Nodes = append(batch.Nodes, *intelligenceNode)

	// Create ANALYZES relationships to all source nodes
	for _, sourceNodeID := range sourceNodeIDs {
		rel := graphrag.NewRelationship(intelligenceNode.ID, sourceNodeID, "ANALYZES").
			WithProperty("analyzed_at", time.Now().Format(time.RFC3339))
		batch.Relationships = append(batch.Relationships, *rel)
	}

	// Create GENERATED_BY relationship to LLM call
	if llmCallID != "" {
		rel := graphrag.NewRelationship(intelligenceNode.ID, llmCallID, "GENERATED_BY").
			WithProperty("generated_at", time.Now().Format(time.RFC3339))
		batch.Relationships = append(batch.Relationships, *rel)
	}

	// Store batch in knowledge graph
	nodeIDs, err := g.harness.StoreGraphBatch(ctx, *batch)
	if err != nil {
		return "", fmt.Errorf("failed to store graph batch: %w", err)
	}

	if len(nodeIDs) == 0 {
		return "", fmt.Errorf("no node IDs returned from StoreGraphBatch")
	}

	// First node ID is the intelligence node ID
	return nodeIDs[0], nil
}

// truncate truncates a string to maxLen characters for logging purposes.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
