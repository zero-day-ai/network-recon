package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"text/template"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/schema"
	"github.com/zero-day-ai/sdk/tool"
)

// TaxonomyExtractor processes tool output JSON and extracts nodes and relationships
// based on embedded taxonomy mappings in tool schemas. It builds knowledge graph entities
// from tool outputs and stores them via the harness GraphRAG interface.
//
// The extractor:
//   - Retrieves tool schemas containing taxonomy mappings
//   - Parses JSON output according to JSONPath selectors in the mapping
//   - Builds node IDs using ID templates
//   - Creates nodes with mapped properties
//   - Creates relationships using template patterns
//   - Stores entities in batch via harness.StoreGraphBatch()
type TaxonomyExtractor interface {
	// Extract processes tool output JSON and extracts taxonomy-defined entities.
	// It retrieves the tool's schema, parses the output according to taxonomy mappings,
	// and creates nodes and relationships in the knowledge graph.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - toolName: Name of the tool that produced the output
	//   - outputJSON: Raw JSON output from the tool
	//
	// Returns:
	//   - nodesCreated: Count of nodes extracted and stored
	//   - relationsCreated: Count of relationships extracted and stored
	//   - error: Non-nil if extraction fails
	//
	// The extraction process:
	//   1. Get tool schema via harness.ListTools()
	//   2. Extract taxonomy mappings from output schema
	//   3. Parse JSON output and apply JSONPath selectors
	//   4. Build node IDs from id_template
	//   5. Map properties from source to target fields
	//   6. Evaluate relationship templates
	//   7. Store batch via harness.StoreGraphBatch()
	Extract(ctx context.Context, toolName string, outputJSON json.RawMessage) (int, int, error)
}

// DefaultTaxonomyExtractor implements TaxonomyExtractor using the agent harness
// for tool schema retrieval and knowledge graph storage.
type DefaultTaxonomyExtractor struct {
	harness agent.Harness
	logger  *slog.Logger
}

// NewTaxonomyExtractor creates a new taxonomy extractor that uses the provided harness.
func NewTaxonomyExtractor(harness agent.Harness) TaxonomyExtractor {
	return &DefaultTaxonomyExtractor{
		harness: harness,
		logger:  harness.Logger(),
	}
}

// Extract processes tool output and extracts taxonomy-defined entities.
func (e *DefaultTaxonomyExtractor) Extract(ctx context.Context, toolName string, outputJSON json.RawMessage) (int, int, error) {
	// Parse output JSON into a generic map
	var output map[string]any
	if err := json.Unmarshal(outputJSON, &output); err != nil {
		return 0, 0, fmt.Errorf("failed to parse tool output JSON: %w", err)
	}

	e.logger.InfoContext(ctx, "[EXTRACTOR] Starting extraction",
		"tool", toolName,
		"output_keys", getMapKeys(output))

	// Get tool schema to access taxonomy mappings
	tools, err := e.harness.ListTools(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to list tools: %w", err)
	}

	e.logger.InfoContext(ctx, "[EXTRACTOR] Listed tools", "count", len(tools))

	var toolSchema *tool.Descriptor
	for i := range tools {
		if tools[i].Name == toolName {
			toolSchema = &tools[i]
			break
		}
	}

	if toolSchema == nil {
		e.logger.WarnContext(ctx, "[EXTRACTOR] tool not found in list", "tool", toolName)
		return 0, 0, nil // Not an error - tool may not have taxonomy
	}

	e.logger.InfoContext(ctx, "[EXTRACTOR] Found tool schema",
		"tool", toolName,
		"has_output_schema", toolSchema.OutputSchema.Type != "")

	// Extract taxonomy mappings from the output schema
	mappings := extractTaxonomyFromSchema(toolSchema.OutputSchema)
	if len(mappings) == 0 {
		e.logger.WarnContext(ctx, "[EXTRACTOR] no taxonomy mappings found in schema", "tool", toolName)
		return 0, 0, nil
	}

	e.logger.InfoContext(ctx, "[EXTRACTOR] Found taxonomy mappings",
		"tool", toolName,
		"mapping_count", len(mappings))

	// Build context for template evaluation (includes mission/agent context)
	contextData := map[string]any{
		"_context": map[string]any{
			"mission_id":   e.harness.Mission().ID,
			"agent_name":   "debug", // TODO: Get from harness if available
			"agent_run_id": fmt.Sprintf("run_%s", e.harness.Mission().ID),
		},
	}

	// Process each taxonomy mapping and extract entities
	batch := graphrag.NewBatch()
	nodeIDMap := make(map[string]string) // Maps template ID to actual node ID

	for _, mapping := range mappings {
		nodesExtracted, err := e.extractNodesFromMapping(mapping, output, contextData, batch, nodeIDMap)
		if err != nil {
			e.logger.WarnContext(ctx, "failed to extract nodes from mapping",
				"tool", toolName,
				"node_type", mapping.NodeType,
				"error", err)
			continue
		}

		e.logger.DebugContext(ctx, "extracted nodes from mapping",
			"tool", toolName,
			"node_type", mapping.NodeType,
			"count", nodesExtracted)
	}

	// Store the batch in GraphRAG
	if len(batch.Nodes) == 0 {
		e.logger.DebugContext(ctx, "no entities extracted", "tool", toolName)
		return 0, 0, nil
	}

	nodeIDs, err := e.harness.StoreGraphBatch(ctx, *batch)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to store graph batch: %w", err)
	}

	e.logger.InfoContext(ctx, "extracted and stored entities",
		"tool", toolName,
		"nodes", len(batch.Nodes),
		"relationships", len(batch.Relationships))

	return len(nodeIDs), len(batch.Relationships), nil
}

// extractNodesFromMapping extracts nodes for a single taxonomy mapping from the output data.
func (e *DefaultTaxonomyExtractor) extractNodesFromMapping(
	mapping schema.TaxonomyMapping,
	output map[string]any,
	contextData map[string]any,
	batch *graphrag.Batch,
	nodeIDMap map[string]string,
) (int, error) {
	count := 0

	// For array outputs, iterate each element
	// For object outputs, process as single item
	items := []map[string]any{}

	// Check common array patterns in tool output
	arrayFound := false
	for _, key := range []string{"items", "results", "hosts", "ports", "domains", "subdomains", "endpoints", "findings"} {
		if arr, ok := output[key].([]any); ok {
			for _, item := range arr {
				if itemMap, ok := item.(map[string]any); ok {
					items = append(items, itemMap)
				}
			}
			arrayFound = true
			break
		}
	}

	if !arrayFound {
		// Single object case
		items = append(items, output)
	}

	// Process each item
	for _, item := range items {
		// Merge item data with context
		fullData := mergeMaps(item, contextData)

		// Build node ID from template
		nodeID, err := evaluateTemplate(mapping.IDTemplate, fullData)
		if err != nil {
			e.logger.WarnContext(context.Background(), "failed to evaluate ID template",
				"template", mapping.IDTemplate,
				"error", err)
			continue
		}

		// Skip if empty ID (may be filtered out)
		if nodeID == "" {
			continue
		}

		// Create node
		node := graphrag.NewGraphNode(mapping.NodeType).WithID(nodeID)

		// Map properties
		for _, prop := range mapping.Properties {
			value := extractValue(item, prop.Source)
			if value == nil && prop.Default != nil {
				value = prop.Default
			}
			if value != nil {
				node.WithProperty(prop.Target, value)
			}
		}

		// Store node in batch
		batch.Nodes = append(batch.Nodes, *node)
		nodeIDMap[nodeID] = nodeID
		count++

		// Create relationships
		for _, rel := range mapping.Relationships {
			fromID, err := evaluateTemplate(rel.FromTemplate, fullData)
			if err != nil {
				e.logger.WarnContext(context.Background(), "failed to evaluate from template",
					"template", rel.FromTemplate,
					"error", err)
				continue
			}

			toID, err := evaluateTemplate(rel.ToTemplate, fullData)
			if err != nil {
				e.logger.WarnContext(context.Background(), "failed to evaluate to template",
					"template", rel.ToTemplate,
					"error", err)
				continue
			}

			// Skip if either ID is empty
			if fromID == "" || toID == "" {
				continue
			}

			relationship := graphrag.NewRelationship(fromID, toID, rel.Type)

			// Map relationship properties
			for _, prop := range rel.Properties {
				value := extractValue(item, prop.Source)
				if value != nil {
					relationship.WithProperty(prop.Target, value)
				}
			}

			batch.Relationships = append(batch.Relationships, *relationship)
		}
	}

	return count, nil
}

// extractTaxonomyFromSchema recursively walks a JSON schema and extracts TaxonomyMapping instances.
func extractTaxonomyFromSchema(s schema.JSON) []schema.TaxonomyMapping {
	var mappings []schema.TaxonomyMapping

	// If this schema has a taxonomy, extract it
	if s.Taxonomy != nil {
		mappings = append(mappings, *s.Taxonomy)
	}

	// Recursively process object properties
	if s.Type == "object" && len(s.Properties) > 0 {
		for _, propSchema := range s.Properties {
			childMappings := extractTaxonomyFromSchema(propSchema)
			mappings = append(mappings, childMappings...)
		}
	}

	// Recursively process array items
	if s.Type == "array" && s.Items != nil {
		childMappings := extractTaxonomyFromSchema(*s.Items)
		mappings = append(mappings, childMappings...)
	}

	return mappings
}

// extractValue extracts a value from a map using a dotted path (e.g., "host.ip").
func extractValue(data map[string]any, path string) any {
	parts := strings.Split(path, ".")
	current := any(data)

	for _, part := range parts {
		if m, ok := current.(map[string]any); ok {
			current = m[part]
		} else {
			return nil
		}
	}

	return current
}

// evaluateTemplate evaluates a template string with the given data.
// Supports both {.field} and {{.field}} syntax, e.g., "host:{.ip}" or "host:{{.ip}}".
func evaluateTemplate(tmplStr string, data map[string]any) (string, error) {
	// Convert {.field} syntax to {{.field}} for Go template compatibility
	if strings.Contains(tmplStr, "{.") && !strings.Contains(tmplStr, "{{") {
		tmplStr = strings.ReplaceAll(tmplStr, "{.", "{{.")
		tmplStr = strings.ReplaceAll(tmplStr, "}", "}}")
		// Fix double-closing braces that might have been created
		tmplStr = strings.ReplaceAll(tmplStr, "}}}}", "}}")
	}

	// If template doesn't contain {{, return as-is
	if !strings.Contains(tmplStr, "{{") {
		return tmplStr, nil
	}

	tmpl, err := template.New("id").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// mergeMaps merges multiple maps into a new map, with later maps overwriting earlier ones.
func mergeMaps(maps ...map[string]any) map[string]any {
	result := make(map[string]any)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// getMapKeys returns the keys of a map as a slice of strings.
func getMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
