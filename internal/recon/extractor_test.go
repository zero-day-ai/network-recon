package recon

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/schema"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

// mockHarness implements agent.Harness for testing the extractor.
type mockHarness struct {
	agent.Harness // Embed to satisfy interface

	toolDescriptors []tool.Descriptor
	capturedBatches []graphrag.Batch
	logger          *slog.Logger
	missionID       string
}

func newMockHarness() *mockHarness {
	return &mockHarness{
		toolDescriptors: []tool.Descriptor{},
		capturedBatches: []graphrag.Batch{},
		logger:          slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
		missionID:       "test-mission-123",
	}
}

func (m *mockHarness) ListTools(ctx context.Context) ([]tool.Descriptor, error) {
	return m.toolDescriptors, nil
}

func (m *mockHarness) StoreGraphBatch(ctx context.Context, batch graphrag.Batch) ([]string, error) {
	// Capture the batch for inspection
	m.capturedBatches = append(m.capturedBatches, batch)

	// Generate IDs for each node
	ids := make([]string, len(batch.Nodes))
	for i := range batch.Nodes {
		ids[i] = batch.Nodes[i].ID
	}
	return ids, nil
}

func (m *mockHarness) Logger() *slog.Logger {
	return m.logger
}

func (m *mockHarness) Mission() types.MissionContext {
	return types.MissionContext{
		ID:   m.missionID,
		Name: "test-mission",
	}
}

// addToolWithTaxonomy adds a mock tool with taxonomy mappings to the harness.
func (m *mockHarness) addToolWithTaxonomy(toolName string, mapping schema.TaxonomyMapping) {
	descriptor := tool.Descriptor{
		Name:        toolName,
		Description: "Mock tool for testing",
		Version:     "1.0.0",
		OutputSchema: schema.JSON{
			Type: "object",
			Properties: map[string]schema.JSON{
				"items": {
					Type: "array",
					Items: &schema.JSON{
						Type:     "object",
						Taxonomy: &mapping,
					},
				},
			},
		},
	}
	m.toolDescriptors = append(m.toolDescriptors, descriptor)
}

func TestExtract_DeterministicIDs(t *testing.T) {
	// Create mock harness
	harness := newMockHarness()

	// Create taxonomy mapping for host nodes
	mapping := schema.TaxonomyMapping{
		NodeType: "host",
		IdentifyingProperties: map[string]string{
			"ip": "$.ip",
		},
		Properties: []schema.PropertyMapping{
			{Source: "hostname", Target: "hostname"},
			{Source: "status", Target: "status"},
		},
	}
	harness.addToolWithTaxonomy("port-scanner", mapping)

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock nmap-like output with hosts
	output := map[string]any{
		"items": []any{
			map[string]any{
				"ip":       "192.168.1.1",
				"hostname": "router.local",
				"status":   "up",
			},
			map[string]any{
				"ip":       "192.168.1.10",
				"hostname": "server.local",
				"status":   "up",
			},
		},
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// First extraction
	nodes1, rels1, err := extractor.Extract(ctx, "port-scanner", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 2, nodes1, "should extract 2 nodes")
	assert.Equal(t, 0, rels1, "should extract 0 relationships")
	require.Len(t, harness.capturedBatches, 1, "should have captured 1 batch")
	batch1 := harness.capturedBatches[0]

	// Second extraction with same input
	harness.capturedBatches = nil // Reset captured batches
	nodes2, rels2, err := extractor.Extract(ctx, "port-scanner", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 2, nodes2, "should extract 2 nodes")
	assert.Equal(t, 0, rels2, "should extract 0 relationships")
	require.Len(t, harness.capturedBatches, 1, "should have captured 1 batch")
	batch2 := harness.capturedBatches[0]

	// Verify both batches have identical node IDs
	require.Len(t, batch1.Nodes, 2, "batch1 should have 2 nodes")
	require.Len(t, batch2.Nodes, 2, "batch2 should have 2 nodes")

	assert.Equal(t, batch1.Nodes[0].ID, batch2.Nodes[0].ID, "first node ID should be identical")
	assert.Equal(t, batch1.Nodes[1].ID, batch2.Nodes[1].ID, "second node ID should be identical")

	// Verify IDs are not empty
	assert.NotEmpty(t, batch1.Nodes[0].ID, "node IDs should not be empty")
	assert.NotEmpty(t, batch1.Nodes[1].ID, "node IDs should not be empty")
}

func TestExtract_RelationshipsValid(t *testing.T) {
	// Create mock harness
	harness := newMockHarness()

	// Create taxonomy mapping for port nodes with relationships to host
	// Port identifying properties: host_id, number, protocol
	mapping := schema.TaxonomyMapping{
		NodeType: "port",
		IdentifyingProperties: map[string]string{
			"host_id":  "$.host_id",
			"number":   "$.port",
			"protocol": "$.protocol",
		},
		Properties: []schema.PropertyMapping{
			{Source: "state", Target: "state"},
			{Source: "service", Target: "service"},
		},
		Relationships: []schema.RelationshipMapping{
			{
				Type: "HAS_PORT",
				From: schema.NodeReference{
					Type: "host",
					Properties: map[string]string{
						"ip": "$.host_ip",
					},
				},
				To: schema.NodeReference{
					Type: "self",
				},
			},
		},
	}
	harness.addToolWithTaxonomy("port-scanner", mapping)

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock output with ports (including host_id which would be the host node's ID)
	output := map[string]any{
		"items": []any{
			map[string]any{
				"host_ip":  "192.168.1.1",
				"host_id":  "host:192.168.1.1", // Simulated host node ID
				"port":     80,
				"protocol": "tcp",
				"state":    "open",
				"service":  "http",
			},
			map[string]any{
				"host_ip":  "192.168.1.1",
				"host_id":  "host:192.168.1.1", // Same host
				"port":     443,
				"protocol": "tcp",
				"state":    "open",
				"service":  "https",
			},
		},
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// Extract
	nodes, rels, err := extractor.Extract(ctx, "port-scanner", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 2, nodes, "should extract 2 nodes")
	assert.Equal(t, 2, rels, "should extract 2 relationships")

	require.Len(t, harness.capturedBatches, 1, "should have captured 1 batch")
	batch := harness.capturedBatches[0]

	// Verify all relationship FromID/ToID values exist in the batch nodes
	nodeIDSet := make(map[string]bool)
	for _, node := range batch.Nodes {
		nodeIDSet[node.ID] = true
	}

	for i, rel := range batch.Relationships {
		// ToID should match one of the port node IDs (since To is "self")
		assert.Contains(t, nodeIDSet, rel.ToID,
			"relationship %d ToID should reference a node in the batch", i)

		// FromID should be a generated host ID
		assert.NotEmpty(t, rel.FromID,
			"relationship %d FromID should not be empty", i)

		// Verify relationship type
		assert.Equal(t, "HAS_PORT", rel.Type,
			"relationship %d should be HAS_PORT", i)
	}
}

func TestExtract_HostPortRelationship(t *testing.T) {
	// Create mock harness
	harness := newMockHarness()

	// Create a single taxonomy mapping that extracts ports and creates relationships to hosts
	// This test verifies that relationships correctly link port nodes to host nodes
	// Port identifying properties: host_id, number, protocol
	portMapping := schema.TaxonomyMapping{
		NodeType: "port",
		IdentifyingProperties: map[string]string{
			"host_id":  "$.host_id",
			"number":   "$.number",
			"protocol": "$.protocol",
		},
		Properties: []schema.PropertyMapping{
			{Source: "state", Target: "state"},
			{Source: "host_id", Target: "host_id"}, // Store host_id as property for verification
		},
		Relationships: []schema.RelationshipMapping{
			{
				Type: "HAS_PORT",
				From: schema.NodeReference{
					Type: "host",
					Properties: map[string]string{
						"ip": "$.host_ip",
					},
				},
				To: schema.NodeReference{
					Type: "self",
				},
			},
		},
	}
	harness.addToolWithTaxonomy("port-scanner", portMapping)

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock output with ports and their host information
	// Each port item contains the host_ip needed for the relationship
	output := map[string]any{
		"items": []any{
			map[string]any{
				"host_ip":  "10.0.0.5",
				"host_id":  "host:10.0.0.5", // Simulated host node ID
				"number":   80,
				"protocol": "tcp",
				"state":    "open",
			},
			map[string]any{
				"host_ip":  "10.0.0.5",
				"host_id":  "host:10.0.0.5", // Simulated host node ID
				"number":   443,
				"protocol": "tcp",
				"state":    "open",
			},
		},
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// Extract
	nodes, rels, err := extractor.Extract(ctx, "port-scanner", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 2, nodes, "should extract 2 port nodes")
	assert.Equal(t, 2, rels, "should extract 2 HAS_PORT relationships")

	require.Len(t, harness.capturedBatches, 1, "should have captured 1 batch")
	batch := harness.capturedBatches[0]

	// Verify both nodes are port nodes
	require.Len(t, batch.Nodes, 2, "batch should have 2 nodes")
	for i, node := range batch.Nodes {
		assert.Equal(t, "port", node.Type, "node %d should be a port", i)
		assert.Equal(t, "host:10.0.0.5", node.Properties["host_id"],
			"port node %d should have correct host_id", i)
	}

	// Verify all HAS_PORT relationships
	require.Len(t, batch.Relationships, 2, "should have 2 relationships")
	for i, rel := range batch.Relationships {
		assert.Equal(t, "HAS_PORT", rel.Type, "relationship %d should be HAS_PORT", i)

		// FromID should be the generated host ID (from host_ip in the data)
		assert.NotEmpty(t, rel.FromID,
			"relationship %d FromID should not be empty", i)

		// ToID should match one of the port nodes
		var foundPortNode bool
		for _, node := range batch.Nodes {
			if node.Type == "port" && node.ID == rel.ToID {
				foundPortNode = true
				// Verify the port's host_id property
				assert.Equal(t, "host:10.0.0.5", node.Properties["host_id"],
					"port node should have correct host_id")
				break
			}
		}
		assert.True(t, foundPortNode, "relationship %d ToID should reference a port node", i)
	}
}

func TestExtract_MissingProperty(t *testing.T) {
	// Create mock harness
	harness := newMockHarness()

	// Create taxonomy mapping with required identifying properties
	mapping := schema.TaxonomyMapping{
		NodeType: "host",
		IdentifyingProperties: map[string]string{
			"ip":       "$.ip",
			"hostname": "$.hostname",
		},
		Properties: []schema.PropertyMapping{
			{Source: "status", Target: "status"},
		},
	}
	harness.addToolWithTaxonomy("scanner", mapping)

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock output with mixed valid and invalid data
	// First item missing hostname, second item valid, third item missing ip
	output := map[string]any{
		"items": []any{
			map[string]any{
				"ip":     "192.168.1.1",
				"status": "up",
				// Missing hostname
			},
			map[string]any{
				"ip":       "192.168.1.2",
				"hostname": "valid.local",
				"status":   "up",
			},
			map[string]any{
				"hostname": "noip.local",
				"status":   "up",
				// Missing ip
			},
		},
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// Extract - should only get the valid node
	nodes, rels, err := extractor.Extract(ctx, "scanner", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 1, nodes, "should extract only 1 valid node")
	assert.Equal(t, 0, rels, "should extract 0 relationships")

	require.Len(t, harness.capturedBatches, 1, "should have captured 1 batch")
	batch := harness.capturedBatches[0]

	// Verify only the valid node was extracted
	require.Len(t, batch.Nodes, 1, "batch should contain only 1 node")
	assert.Equal(t, "host", batch.Nodes[0].Type)

	// Get the identifying properties from the node's properties
	// They might be stored in Properties or used for ID generation
	node := batch.Nodes[0]
	t.Logf("Node properties: %+v", node.Properties)
	t.Logf("Node ID: %s", node.ID)

	// The valid node should have been created with both ip and hostname
	// Check that status property was set
	assert.Equal(t, "up", node.Properties["status"])
}

func TestExtract_NoTaxonomyMapping(t *testing.T) {
	// Create mock harness with a tool that has no taxonomy
	harness := newMockHarness()

	descriptor := tool.Descriptor{
		Name:        "plain-tool",
		Description: "Tool without taxonomy",
		Version:     "1.0.0",
		OutputSchema: schema.JSON{
			Type: "object",
			Properties: map[string]schema.JSON{
				"result": {Type: "string"},
			},
		},
	}
	harness.toolDescriptors = append(harness.toolDescriptors, descriptor)

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock output
	output := map[string]any{
		"result": "some result",
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// Extract - should return 0 nodes and 0 relationships without error
	nodes, rels, err := extractor.Extract(ctx, "plain-tool", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 0, nodes, "should extract 0 nodes from tool without taxonomy")
	assert.Equal(t, 0, rels, "should extract 0 relationships from tool without taxonomy")

	assert.Len(t, harness.capturedBatches, 0, "should not store any batches")
}

func TestExtract_ToolNotFound(t *testing.T) {
	// Create mock harness with no tools
	harness := newMockHarness()

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock output
	output := map[string]any{
		"items": []any{},
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// Extract with non-existent tool - should return 0 nodes without error
	nodes, rels, err := extractor.Extract(ctx, "nonexistent-tool", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 0, nodes, "should extract 0 nodes for non-existent tool")
	assert.Equal(t, 0, rels, "should extract 0 relationships for non-existent tool")

	assert.Len(t, harness.capturedBatches, 0, "should not store any batches")
}

func TestExtract_EmptyOutput(t *testing.T) {
	// Create mock harness
	harness := newMockHarness()

	// Create taxonomy mapping
	mapping := schema.TaxonomyMapping{
		NodeType: "host",
		IdentifyingProperties: map[string]string{
			"ip": "$.ip",
		},
		Properties: []schema.PropertyMapping{
			{Source: "hostname", Target: "hostname"},
		},
	}
	harness.addToolWithTaxonomy("scanner", mapping)

	// Create extractor
	extractor := NewTaxonomyExtractor(harness)

	// Mock empty output
	output := map[string]any{
		"items": []any{},
	}
	outputJSON, err := json.Marshal(output)
	require.NoError(t, err)

	ctx := context.Background()

	// Extract - should return 0 nodes without error
	nodes, rels, err := extractor.Extract(ctx, "scanner", outputJSON)
	require.NoError(t, err)
	assert.Equal(t, 0, nodes, "should extract 0 nodes from empty output")
	assert.Equal(t, 0, rels, "should extract 0 relationships from empty output")

	assert.Len(t, harness.capturedBatches, 0, "should not store empty batches")
}
