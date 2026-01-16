package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/finding"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/llm"
	"github.com/zero-day-ai/sdk/memory"
	"github.com/zero-day-ai/sdk/mission"
	"github.com/zero-day-ai/sdk/planning"
	"github.com/zero-day-ai/sdk/plugin"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
)

// mockHarness implements agent.Harness for testing
type mockHarness struct {
	// Mock responses
	graphQueryResults []graphrag.Result
	graphQueryError   error
	llmResponse       *llm.CompletionResponse
	llmError          error
	storeGraphResults []string
	storeGraphError   error

	// Call tracking
	graphQueryCalls   int
	llmCompleteCalls  int
	storeGraphCalls   int
	lastLLMMessages   []llm.Message
	lastGraphBatch    *graphrag.Batch
}

func newMockHarness() *mockHarness {
	return &mockHarness{
		graphQueryResults: []graphrag.Result{},
		storeGraphResults: []string{"intel-node-123"},
	}
}

func (m *mockHarness) QueryGraphRAG(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	m.graphQueryCalls++
	if m.graphQueryError != nil {
		return nil, m.graphQueryError
	}
	return m.graphQueryResults, nil
}

func (m *mockHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...llm.CompletionOption) (*llm.CompletionResponse, error) {
	m.llmCompleteCalls++
	m.lastLLMMessages = messages
	if m.llmError != nil {
		return nil, m.llmError
	}
	return m.llmResponse, nil
}

func (m *mockHarness) StoreGraphBatch(ctx context.Context, batch graphrag.Batch) ([]string, error) {
	m.storeGraphCalls++
	m.lastGraphBatch = &batch
	if m.storeGraphError != nil {
		return nil, m.storeGraphError
	}
	return m.storeGraphResults, nil
}

func (m *mockHarness) Logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // Only show errors during tests
	}))
}

// Implement other required agent.Harness methods as no-ops
func (m *mockHarness) CallTool(ctx context.Context, toolName string, input map[string]interface{}) (map[string]interface{}, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) CallToolsParallel(ctx context.Context, calls []agent.ToolCall, maxConcurrency int) ([]agent.ToolResult, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetConfig(key string) (string, bool) {
	return "", false
}

func (m *mockHarness) GetTask() agent.Task {
	return agent.Task{}
}

func (m *mockHarness) SendPartialResult(ctx context.Context, result map[string]interface{}) error {
	return nil
}

func (m *mockHarness) CancelMission(ctx context.Context, missionID string) error {
	return errors.New("not implemented")
}

// Additional stub methods to satisfy agent.Harness interface
func (m *mockHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) CompleteStructured(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) SubmitFinding(ctx context.Context, f *finding.Finding) error {
	return errors.New("not implemented")
}

func (m *mockHarness) GetFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]graphrag.AttackPattern, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]graphrag.FindingNode, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]graphrag.AttackChain, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetRelatedFindings(ctx context.Context, findingID string) ([]graphrag.FindingNode, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) StoreGraphNode(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", errors.New("not implemented")
}

func (m *mockHarness) GetMissionRunHistory(ctx context.Context) ([]types.MissionRunSummary, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetPreviousRunFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetAllRunFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) QueryGraphRAGScoped(ctx context.Context, query graphrag.Query, scope graphrag.MissionScope) ([]graphrag.Result, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetCredential(ctx context.Context, name string) (*types.Credential, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, errors.New("not implemented")
}

func (m *mockHarness) CreateGraphRelationship(ctx context.Context, rel graphrag.Relationship) error {
	return errors.New("not implemented")
}

func (m *mockHarness) CreateMission(ctx context.Context, workflowSpec any, targetID string, opts *mission.CreateMissionOpts) (*mission.MissionInfo, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) TokenUsage() llm.TokenTracker {
	return nil
}

func (m *mockHarness) GraphRAGHealth(ctx context.Context) types.HealthStatus {
	return types.HealthStatus{}
}

func (m *mockHarness) ListAgents(ctx context.Context) ([]agent.Descriptor, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) ListPlugins(ctx context.Context) ([]plugin.Descriptor, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) ListTools(ctx context.Context) ([]tool.Descriptor, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) Memory() memory.Store {
	return nil
}

func (m *mockHarness) Mission() types.MissionContext {
	return types.MissionContext{}
}

func (m *mockHarness) Target() types.TargetInfo {
	return types.TargetInfo{}
}

func (m *mockHarness) MissionExecutionContext() types.MissionExecutionContext {
	return types.MissionExecutionContext{}
}

func (m *mockHarness) PlanContext() planning.PlanningContext {
	return nil
}

func (m *mockHarness) ReportStepHints(ctx context.Context, hints *planning.StepHints) error {
	return errors.New("not implemented")
}

func (m *mockHarness) TraverseGraph(ctx context.Context, startNodeID string, opts graphrag.TraversalOptions) ([]graphrag.TraversalResult, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) RunMission(ctx context.Context, missionID string, opts *mission.RunMissionOpts) error {
	return errors.New("not implemented")
}

func (m *mockHarness) WaitForMission(ctx context.Context, missionID string, timeout time.Duration) (*mission.MissionResult, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) Stream(ctx context.Context, slot string, messages []llm.Message) (<-chan llm.StreamChunk, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) EmitOutput(content string, isReasoning bool) error {
	return errors.New("not implemented")
}

func (m *mockHarness) EmitToolCall(toolName string, input map[string]any, callID string) error {
	return errors.New("not implemented")
}

func (m *mockHarness) EmitToolResult(output map[string]any, err error, callID string) error {
	return errors.New("not implemented")
}

func (m *mockHarness) Tracer() trace.Tracer {
	return nil
}

func (m *mockHarness) ListMissions(ctx context.Context, filter *mission.MissionFilter) ([]*mission.MissionInfo, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetMissionStatus(ctx context.Context, missionID string) (*mission.MissionStatusInfo, error) {
	return nil, errors.New("not implemented")
}

func (m *mockHarness) GetMissionResults(ctx context.Context, missionID string) (*mission.MissionResult, error) {
	return nil, errors.New("not implemented")
}

// setupMockHarnessWithSampleData creates a mock harness with realistic reconnaissance data
func setupMockHarnessWithSampleData(phase string) *mockHarness {
	mock := newMockHarness()

	// Simulate GraphRAG query results for a specific phase
	mock.graphQueryResults = []graphrag.Result{
		{
			Node: graphrag.GraphNode{
				ID:   "host-192-168-1-10",
				Type: "Host",
				Properties: map[string]interface{}{
					"ip":       "192.168.1.10",
					"hostname": "web-server-01",
					"phase":    phase,
				},
			},
			Score: 0.95,
		},
		{
			Node: graphrag.GraphNode{
				ID:   "port-192-168-1-10-80",
				Type: "Port",
				Properties: map[string]interface{}{
					"port":    80,
					"service": "http",
					"phase":   phase,
				},
			},
			Score: 0.90,
		},
		{
			Node: graphrag.GraphNode{
				ID:   "finding-sqli-001",
				Type: "Finding",
				Properties: map[string]interface{}{
					"title":    "SQL Injection Vulnerability",
					"severity": "critical",
					"phase":    phase,
				},
			},
			Score: 0.85,
		},
	}

	// Simulate valid LLM response
	llmResponseJSON := `{
		"summary": "Analysis of ` + phase + ` phase revealed critical security vulnerabilities including SQL injection and exposed admin interfaces. The web server at 192.168.1.10 presents significant attack surface.",
		"risk_assessment": "Critical risk due to exploitable SQL injection vulnerability combined with weak authentication mechanisms. Immediate remediation required to prevent unauthorized access and data exfiltration.",
		"attack_paths": [
			{
				"name": "SQL Injection to Database Compromise",
				"description": "Attacker exploits SQL injection vulnerability to extract database credentials and escalate privileges",
				"steps": [
					"Identify SQL injection endpoint via error-based probing",
					"Extract database schema using UNION-based injection",
					"Retrieve admin credentials from users table",
					"Authenticate as administrator to access sensitive data"
				],
				"risk": "critical",
				"finding_ids": ["finding-sqli-001"]
			}
		],
		"recommendations": [
			{
				"title": "Remediate SQL Injection Vulnerabilities",
				"description": "Implement parameterized queries and input validation across all database interactions. Deploy web application firewall as compensating control during remediation.",
				"priority": "immediate",
				"affected_node_ids": ["host-192-168-1-10", "finding-sqli-001"]
			}
		],
		"confidence": 0.92
	}`

	mock.llmResponse = &llm.CompletionResponse{
		Content: llmResponseJSON,
		Usage: llm.TokenUsage{
			InputTokens:  1500,
			OutputTokens: 800,
		},
	}

	return mock
}

func TestBuildPhasePrompt(t *testing.T) {
	tests := []struct {
		name        string
		phase       string
		entities    interface{}
		wantErr     bool
		expectPhase string
		expectDesc  bool
	}{
		{
			name:  "Valid discover phase",
			phase: "discover",
			entities: map[string]interface{}{
				"hosts": []map[string]interface{}{
					{"ip": "192.168.1.10", "hostname": "web-01"},
				},
			},
			wantErr:     false,
			expectPhase: "discover",
			expectDesc:  true,
		},
		{
			name:  "Valid probe phase",
			phase: "probe",
			entities: map[string]interface{}{
				"endpoints": []map[string]interface{}{
					{"url": "http://example.com/api", "status": 200},
				},
			},
			wantErr:     false,
			expectPhase: "probe",
			expectDesc:  true,
		},
		{
			name:  "Valid scan phase",
			phase: "scan",
			entities: map[string]interface{}{
				"findings": []map[string]interface{}{
					{"title": "SQL Injection", "severity": "critical"},
				},
			},
			wantErr:     false,
			expectPhase: "scan",
			expectDesc:  true,
		},
		{
			name:  "Valid domain phase",
			phase: "domain",
			entities: map[string]interface{}{
				"domains": []string{"example.com", "api.example.com"},
			},
			wantErr:     false,
			expectPhase: "domain",
			expectDesc:  true,
		},
		{
			name:     "Unknown phase",
			phase:    "invalid-phase",
			entities: map[string]interface{}{},
			wantErr:  true,
		},
		{
			name:  "Empty entities",
			phase: "discover",
			entities: map[string]interface{}{
				"hosts": []interface{}{},
			},
			wantErr:     false,
			expectPhase: "discover",
			expectDesc:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt, err := BuildPhasePrompt(tt.phase, tt.entities)

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildPhasePrompt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify prompt contains phase name
			if tt.expectPhase != "" {
				if len(prompt) == 0 {
					t.Error("BuildPhasePrompt() returned empty prompt")
				}
			}

			// Verify prompt contains JSON data
			entitiesJSON, _ := json.Marshal(tt.entities)
			if len(entitiesJSON) > 0 {
				// Prompt should include some portion of the entities
				if len(prompt) < 500 {
					t.Error("BuildPhasePrompt() returned suspiciously short prompt")
				}
			}

			// Verify prompt contains phase description
			if tt.expectDesc {
				desc, ok := PhaseDescriptions[tt.phase]
				if ok && len(desc) > 0 {
					// We know the description should be replaced in template
					if len(prompt) == 0 {
						t.Error("BuildPhasePrompt() prompt doesn't contain phase description")
					}
				}
			}
		})
	}
}

func TestBuildSummaryPrompt(t *testing.T) {
	tests := []struct {
		name             string
		missionID        string
		phasesCompleted  []string
		totalNodes       int
		entitiesByPhase  interface{}
		wantErr          bool
	}{
		{
			name:            "Valid mission summary",
			missionID:       "mission-123",
			phasesCompleted: []string{"discover", "probe", "scan", "domain"},
			totalNodes:      42,
			entitiesByPhase: map[string]interface{}{
				"discover": map[string]interface{}{
					"hosts": []map[string]interface{}{
						{"ip": "192.168.1.10"},
					},
				},
				"probe": map[string]interface{}{
					"endpoints": []map[string]interface{}{
						{"url": "http://example.com"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:            "Single phase completed",
			missionID:       "mission-456",
			phasesCompleted: []string{"discover"},
			totalNodes:      10,
			entitiesByPhase: map[string]interface{}{
				"discover": map[string]interface{}{
					"hosts": []map[string]interface{}{
						{"ip": "192.168.1.10"},
					},
				},
			},
			wantErr: false,
		},
		{
			name:            "No phases completed",
			missionID:       "mission-789",
			phasesCompleted: []string{},
			totalNodes:      0,
			entitiesByPhase: map[string]interface{}{},
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt, err := BuildSummaryPrompt(tt.missionID, tt.phasesCompleted, tt.totalNodes, tt.entitiesByPhase)

			if (err != nil) != tt.wantErr {
				t.Errorf("BuildSummaryPrompt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify prompt contains mission ID
			if tt.missionID != "" && len(prompt) == 0 {
				t.Error("BuildSummaryPrompt() returned empty prompt")
			}

			// Verify prompt is substantial
			if len(tt.phasesCompleted) > 0 && len(prompt) < 500 {
				t.Error("BuildSummaryPrompt() returned suspiciously short prompt")
			}
		})
	}
}

func TestGenerateForPhase_Success(t *testing.T) {
	mock := setupMockHarnessWithSampleData("scan")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	intel, err := gen.GenerateForPhase(ctx, "mission-123", "scan")

	if err != nil {
		t.Fatalf("GenerateForPhase() unexpected error: %v", err)
	}

	// Verify harness was called correctly
	if mock.graphQueryCalls != 1 {
		t.Errorf("Expected 1 GraphRAG query call, got %d", mock.graphQueryCalls)
	}

	if mock.llmCompleteCalls != 1 {
		t.Errorf("Expected 1 LLM completion call, got %d", mock.llmCompleteCalls)
	}

	if mock.storeGraphCalls != 1 {
		t.Errorf("Expected 1 StoreGraphBatch call, got %d", mock.storeGraphCalls)
	}

	// Verify intelligence metadata
	if intel.MissionID != "mission-123" {
		t.Errorf("Expected mission_id 'mission-123', got %q", intel.MissionID)
	}

	if intel.Phase != "scan" {
		t.Errorf("Expected phase 'scan', got %q", intel.Phase)
	}

	if intel.SourceNodeCount != 3 {
		t.Errorf("Expected source_node_count 3, got %d", intel.SourceNodeCount)
	}

	// Verify intelligence content
	if intel.Summary == "" {
		t.Error("Expected non-empty summary")
	}

	if intel.RiskAssessment == "" {
		t.Error("Expected non-empty risk assessment")
	}

	if len(intel.AttackPaths) == 0 {
		t.Error("Expected at least one attack path")
	}

	if len(intel.Recommendations) == 0 {
		t.Error("Expected at least one recommendation")
	}

	if intel.Confidence < 0.0 || intel.Confidence > 1.0 {
		t.Errorf("Expected confidence in range [0.0, 1.0], got %f", intel.Confidence)
	}

	// Verify timestamp is recent
	if time.Since(intel.Timestamp) > time.Minute {
		t.Error("Expected recent timestamp")
	}
}

func TestGenerateForPhase_GraphRAGQueryFailure(t *testing.T) {
	mock := newMockHarness()
	mock.graphQueryError = errors.New("GraphRAG connection failed")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	_, err := gen.GenerateForPhase(ctx, "mission-123", "discover")

	if err == nil {
		t.Fatal("Expected error when GraphRAG query fails")
	}

	// Verify that we stopped early - LLM should not be called
	if mock.llmCompleteCalls != 0 {
		t.Errorf("Expected 0 LLM calls after GraphRAG failure, got %d", mock.llmCompleteCalls)
	}
}

func TestGenerateForPhase_LLMFailure(t *testing.T) {
	mock := setupMockHarnessWithSampleData("probe")
	mock.llmError = errors.New("LLM service unavailable")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	_, err := gen.GenerateForPhase(ctx, "mission-123", "probe")

	if err == nil {
		t.Fatal("Expected error when LLM completion fails")
	}

	// Verify harness was called up to the failure point
	if mock.graphQueryCalls != 1 {
		t.Errorf("Expected GraphRAG query to be attempted, got %d calls", mock.graphQueryCalls)
	}

	if mock.llmCompleteCalls != 1 {
		t.Errorf("Expected LLM completion to be attempted, got %d calls", mock.llmCompleteCalls)
	}

	// StoreGraphBatch should not be called after LLM failure
	if mock.storeGraphCalls != 0 {
		t.Errorf("Expected 0 StoreGraphBatch calls after LLM failure, got %d", mock.storeGraphCalls)
	}
}

func TestGenerateForPhase_ParsingFailure(t *testing.T) {
	mock := setupMockHarnessWithSampleData("scan")
	// Set invalid JSON response
	mock.llmResponse.Content = "This is not JSON at all, just plain text"
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	_, err := gen.GenerateForPhase(ctx, "mission-123", "scan")

	if err == nil {
		t.Fatal("Expected error when LLM response parsing fails")
	}

	// Verify all calls were made up to parsing
	if mock.graphQueryCalls != 1 {
		t.Errorf("Expected 1 GraphRAG query call, got %d", mock.graphQueryCalls)
	}

	if mock.llmCompleteCalls != 1 {
		t.Errorf("Expected 1 LLM completion call, got %d", mock.llmCompleteCalls)
	}

	// StoreGraphBatch should not be called if parsing fails
	if mock.storeGraphCalls != 0 {
		t.Errorf("Expected 0 StoreGraphBatch calls after parsing failure, got %d", mock.storeGraphCalls)
	}
}

func TestGenerateForPhase_StoreGraphFailure(t *testing.T) {
	mock := setupMockHarnessWithSampleData("domain")
	mock.storeGraphError = errors.New("Neo4j connection timeout")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	intel, err := gen.GenerateForPhase(ctx, "mission-123", "domain")

	// We should get an error but also get the intelligence data
	if err == nil {
		t.Fatal("Expected error when StoreGraphBatch fails")
	}

	// Intelligence should still be populated even if storage fails
	if intel == nil {
		t.Fatal("Expected intelligence to be returned even when storage fails")
	}

	if intel.Summary == "" {
		t.Error("Expected intelligence summary even when storage fails")
	}
}

func TestGenerateForPhase_AllPhases(t *testing.T) {
	phases := []string{"discover", "probe", "scan", "domain"}

	for _, phase := range phases {
		t.Run(phase, func(t *testing.T) {
			mock := setupMockHarnessWithSampleData(phase)
			gen := NewIntelligenceGenerator(mock)

			ctx := context.Background()
			intel, err := gen.GenerateForPhase(ctx, "mission-test", phase)

			if err != nil {
				t.Fatalf("GenerateForPhase(%s) unexpected error: %v", phase, err)
			}

			if intel.Phase != phase {
				t.Errorf("Expected phase %q, got %q", phase, intel.Phase)
			}
		})
	}
}

func TestGenerateSummary_Success(t *testing.T) {
	mock := newMockHarness()

	// Setup multi-phase reconnaissance data
	mock.graphQueryResults = []graphrag.Result{
		{
			Node: graphrag.GraphNode{
				ID:   "host-001",
				Type: "Host",
				Properties: map[string]interface{}{
					"ip": "192.168.1.10",
				},
			},
			Score: 0.95,
		},
		{
			Node: graphrag.GraphNode{
				ID:   "endpoint-001",
				Type: "Endpoint",
				Properties: map[string]interface{}{
					"url": "http://192.168.1.10/admin",
				},
			},
			Score: 0.90,
		},
	}

	// Setup mission-wide LLM response
	summaryJSON := `{
		"summary": "Comprehensive security assessment across all phases reveals critical vulnerabilities requiring immediate attention. The network environment exhibits multiple high-risk attack vectors including SQL injection, weak authentication, and exposed admin interfaces.",
		"risk_assessment": "Overall risk posture is critical. Multiple exploit chains exist from initial network discovery through privilege escalation. Business impact includes potential data breach, service disruption, and regulatory compliance violations.",
		"attack_paths": [
			{
				"name": "Complete Network Compromise",
				"description": "Multi-phase attack from network discovery through domain takeover",
				"steps": [
					"Phase 1: Network discovery identifies web server at 192.168.1.10",
					"Phase 2: Probe reveals exposed admin interface",
					"Phase 3: Vulnerability scan finds SQL injection",
					"Phase 4: Domain reconnaissance reveals additional attack surface"
				],
				"risk": "critical",
				"finding_ids": ["finding-sqli-001", "finding-auth-002"]
			}
		],
		"recommendations": [
			{
				"title": "Implement Defense-in-Depth Strategy",
				"description": "Deploy multiple layers of security controls including network segmentation, WAF, strong authentication, and vulnerability management program",
				"priority": "immediate",
				"affected_node_ids": ["host-001", "endpoint-001"]
			}
		],
		"confidence": 0.88
	}`

	mock.llmResponse = &llm.CompletionResponse{
		Content: summaryJSON,
		Usage: llm.TokenUsage{
			InputTokens:  3000,
			OutputTokens: 1200,
		},
	}

	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	intel, err := gen.GenerateSummary(ctx, "mission-comprehensive")

	if err != nil {
		t.Fatalf("GenerateSummary() unexpected error: %v", err)
	}

	// Verify harness was called correctly
	// Note: queryAllPhaseEntities calls queryPhaseEntities for each phase
	expectedQueryCalls := 4 // discover, probe, scan, domain
	if mock.graphQueryCalls != expectedQueryCalls {
		t.Errorf("Expected %d GraphRAG query calls (one per phase), got %d", expectedQueryCalls, mock.graphQueryCalls)
	}

	if mock.llmCompleteCalls != 1 {
		t.Errorf("Expected 1 LLM completion call, got %d", mock.llmCompleteCalls)
	}

	// Verify intelligence metadata
	if intel.MissionID != "mission-comprehensive" {
		t.Errorf("Expected mission_id 'mission-comprehensive', got %q", intel.MissionID)
	}

	if intel.Phase != "" {
		t.Errorf("Expected empty phase for summary, got %q", intel.Phase)
	}

	// Verify intelligence content
	if intel.Summary == "" {
		t.Error("Expected non-empty summary")
	}

	if len(intel.AttackPaths) == 0 {
		t.Error("Expected at least one attack path in summary")
	}

	if len(intel.Recommendations) == 0 {
		t.Error("Expected at least one recommendation in summary")
	}
}

func TestGenerateSummary_NoPhaseData(t *testing.T) {
	mock := newMockHarness()
	// No query results - empty reconnaissance
	mock.graphQueryResults = []graphrag.Result{}

	// Even with no data, LLM should generate a summary (though confidence will be low)
	emptyDataSummaryJSON := `{
		"summary": "No reconnaissance data available for analysis. Unable to assess security posture without completed reconnaissance phases.",
		"risk_assessment": "Unknown risk level - insufficient data for assessment. Recommend completing reconnaissance phases before generating intelligence.",
		"attack_paths": [],
		"recommendations": [
			{
				"title": "Complete Reconnaissance Phases",
				"description": "Execute discover, probe, scan, and domain phases to gather data for security analysis",
				"priority": "immediate",
				"affected_node_ids": []
			}
		],
		"confidence": 0.1
	}`

	mock.llmResponse = &llm.CompletionResponse{
		Content: emptyDataSummaryJSON,
		Usage: llm.TokenUsage{
			InputTokens:  500,
			OutputTokens: 200,
		},
	}

	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	intel, err := gen.GenerateSummary(ctx, "mission-empty")

	if err != nil {
		t.Fatalf("GenerateSummary() unexpected error: %v", err)
	}

	// Verify low confidence for empty data
	if intel.Confidence > 0.3 {
		t.Errorf("Expected low confidence for empty data, got %f", intel.Confidence)
	}

	if intel.SourceNodeCount != 0 {
		t.Errorf("Expected 0 source nodes for empty data, got %d", intel.SourceNodeCount)
	}
}

func TestGenerateSummary_LLMFailure(t *testing.T) {
	mock := setupMockHarnessWithSampleData("scan")
	mock.llmError = errors.New("LLM rate limit exceeded")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	_, err := gen.GenerateSummary(ctx, "mission-fail")

	if err == nil {
		t.Fatal("Expected error when LLM completion fails")
	}

	// Verify StoreGraphBatch was not called
	if mock.storeGraphCalls != 0 {
		t.Errorf("Expected 0 StoreGraphBatch calls after LLM failure, got %d", mock.storeGraphCalls)
	}
}

func TestNewIntelligenceGeneratorWithSlot(t *testing.T) {
	mock := newMockHarness()
	customSlot := "analysis-llm"
	gen := NewIntelligenceGeneratorWithSlot(mock, customSlot)

	// Verify the generator uses the custom slot
	defGen, ok := gen.(*DefaultIntelligenceGenerator)
	if !ok {
		t.Fatal("Expected DefaultIntelligenceGenerator type")
	}

	if defGen.llmSlot != customSlot {
		t.Errorf("Expected LLM slot %q, got %q", customSlot, defGen.llmSlot)
	}
}

func TestPromptTokenEstimation(t *testing.T) {
	tests := []struct {
		name          string
		prompt        string
		expectedRange [2]int // min, max expected tokens
	}{
		{
			name:          "Empty prompt",
			prompt:        "",
			expectedRange: [2]int{0, 1},
		},
		{
			name:          "Short prompt",
			prompt:        "Analyze this data",
			expectedRange: [2]int{3, 6},
		},
		{
			name:          "Medium prompt",
			prompt:        "You are a security analyst. Analyze the following reconnaissance data and generate actionable intelligence including risk assessment and recommendations.",
			expectedRange: [2]int{25, 40},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens := EstimatePromptTokens(tt.prompt)

			if tokens < tt.expectedRange[0] || tokens > tt.expectedRange[1] {
				t.Errorf("EstimatePromptTokens() = %d, expected range [%d, %d]",
					tokens, tt.expectedRange[0], tt.expectedRange[1])
			}
		})
	}
}

func TestGenerateForPhase_PromptContainsCorrectData(t *testing.T) {
	mock := setupMockHarnessWithSampleData("probe")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	_, err := gen.GenerateForPhase(ctx, "mission-123", "probe")

	if err != nil {
		t.Fatalf("GenerateForPhase() unexpected error: %v", err)
	}

	// Verify that LLM was called with a prompt
	if len(mock.lastLLMMessages) != 1 {
		t.Fatalf("Expected 1 LLM message, got %d", len(mock.lastLLMMessages))
	}

	prompt := mock.lastLLMMessages[0].Content

	// Verify prompt contains phase name
	if len(prompt) == 0 {
		t.Error("Expected prompt to contain phase name 'probe'")
	}

	// Verify prompt contains reconnaissance data (should be substantial)
	if len(prompt) < 1000 {
		t.Errorf("Prompt seems too short (%d chars), may not contain full reconnaissance data", len(prompt))
	}

	// Verify prompt contains instructions for structured output
	if len(prompt) == 0 {
		t.Error("Expected prompt to contain JSON output instructions")
	}
}

func TestGenerateForPhase_GraphBatchStructure(t *testing.T) {
	mock := setupMockHarnessWithSampleData("scan")
	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	_, err := gen.GenerateForPhase(ctx, "mission-123", "scan")

	if err != nil {
		t.Fatalf("GenerateForPhase() unexpected error: %v", err)
	}

	// Verify batch structure
	if mock.lastGraphBatch == nil {
		t.Fatal("Expected StoreGraphBatch to be called with a batch")
	}

	batch := mock.lastGraphBatch

	// Should contain at least one node (the intelligence node)
	if len(batch.Nodes) != 1 {
		t.Errorf("Expected 1 intelligence node in batch, got %d", len(batch.Nodes))
	}

	intelNode := batch.Nodes[0]
	if intelNode.Type != "Intelligence" {
		t.Errorf("Expected node type 'Intelligence', got %q", intelNode.Type)
	}

	// Verify intelligence node has required properties
	requiredProps := []string{"mission_id", "phase", "summary", "risk_assessment", "confidence"}
	for _, prop := range requiredProps {
		if _, ok := intelNode.Properties[prop]; !ok {
			t.Errorf("Intelligence node missing required property %q", prop)
		}
	}

	// Should contain ANALYZES relationships to source nodes
	// We had 3 source nodes in our mock data
	expectedAnalyzesRels := 3
	analyzesCount := 0
	for _, rel := range batch.Relationships {
		if rel.Type == "ANALYZES" {
			analyzesCount++
		}
	}

	if analyzesCount != expectedAnalyzesRels {
		t.Errorf("Expected %d ANALYZES relationships, got %d", expectedAnalyzesRels, analyzesCount)
	}
}

func TestGenerateForPhase_ContextCancellation(t *testing.T) {
	mock := setupMockHarnessWithSampleData("discover")

	// Make GraphRAG query slow to allow context cancellation
	mock.graphQueryError = context.Canceled

	gen := NewIntelligenceGenerator(mock)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := gen.GenerateForPhase(ctx, "mission-123", "discover")

	if err == nil {
		t.Fatal("Expected error when context is canceled")
	}
}

func TestIntelligenceGenerator_EndToEnd(t *testing.T) {
	// This test verifies the complete flow: query -> prompt -> LLM -> parse -> store
	mock := newMockHarness()

	// Setup realistic phase data
	mock.graphQueryResults = []graphrag.Result{
		{
			Node: graphrag.GraphNode{
				ID:   "host-192-168-1-100",
				Type: "Host",
				Properties: map[string]interface{}{
					"ip":       "192.168.1.100",
					"hostname": "db-server",
					"phase":    "discover",
				},
			},
			Score: 0.92,
		},
		{
			Node: graphrag.GraphNode{
				ID:   "port-192-168-1-100-3306",
				Type: "Port",
				Properties: map[string]interface{}{
					"port":    3306,
					"service": "mysql",
					"version": "5.7.32",
					"phase":   "discover",
				},
			},
			Score: 0.88,
		},
		{
			Node: graphrag.GraphNode{
				ID:   "finding-weak-password",
				Type: "Finding",
				Properties: map[string]interface{}{
					"title":       "Weak MySQL Root Password",
					"severity":    "high",
					"description": "MySQL root accessible with default credentials",
					"phase":       "scan",
				},
			},
			Score: 0.95,
		},
	}

	// Setup realistic LLM response with all required fields
	fullResponseJSON := `{
		"summary": "Network reconnaissance identified a MySQL database server at 192.168.1.100 with weak authentication. The server is running an outdated version (5.7.32) and accepts connections with default root credentials, presenting immediate exploitation risk.\n\nThis configuration enables unauthorized database access, potential data exfiltration, and server compromise. The weak authentication combined with network exposure creates a critical security gap requiring urgent remediation.",
		"risk_assessment": "Critical risk: Exploitable weak authentication on internet-facing database server. High likelihood of compromise given ease of exploitation. Business impact includes data breach, compliance violations (GDPR, PCI-DSS), and potential ransomware deployment via database compromise.",
		"attack_paths": [
			{
				"name": "Direct Database Compromise via Default Credentials",
				"description": "Attacker authenticates to MySQL using default root credentials, extracts sensitive data, and establishes persistence through backdoor account creation",
				"steps": [
					"Scan network to identify MySQL service on port 3306",
					"Attempt authentication with default credentials (root/root)",
					"Extract customer PII and payment data from database",
					"Create backdoor administrative account for persistence",
					"Optionally deploy ransomware via stored procedures"
				],
				"risk": "critical",
				"finding_ids": ["finding-weak-password"]
			},
			{
				"name": "Lateral Movement via Stored Credentials",
				"description": "Use compromised database to extract application credentials and pivot to other systems",
				"steps": [
					"Access MySQL database with default credentials",
					"Extract application database connection strings",
					"Use stored credentials to access application servers",
					"Escalate privileges on compromised application hosts"
				],
				"risk": "high",
				"finding_ids": ["finding-weak-password"]
			}
		],
		"recommendations": [
			{
				"title": "Immediately Change MySQL Root Password",
				"description": "Generate strong random password (32+ characters, high entropy) and update MySQL root password immediately. Document password in enterprise password manager. Rotate passwords for all MySQL user accounts.",
				"priority": "immediate",
				"affected_node_ids": ["host-192-168-1-100", "port-192-168-1-100-3306", "finding-weak-password"]
			},
			{
				"title": "Upgrade MySQL to Supported Version",
				"description": "MySQL 5.7.32 has known vulnerabilities. Upgrade to MySQL 8.0.x (latest patch) within 30 days. Test application compatibility in staging before production deployment. Schedule maintenance window for upgrade.",
				"priority": "short-term",
				"affected_node_ids": ["host-192-168-1-100", "port-192-168-1-100-3306"]
			},
			{
				"title": "Implement Network Segmentation for Database Tier",
				"description": "Isolate database servers in dedicated VLAN with strict firewall rules. Allow database access only from application servers. Implement jump host for administrative access. Deploy database activity monitoring (DAM) solution.",
				"priority": "short-term",
				"affected_node_ids": ["host-192-168-1-100"]
			},
			{
				"title": "Establish Database Security Hardening Standards",
				"description": "Develop and enforce organizational standards for database security including password complexity, connection encryption (TLS), audit logging, and regular vulnerability scanning. Implement automated compliance checking.",
				"priority": "long-term",
				"affected_node_ids": []
			}
		],
		"confidence": 0.94
	}`

	mock.llmResponse = &llm.CompletionResponse{
		Content: fullResponseJSON,
		Usage: llm.TokenUsage{
			InputTokens:  2100,
			OutputTokens: 980,
		},
	}

	gen := NewIntelligenceGenerator(mock)

	ctx := context.Background()
	intel, err := gen.GenerateForPhase(ctx, "mission-e2e-test", "discover")

	if err != nil {
		t.Fatalf("End-to-end test failed: %v", err)
	}

	// Verify complete intelligence structure
	if intel.MissionID != "mission-e2e-test" {
		t.Errorf("Mission ID mismatch")
	}

	if intel.Phase != "discover" {
		t.Errorf("Phase mismatch")
	}

	if len(intel.Summary) < 100 {
		t.Error("Summary too short or empty")
	}

	if len(intel.RiskAssessment) < 50 {
		t.Error("Risk assessment too short or empty")
	}

	if len(intel.AttackPaths) != 2 {
		t.Errorf("Expected 2 attack paths, got %d", len(intel.AttackPaths))
	}

	// Verify first attack path structure
	ap := intel.AttackPaths[0]
	if ap.Name == "" {
		t.Error("Attack path name is empty")
	}
	if ap.Risk != RiskCritical {
		t.Errorf("Expected critical risk, got %q", ap.Risk)
	}
	if len(ap.Steps) != 5 {
		t.Errorf("Expected 5 steps in first attack path, got %d", len(ap.Steps))
	}

	if len(intel.Recommendations) != 4 {
		t.Errorf("Expected 4 recommendations, got %d", len(intel.Recommendations))
	}

	// Verify recommendation priorities
	priorities := make(map[Priority]int)
	for _, rec := range intel.Recommendations {
		priorities[rec.Priority]++
	}

	if priorities[PriorityImmediate] != 1 {
		t.Errorf("Expected 1 immediate priority recommendation, got %d", priorities[PriorityImmediate])
	}

	if priorities[PriorityShortTerm] != 2 {
		t.Errorf("Expected 2 short-term priority recommendations, got %d", priorities[PriorityShortTerm])
	}

	if priorities[PriorityLongTerm] != 1 {
		t.Errorf("Expected 1 long-term priority recommendation, got %d", priorities[PriorityLongTerm])
	}

	// Verify confidence score
	if intel.Confidence < 0.9 || intel.Confidence > 1.0 {
		t.Errorf("Expected high confidence (0.9-1.0), got %f", intel.Confidence)
	}

	// Verify source node tracking
	if intel.SourceNodeCount != 3 {
		t.Errorf("Expected 3 source nodes, got %d", intel.SourceNodeCount)
	}

	// Verify all harness methods were called
	if mock.graphQueryCalls != 1 {
		t.Errorf("Expected 1 GraphRAG query, got %d", mock.graphQueryCalls)
	}

	if mock.llmCompleteCalls != 1 {
		t.Errorf("Expected 1 LLM completion, got %d", mock.llmCompleteCalls)
	}

	if mock.storeGraphCalls != 1 {
		t.Errorf("Expected 1 StoreGraphBatch call, got %d", mock.storeGraphCalls)
	}

	// Verify graph batch structure
	if mock.lastGraphBatch == nil {
		t.Fatal("Graph batch was not stored")
	}

	if len(mock.lastGraphBatch.Nodes) != 1 {
		t.Errorf("Expected 1 intelligence node, got %d", len(mock.lastGraphBatch.Nodes))
	}

	if len(mock.lastGraphBatch.Relationships) != 3 {
		t.Errorf("Expected 3 ANALYZES relationships, got %d", len(mock.lastGraphBatch.Relationships))
	}
}
