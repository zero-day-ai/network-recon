//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
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
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/proto"
)

// mockIntegrationHarness is a test harness for integration testing the network-recon agent.
// It tracks all interactions and provides predictable responses for LLM, tools, and storage.
type mockIntegrationHarness struct {
	// Tracking state
	llmCalls          []llmCall
	toolCalls         []toolCall
	storedNodes       []*graphragpb.GraphNode
	queriedNodes      []*graphragpb.GraphQuery
	submittedFindings []*finding.Finding

	// Memory tiers
	memoryStore *mockMemoryStore

	// Mission context
	mission types.MissionContext

	// Logger
	logger *slog.Logger

	// LLM response providers
	targetAnalysisResponse *TargetAnalysis
	scanPlanResponses      []*ScanPlan
	intelAnalysisResponses []*IntelAnalysis
	currentPlanIndex       int
	currentIntelIndex      int
}

type llmCall struct {
	slot     string
	messages []llm.Message
	schema   any
}

type toolCall struct {
	name    string
	request proto.Message
}

func newMockIntegrationHarness() *mockIntegrationHarness {
	return &mockIntegrationHarness{
		llmCalls:          []llmCall{},
		toolCalls:         []toolCall{},
		storedNodes:       []*graphragpb.GraphNode{},
		queriedNodes:      []*graphragpb.GraphQuery{},
		submittedFindings: []*finding.Finding{},
		memoryStore:       &mockMemoryStore{working: &mockWorkingMemory{data: make(map[string]any)}},
		mission: types.MissionContext{
			ID:   "test-mission-id",
			Name: "test-mission",
		},
		logger:             slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
		currentPlanIndex:   0,
		currentIntelIndex:  0,
		scanPlanResponses:  []*ScanPlan{},
		intelAnalysisResponses: []*IntelAnalysis{},
	}
}

// CompleteStructured implements the harness interface with mock LLM responses
func (m *mockIntegrationHarness) CompleteStructured(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	// Record the call
	m.llmCalls = append(m.llmCalls, llmCall{
		slot:     slot,
		messages: messages,
		schema:   schema,
	})

	// Determine which response to return based on schema type
	switch schema.(type) {
	case TargetAnalysis:
		if m.targetAnalysisResponse != nil {
			return m.targetAnalysisResponse, nil
		}
		// Default response
		return &TargetAnalysis{
			TargetType:   "subnet",
			NetworkType:  "corporate_lan",
			SizeEstimate: "small (<10)",
			Recommendations: []string{
				"Start with ping sweep to identify live hosts",
				"Follow up with port scan on discovered hosts",
			},
		}, nil

	case ScanPlan:
		if m.currentPlanIndex < len(m.scanPlanResponses) {
			plan := m.scanPlanResponses[m.currentPlanIndex]
			m.currentPlanIndex++
			return plan, nil
		}
		// Default: stop after first iteration
		return &ScanPlan{
			ShouldContinue: false,
			Reasoning:      "Default mock: stopping after first iteration",
			Targets:        []string{},
			Args:           []string{},
		}, nil

	case IntelAnalysis:
		if m.currentIntelIndex < len(m.intelAnalysisResponses) {
			intel := m.intelAnalysisResponses[m.currentIntelIndex]
			m.currentIntelIndex++
			return intel, nil
		}
		// Default response
		return &IntelAnalysis{
			Findings: []NodeIntel{
				{
					NodeType:    "host",
					Identifier:  "192.168.1.1",
					RiskLevel:   "low",
					RiskReasons: []string{"Standard network device"},
					Notes:       "Router or gateway",
				},
			},
			NewHypothesis:   "Standard corporate network segment",
			LearnedPatterns: []string{"Small subnets often have minimal attack surface"},
		}, nil

	default:
		return nil, errors.New("unknown schema type in CompleteStructured")
	}
}

// CallToolProto implements tool calling with mock nmap responses
func (m *mockIntegrationHarness) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	// Record the call
	m.toolCalls = append(m.toolCalls, toolCall{
		name:    name,
		request: request,
	})

	// Handle nmap tool
	if name == "nmap" {
		nmapReq := request.(*toolspb.NmapRequest)
		nmapResp := response.(*toolspb.NmapResponse)

		// Mock nmap response with predictable data
		*nmapResp = toolspb.NmapResponse{
			TotalHosts:   2,
			HostsUp:      2,
			ScanDuration: 5.23,
			Hosts: []*toolspb.NmapHost{
				{
					Ip:       "192.168.1.1",
					Hostname: "gateway.local",
					State:    "up",
					Ports: []*toolspb.NmapPort{
						{
							Number:   22,
							Protocol: "tcp",
							State:    "open",
							Service: &toolspb.NmapService{
								Name:    "ssh",
								Product: "OpenSSH",
								Version: "8.2p1",
							},
						},
						{
							Number:   80,
							Protocol: "tcp",
							State:    "open",
							Service: &toolspb.NmapService{
								Name:    "http",
								Product: "nginx",
								Version: "1.18.0",
							},
						},
					},
				},
				{
					Ip:    "192.168.1.2",
					State: "up",
					Ports: []*toolspb.NmapPort{
						{
							Number:   443,
							Protocol: "tcp",
							State:    "open",
							Service: &toolspb.NmapService{
								Name:    "https",
								Product: "Apache",
								Version: "2.4.41",
							},
						},
					},
				},
			},
		}

		// Include request info in response for tracking
		_ = nmapReq // Used for validation in tests

		return nil
	}

	return errors.New("unsupported tool: " + name)
}

// StoreNode implements node storage and tracks stored nodes
func (m *mockIntegrationHarness) StoreNode(ctx context.Context, node *graphragpb.GraphNode) (string, error) {
	m.storedNodes = append(m.storedNodes, node)
	// Return a mock node ID based on count
	return "node-" + string(rune(len(m.storedNodes))), nil
}

// QueryNodes implements node querying
func (m *mockIntegrationHarness) QueryNodes(ctx context.Context, query *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	m.queriedNodes = append(m.queriedNodes, query)
	return []*graphragpb.QueryResult{}, nil
}

// SubmitFinding tracks submitted findings
func (m *mockIntegrationHarness) SubmitFinding(ctx context.Context, f *finding.Finding) error {
	m.submittedFindings = append(m.submittedFindings, f)
	return nil
}

// Memory returns the mock memory store
func (m *mockIntegrationHarness) Memory() memory.Store {
	return m.memoryStore
}

// Mission returns the mission context
func (m *mockIntegrationHarness) Mission() types.MissionContext {
	return m.mission
}

// Logger returns the logger
func (m *mockIntegrationHarness) Logger() *slog.Logger {
	return m.logger
}

// Tracer returns a no-op tracer
func (m *mockIntegrationHarness) Tracer() trace.Tracer {
	return noop.NewTracerProvider().Tracer("test")
}

// Stub methods for other harness interface requirements
func (m *mockIntegrationHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...llm.CompletionOption) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{Content: "mock complete", FinishReason: "stop"}, nil
}

func (m *mockIntegrationHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return &llm.CompletionResponse{Content: "mock complete with tools", FinishReason: "stop"}, nil
}

func (m *mockIntegrationHarness) Stream(ctx context.Context, slot string, messages []llm.Message) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk, 1)
	ch <- llm.StreamChunk{Delta: "mock", FinishReason: "stop"}
	close(ch)
	return ch, nil
}

func (m *mockIntegrationHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	return m.CompleteStructured(ctx, slot, messages, schema)
}

func (m *mockIntegrationHarness) ListTools(ctx context.Context) ([]tool.Descriptor, error) {
	return []tool.Descriptor{{Name: "nmap"}}, nil
}

func (m *mockIntegrationHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) ListPlugins(ctx context.Context) ([]plugin.Descriptor, error) {
	return []plugin.Descriptor{}, nil
}

func (m *mockIntegrationHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	return agent.NewSuccessResult("delegated"), nil
}

func (m *mockIntegrationHarness) ListAgents(ctx context.Context) ([]agent.Descriptor, error) {
	return []agent.Descriptor{}, nil
}

func (m *mockIntegrationHarness) GetFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	return []*finding.Finding{}, nil
}

func (m *mockIntegrationHarness) Target() types.TargetInfo {
	return types.TargetInfo{ID: "test-target"}
}

func (m *mockIntegrationHarness) TokenUsage() llm.TokenTracker {
	return llm.NewTokenTracker()
}

func (m *mockIntegrationHarness) QueryGraphRAG(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) QuerySemantic(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) QueryStructured(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]graphrag.AttackPattern, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]graphrag.FindingNode, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]graphrag.AttackChain, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) GetRelatedFindings(ctx context.Context, findingID string) ([]graphrag.FindingNode, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) StoreGraphNode(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", nil
}

func (m *mockIntegrationHarness) StoreSemantic(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", nil
}

func (m *mockIntegrationHarness) StoreStructured(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", nil
}

func (m *mockIntegrationHarness) CreateGraphRelationship(ctx context.Context, rel graphrag.Relationship) error {
	return nil
}

func (m *mockIntegrationHarness) StoreGraphBatch(ctx context.Context, batch graphrag.Batch) ([]string, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) TraverseGraph(ctx context.Context, startNodeID string, opts graphrag.TraversalOptions) ([]graphrag.TraversalResult, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) GraphRAGHealth(ctx context.Context) types.HealthStatus {
	return types.NewHealthyStatus("mock healthy")
}

func (m *mockIntegrationHarness) PlanContext() planning.PlanningContext {
	return nil
}

func (m *mockIntegrationHarness) ReportStepHints(ctx context.Context, hints *planning.StepHints) error {
	return nil
}

func (m *mockIntegrationHarness) MissionExecutionContext() types.MissionExecutionContext {
	return types.MissionExecutionContext{}
}

func (m *mockIntegrationHarness) GetMissionRunHistory(ctx context.Context) ([]types.MissionRunSummary, error) {
	return []types.MissionRunSummary{}, nil
}

func (m *mockIntegrationHarness) GetPreviousRunFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	return []*finding.Finding{}, nil
}

func (m *mockIntegrationHarness) GetAllRunFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	return []*finding.Finding{}, nil
}

func (m *mockIntegrationHarness) CreateMission(ctx context.Context, workflow any, targetID string, opts *mission.CreateMissionOpts) (*mission.MissionInfo, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) RunMission(ctx context.Context, missionID string, opts *mission.RunMissionOpts) error {
	return nil
}

func (m *mockIntegrationHarness) GetMissionStatus(ctx context.Context, missionID string) (*mission.MissionStatusInfo, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) WaitForMission(ctx context.Context, missionID string, timeout time.Duration) (*mission.MissionResult, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) ListMissions(ctx context.Context, filter *mission.MissionFilter) ([]*mission.MissionInfo, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) CancelMission(ctx context.Context, missionID string) error {
	return nil
}

func (m *mockIntegrationHarness) GetMissionResults(ctx context.Context, missionID string) (*mission.MissionResult, error) {
	return nil, nil
}

func (m *mockIntegrationHarness) GetCredential(ctx context.Context, name string) (*types.Credential, error) {
	return nil, nil
}

// Mock memory implementations

type mockMemoryStore struct {
	working  *mockWorkingMemory
	mission  *mockMissionMemory
	longTerm *mockLongTermMemory
}

func (m *mockMemoryStore) Working() memory.WorkingMemory {
	if m.working == nil {
		m.working = &mockWorkingMemory{data: make(map[string]any)}
	}
	return m.working
}

func (m *mockMemoryStore) Mission() memory.MissionMemory {
	if m.mission == nil {
		m.mission = &mockMissionMemory{data: make(map[string]any)}
	}
	return m.mission
}

func (m *mockMemoryStore) LongTerm() memory.LongTermMemory {
	if m.longTerm == nil {
		m.longTerm = &mockLongTermMemory{stored: []mockLongTermEntry{}}
	}
	return m.longTerm
}

type mockWorkingMemory struct {
	data map[string]any
}

func (m *mockWorkingMemory) Get(ctx context.Context, key string) (any, error) {
	val, ok := m.data[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return val, nil
}

func (m *mockWorkingMemory) Set(ctx context.Context, key string, value any) error {
	m.data[key] = value
	return nil
}

func (m *mockWorkingMemory) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockWorkingMemory) Clear(ctx context.Context) error {
	m.data = make(map[string]any)
	return nil
}

func (m *mockWorkingMemory) Keys(ctx context.Context) ([]string, error) {
	keys := []string{}
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

type mockMissionMemory struct {
	data map[string]any
}

func (m *mockMissionMemory) Get(ctx context.Context, key string) (*memory.Item, error) {
	val, ok := m.data[key]
	if !ok {
		return nil, errors.New("key not found")
	}
	return &memory.Item{
		Key:   key,
		Value: val,
	}, nil
}

func (m *mockMissionMemory) Set(ctx context.Context, key string, value any, metadata map[string]any) error {
	m.data[key] = value
	return nil
}

func (m *mockMissionMemory) Delete(ctx context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockMissionMemory) Search(ctx context.Context, query string, limit int) ([]memory.Result, error) {
	return []memory.Result{}, nil
}

func (m *mockMissionMemory) History(ctx context.Context, limit int) ([]memory.Item, error) {
	return []memory.Item{}, nil
}

func (m *mockMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	return nil, errors.New("no previous run")
}

func (m *mockMissionMemory) GetValueHistory(ctx context.Context, key string) ([]memory.HistoricalValue, error) {
	return []memory.HistoricalValue{}, nil
}

func (m *mockMissionMemory) ContinuityMode() memory.MemoryContinuityMode {
	return memory.MemoryIsolated
}

type mockLongTermEntry struct {
	content  string
	metadata map[string]any
}

type mockLongTermMemory struct {
	stored []mockLongTermEntry
}

func (m *mockLongTermMemory) Store(ctx context.Context, content string, metadata map[string]any) (string, error) {
	m.stored = append(m.stored, mockLongTermEntry{
		content:  content,
		metadata: metadata,
	})
	return "entry-" + string(rune(len(m.stored))), nil
}

func (m *mockLongTermMemory) Search(ctx context.Context, query string, topK int, filters map[string]any) ([]memory.Result, error) {
	// Return empty results for simplicity
	return []memory.Result{}, nil
}

func (m *mockLongTermMemory) Delete(ctx context.Context, id string) error {
	return nil
}

// Integration Tests

// TestExecuteLoop_SingleIteration verifies that the agent executes a single iteration
// when the LLM decides to stop after the first scan.
func TestExecuteLoop_SingleIteration(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure LLM to stop after first iteration
	harness.scanPlanResponses = []*ScanPlan{
		{
			ShouldContinue: true,
			Reasoning:      "Scan the target subnet",
			Targets:        []string{"192.168.1.0/24"},
			Args:           []string{"-sn"}, // Ping sweep
		},
		{
			ShouldContinue: false,
			Reasoning:      "Sufficient reconnaissance completed",
			Targets:        []string{},
			Args:           []string{},
		},
	}

	// Create task
	task := agent.Task{
		ID:   "test-task-1",
		Goal: "Test single iteration execution",
		Context: map[string]any{
			"target":         "192.168.1.0/24",
			"max_iterations": 5,
		},
	}

	// Execute
	result, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify result
	if result.Status != agent.StatusSuccess {
		t.Errorf("result.Status = %v, want %v", result.Status, agent.StatusSuccess)
	}

	// Verify LLM was called correctly
	// Expected: 1 target analysis + 2 scan plans + 1 intel analysis = 4 calls
	if len(harness.llmCalls) < 3 {
		t.Errorf("LLM calls = %d, want at least 3 (target analysis, scan plan, intel)", len(harness.llmCalls))
	}

	// Verify tool was called once
	if len(harness.toolCalls) != 1 {
		t.Errorf("tool calls = %d, want 1", len(harness.toolCalls))
	}

	// Verify nodes were stored (2 hosts + 3 ports + 3 services = 8 nodes)
	if len(harness.storedNodes) == 0 {
		t.Error("No nodes were stored to graph")
	}

	// Verify Working Memory was used
	working := harness.Memory().Working()
	iter, err := working.Get(ctx, "iteration")
	if err != nil {
		t.Errorf("Working memory 'iteration' not found: %v", err)
	}
	if iter.(int) != 1 {
		t.Errorf("Final iteration = %d, want 1", iter.(int))
	}

	// Verify scan history
	historyVal, err := working.Get(ctx, "scan_history")
	if err != nil {
		t.Errorf("Working memory 'scan_history' not found: %v", err)
	}
	history := historyVal.([]ScanSummary)
	if len(history) != 1 {
		t.Errorf("Scan history length = %d, want 1", len(history))
	}
}

// TestExecuteLoop_MultipleIterations verifies that the agent executes multiple iterations
// in the autonomous loop before stopping.
func TestExecuteLoop_MultipleIterations(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure LLM to run 3 iterations
	harness.scanPlanResponses = []*ScanPlan{
		{
			ShouldContinue: true,
			Reasoning:      "Initial ping sweep",
			Targets:        []string{"192.168.1.0/24"},
			Args:           []string{"-sn"},
		},
		{
			ShouldContinue: true,
			Reasoning:      "Port scan discovered hosts",
			Targets:        []string{"192.168.1.1", "192.168.1.2"},
			Args:           []string{"-p", "1-1000"},
		},
		{
			ShouldContinue: true,
			Reasoning:      "Service detection on open ports",
			Targets:        []string{"192.168.1.1", "192.168.1.2"},
			Args:           []string{"-sV", "-p", "22,80,443"},
		},
		{
			ShouldContinue: false,
			Reasoning:      "Complete reconnaissance achieved",
			Targets:        []string{},
			Args:           []string{},
		},
	}

	// Create task
	task := agent.Task{
		ID:   "test-task-2",
		Goal: "Test multiple iteration execution",
		Context: map[string]any{
			"target":         "192.168.1.0/24",
			"max_iterations": 10,
		},
	}

	// Execute
	result, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify result
	if result.Status != agent.StatusSuccess {
		t.Errorf("result.Status = %v, want %v", result.Status, agent.StatusSuccess)
	}

	// Verify 3 scan iterations occurred
	if len(harness.toolCalls) != 3 {
		t.Errorf("tool calls = %d, want 3", len(harness.toolCalls))
	}

	// Verify Working Memory iteration count
	working := harness.Memory().Working()
	iter, _ := working.Get(ctx, "iteration")
	if iter.(int) != 3 {
		t.Errorf("Final iteration = %d, want 3", iter.(int))
	}

	// Verify scan history has 3 entries
	historyVal, _ := working.Get(ctx, "scan_history")
	history := historyVal.([]ScanSummary)
	if len(history) != 3 {
		t.Errorf("Scan history length = %d, want 3", len(history))
	}

	// Verify result metadata
	metadata := result.Output.(map[string]any)
	if metadata["iterations"].(int) != 3 {
		t.Errorf("Result iterations = %d, want 3", metadata["iterations"].(int))
	}
}

// TestMemoryUsage verifies that all three memory tiers are used correctly.
func TestMemoryUsage(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure LLM to run 1 iteration
	harness.scanPlanResponses = []*ScanPlan{
		{
			ShouldContinue: true,
			Reasoning:      "Scan target",
			Targets:        []string{"192.168.1.0/24"},
			Args:           []string{"-sn"},
		},
		{
			ShouldContinue: false,
			Reasoning:      "Done",
			Targets:        []string{},
			Args:           []string{},
		},
	}

	// Create task
	task := agent.Task{
		ID:   "test-task-3",
		Goal: "Test memory tier usage",
		Context: map[string]any{
			"target":         "192.168.1.0/24",
			"max_iterations": 5,
		},
	}

	// Execute
	_, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify Working Memory usage
	working := harness.Memory().Working()
	keys, _ := working.Keys(ctx)
	expectedKeys := []string{
		"iteration",
		"current_hypothesis",
		"scan_history",
		"pending_targets",
		"total_hosts",
		"total_ports",
		"total_services",
	}
	for _, expectedKey := range expectedKeys {
		found := false
		for _, key := range keys {
			if key == expectedKey {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Working memory missing expected key: %s", expectedKey)
		}
	}

	// Verify Mission Memory usage (target_analysis should be stored)
	mission := harness.Memory().Mission().(*mockMissionMemory)
	if _, ok := mission.data["target_analysis"]; !ok {
		t.Error("Mission memory missing 'target_analysis' key")
	}

	// Verify Long-Term Memory usage (patterns should be stored)
	longTerm := harness.Memory().LongTerm().(*mockLongTermMemory)
	if len(longTerm.stored) == 0 {
		t.Error("Long-term memory has no stored patterns")
	}
}

// TestNodeStorage verifies that storeNodes is called with correct Host/Port/Service nodes.
func TestNodeStorage(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure LLM to run 1 iteration
	harness.scanPlanResponses = []*ScanPlan{
		{
			ShouldContinue: true,
			Reasoning:      "Scan target",
			Targets:        []string{"192.168.1.0/24"},
			Args:           []string{"-sV"},
		},
		{
			ShouldContinue: false,
			Reasoning:      "Done",
			Targets:        []string{},
			Args:           []string{},
		},
	}

	// Create task
	task := agent.Task{
		ID:   "test-task-4",
		Goal: "Test node storage to graph",
		Context: map[string]any{
			"target":         "192.168.1.0/24",
			"max_iterations": 5,
		},
	}

	// Execute
	_, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify nodes were stored
	if len(harness.storedNodes) == 0 {
		t.Fatal("No nodes were stored")
	}

	// Count node types
	hostCount := 0
	portCount := 0
	serviceCount := 0

	for _, node := range harness.storedNodes {
		switch node.Type {
		case "Host":
			hostCount++
			// Verify host has required properties
			if node.Properties["ip"] == nil {
				t.Error("Host node missing 'ip' property")
			}
		case "Port":
			portCount++
			// Verify port has required properties
			if node.Properties["number"] == nil {
				t.Error("Port node missing 'number' property")
			}
			if node.Properties["protocol"] == nil {
				t.Error("Port node missing 'protocol' property")
			}
		case "Service":
			serviceCount++
			// Verify service has required properties
			if node.Properties["name"] == nil {
				t.Error("Service node missing 'name' property")
			}
		}
	}

	// Verify expected counts (2 hosts, 3 ports, 3 services from mock response)
	if hostCount != 2 {
		t.Errorf("Host nodes = %d, want 2", hostCount)
	}
	if portCount != 3 {
		t.Errorf("Port nodes = %d, want 3", portCount)
	}
	if serviceCount != 3 {
		t.Errorf("Service nodes = %d, want 3", serviceCount)
	}
}

// TestMaxIterationsLimit verifies that the loop respects the max_iterations limit.
func TestMaxIterationsLimit(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure LLM to always continue (never stop)
	harness.scanPlanResponses = []*ScanPlan{}
	for i := 0; i < 10; i++ {
		harness.scanPlanResponses = append(harness.scanPlanResponses, &ScanPlan{
			ShouldContinue: true,
			Reasoning:      "Continue scanning",
			Targets:        []string{"192.168.1.0/24"},
			Args:           []string{"-sn"},
		})
	}

	// Create task with max_iterations = 3
	task := agent.Task{
		ID:   "test-task-5",
		Goal: "Test max iterations limit",
		Context: map[string]any{
			"target":         "192.168.1.0/24",
			"max_iterations": 3,
		},
	}

	// Execute
	result, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify result
	if result.Status != agent.StatusSuccess {
		t.Errorf("result.Status = %v, want %v", result.Status, agent.StatusSuccess)
	}

	// Verify exactly 3 iterations occurred
	if len(harness.toolCalls) != 3 {
		t.Errorf("tool calls = %d, want 3 (limited by max_iterations)", len(harness.toolCalls))
	}

	// Verify result metadata
	metadata := result.Output.(map[string]any)
	if metadata["iterations"].(int) != 3 {
		t.Errorf("Result iterations = %d, want 3", metadata["iterations"].(int))
	}
}

// TestLLMResponseParsing verifies that LLM JSON responses are correctly parsed.
func TestLLMResponseParsing(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure custom LLM responses with specific data
	harness.targetAnalysisResponse = &TargetAnalysis{
		TargetType:   "single_host",
		NetworkType:  "cloud",
		SizeEstimate: "small (<10)",
		Recommendations: []string{
			"Focus on cloud-specific vulnerabilities",
			"Check for exposed management interfaces",
		},
	}

	harness.scanPlanResponses = []*ScanPlan{
		{
			ShouldContinue: false, // Stop immediately
			Reasoning:      "Target is a single host, no further scanning needed",
			Targets:        []string{},
			Args:           []string{},
		},
	}

	// Create task
	task := agent.Task{
		ID:   "test-task-6",
		Goal: "Test LLM response parsing",
		Context: map[string]any{
			"target":         "10.0.0.1",
			"max_iterations": 5,
		},
	}

	// Execute
	_, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify target analysis was stored in Mission Memory
	mission := harness.Memory().Mission().(*mockMissionMemory)
	analysisVal, ok := mission.data["target_analysis"]
	if !ok {
		t.Fatal("target_analysis not stored in Mission memory")
	}

	analysis := analysisVal.(*TargetAnalysis)
	if analysis.TargetType != "single_host" {
		t.Errorf("TargetType = %s, want 'single_host'", analysis.TargetType)
	}
	if analysis.NetworkType != "cloud" {
		t.Errorf("NetworkType = %s, want 'cloud'", analysis.NetworkType)
	}
}

// TestIntelAnalysis verifies that intelligence analysis produces findings and updates hypothesis.
func TestIntelAnalysis(t *testing.T) {
	ctx := context.Background()
	harness := newMockIntegrationHarness()

	// Configure LLM with specific intelligence analysis response
	harness.intelAnalysisResponses = []*IntelAnalysis{
		{
			Findings: []NodeIntel{
				{
					NodeType:    "host",
					Identifier:  "192.168.1.1",
					RiskLevel:   "high",
					RiskReasons: []string{"SSH exposed on internet", "Outdated OpenSSH version"},
					Notes:       "Gateway host with elevated risk",
				},
				{
					NodeType:    "service",
					Identifier:  "ssh",
					RiskLevel:   "medium",
					RiskReasons: []string{"Common attack vector"},
					Notes:       "Monitor for brute force attempts",
				},
			},
			NewHypothesis:   "Internet-facing infrastructure with potential vulnerabilities",
			LearnedPatterns: []string{"Exposed SSH services often indicate admin access points"},
		},
	}

	harness.scanPlanResponses = []*ScanPlan{
		{
			ShouldContinue: true,
			Reasoning:      "Scan target",
			Targets:        []string{"192.168.1.0/24"},
			Args:           []string{"-sV"},
		},
		{
			ShouldContinue: false,
			Reasoning:      "Done",
			Targets:        []string{},
			Args:           []string{},
		},
	}

	// Create task
	task := agent.Task{
		ID:   "test-task-7",
		Goal: "Test intelligence analysis",
		Context: map[string]any{
			"target":         "192.168.1.0/24",
			"max_iterations": 5,
		},
	}

	// Execute
	_, err := executeRecon(ctx, harness, task)
	if err != nil {
		t.Fatalf("executeRecon() error = %v", err)
	}

	// Verify hypothesis was updated in Working Memory
	working := harness.Memory().Working()
	hypothesisVal, err := working.Get(ctx, "current_hypothesis")
	if err != nil {
		t.Fatalf("current_hypothesis not found in Working memory: %v", err)
	}

	hypothesis := hypothesisVal.(string)
	if hypothesis != "Internet-facing infrastructure with potential vulnerabilities" {
		t.Errorf("Hypothesis = %s, want 'Internet-facing infrastructure with potential vulnerabilities'", hypothesis)
	}

	// Verify patterns were stored in Long-Term Memory
	longTerm := harness.Memory().LongTerm().(*mockLongTermMemory)
	if len(longTerm.stored) == 0 {
		t.Error("No patterns stored in Long-Term memory")
	}

	// Check that at least one pattern matches expected content
	foundPattern := false
	for _, entry := range longTerm.stored {
		if entry.content == "Exposed SSH services often indicate admin access points" {
			foundPattern = true
			// Verify metadata
			if entry.metadata["type"] != "security_pattern" {
				t.Errorf("Pattern metadata type = %v, want 'security_pattern'", entry.metadata["type"])
			}
			break
		}
	}
	if !foundPattern {
		t.Error("Expected pattern not found in Long-Term memory")
	}
}

// Helper function to pretty-print JSON for debugging
func prettyPrint(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
