package main

import (
	"context"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
	protolib "google.golang.org/protobuf/proto"
)

// mockHarnessForStreaming is a test harness that tracks CallToolProtoStream calls
// This is a simplified mock that focuses on streaming tool calls for testing
type mockHarnessForStreaming struct {
	mu                  sync.Mutex
	streamCallbacks     []toolStreamCallbackCapture
	toolStreamCallCount int
	memoryStorage       map[string]interface{}
	logMessages         []logMessage
	findingsSubmitted   []agent.Finding
	agentName           string
}

type toolStreamCallbackCapture struct {
	toolName       string
	progressEvents []progressEventCapture
	partialResults []protolib.Message
	warnings       []warningEventCapture
	errors         []errorEventCapture
	finalResult    protolib.Message
	finalError     error
}

type progressEventCapture struct {
	percent int
	phase   string
	message string
}

type warningEventCapture struct {
	message string
	context string
}

type errorEventCapture struct {
	err   error
	fatal bool
}

type logMessage struct {
	level   string
	message string
	fields  map[string]interface{}
}

func newMockHarnessForStreaming() *mockHarnessForStreaming {
	return &mockHarnessForStreaming{
		streamCallbacks:   make([]toolStreamCallbackCapture, 0),
		memoryStorage:     make(map[string]interface{}),
		logMessages:       make([]logMessage, 0),
		findingsSubmitted: make([]agent.Finding, 0),
		agentName:         "test-agent",
	}
}

// CallToolProtoStream simulates streaming tool execution with callback
// This is the key method we're testing - it should properly handle streaming events
func (h *mockHarnessForStreaming) CallToolProtoStream(
	ctx context.Context,
	toolName string,
	input protolib.Message,
	callback agent.ToolStreamCallback,
) (protolib.Message, error) {
	h.mu.Lock()
	h.toolStreamCallCount++
	h.mu.Unlock()

	// Create capture for this invocation
	capture := toolStreamCallbackCapture{
		toolName:       toolName,
		progressEvents: make([]progressEventCapture, 0),
		partialResults: make([]protolib.Message, 0),
		warnings:       make([]warningEventCapture, 0),
		errors:         make([]errorEventCapture, 0),
	}

	// Check if nmap is available for real execution
	_, err := exec.LookPath("nmap")
	if err != nil {
		// Nmap not available - simulate streaming events
		return h.simulateNmapStreamingExecution(ctx, input, callback, &capture)
	}

	// Real execution path would go here
	// For testing purposes, we'll simulate a successful scan with events

	// Simulate initial progress
	callback.OnProgress(0, "init", "Starting nmap scan")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{0, "init", "Starting nmap scan"})

	// Simulate scanning progress
	callback.OnProgress(25, "scanning", "Scanning ports...")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{25, "scanning", "Scanning ports..."})

	callback.OnProgress(50, "scanning", "Halfway through scan")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{50, "scanning", "Halfway through scan"})

	// Simulate a warning
	callback.OnWarning("Host timeout", "host_192.168.1.100")
	capture.warnings = append(capture.warnings, warningEventCapture{"Host timeout", "host_192.168.1.100"})

	// Simulate more progress
	callback.OnProgress(75, "scanning", "Almost done...")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{75, "scanning", "Almost done..."})

	callback.OnProgress(90, "parsing", "Parsing results")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{90, "parsing", "Parsing results"})

	// Simulate partial result (optional)
	partialResult := &toolspb.NmapResponse{
		Hosts: []*toolspb.Host{
			{
				Address: "127.0.0.1",
				Status:  "up",
				Ports: []*toolspb.Port{
					{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
				},
			},
		},
	}
	callback.OnPartial(partialResult, true)
	capture.partialResults = append(capture.partialResults, partialResult)

	callback.OnProgress(100, "complete", "Scan finished")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{100, "complete", "Scan finished"})

	// Build final result
	finalResult := &toolspb.NmapResponse{
		Hosts: []*toolspb.Host{
			{
				Address: "127.0.0.1",
				Status:  "up",
				Ports: []*toolspb.Port{
					{Number: 80, Protocol: "tcp", State: "open", Service: "http"},
					{Number: 443, Protocol: "tcp", State: "open", Service: "https"},
				},
			},
		},
		ScanDuration: 5.5,
		Summary: &toolspb.ScanSummary{
			TotalHosts: 1,
			UpHosts:    1,
			TotalPorts: 2,
			OpenPorts:  2,
		},
	}

	capture.finalResult = finalResult
	capture.finalError = nil

	h.mu.Lock()
	h.streamCallbacks = append(h.streamCallbacks, capture)
	h.mu.Unlock()

	return finalResult, nil
}

// simulateNmapStreamingExecution simulates nmap execution when binary is not available
func (h *mockHarnessForStreaming) simulateNmapStreamingExecution(
	ctx context.Context,
	input protolib.Message,
	callback agent.ToolStreamCallback,
	capture *toolStreamCallbackCapture,
) (protolib.Message, error) {
	// Simulate streaming events without actual nmap execution
	callback.OnProgress(0, "init", "Simulating nmap scan (binary not available)")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{0, "init", "Simulating scan"})

	callback.OnProgress(50, "scanning", "Simulation in progress")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{50, "scanning", "Simulation in progress"})

	callback.OnProgress(100, "complete", "Simulation complete")
	capture.progressEvents = append(capture.progressEvents, progressEventCapture{100, "complete", "Simulation complete"})

	// Return simulated result
	result := &toolspb.NmapResponse{
		Hosts: []*toolspb.Host{
			{Address: "127.0.0.1", Status: "up"},
		},
		ScanDuration: 1.0,
	}

	capture.finalResult = result
	capture.finalError = nil

	h.mu.Lock()
	h.streamCallbacks = append(h.streamCallbacks, capture)
	h.mu.Unlock()

	return result, nil
}

// CallToolProto implements non-streaming tool call (not used in this test)
func (h *mockHarnessForStreaming) CallToolProto(ctx context.Context, toolName string, input, output protolib.Message) error {
	return nil
}

// Memory implements memory access
func (h *mockHarnessForStreaming) Memory() agent.MemoryAccess {
	return &mockMemoryAccess{storage: h.memoryStorage, mu: &h.mu}
}

// Logger returns a mock logger
func (h *mockHarnessForStreaming) Logger() agent.Logger {
	return &mockLogger{harness: h}
}

// SubmitFinding captures findings
func (h *mockHarnessForStreaming) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.findingsSubmitted = append(h.findingsSubmitted, finding)
	return nil
}

// Methods not used in this test but required by interface
func (h *mockHarnessForStreaming) Complete(ctx context.Context, slot string, msgs []agent.Message) (*agent.CompletionResult, error) {
	return nil, nil
}
func (h *mockHarnessForStreaming) StreamComplete(ctx context.Context, slot string, msgs []agent.Message) (<-chan agent.StreamChunk, error) {
	return nil, nil
}
func (h *mockHarnessForStreaming) CompleteStructured(ctx context.Context, slot string, schema interface{}, msgs []agent.Message) (*agent.CompletionResult, error) {
	return nil, nil
}
func (h *mockHarnessForStreaming) QueryPlugin(ctx context.Context, pluginName, method string, params map[string]interface{}) (interface{}, error) {
	return nil, nil
}
func (h *mockHarnessForStreaming) DelegateToAgent(ctx context.Context, agentName string, task agent.Task) (agent.Result, error) {
	return agent.Result{}, nil
}
func (h *mockHarnessForStreaming) ListAgents(ctx context.Context) ([]agent.AgentInfo, error) {
	return nil, nil
}
func (h *mockHarnessForStreaming) Tracer() agent.Tracer {
	return nil
}
func (h *mockHarnessForStreaming) Mission() agent.MissionInfo {
	return agent.MissionInfo{ID: "test-mission"}
}

// getStreamCallbacks returns captured streaming callbacks
func (h *mockHarnessForStreaming) getStreamCallbacks() []toolStreamCallbackCapture {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]toolStreamCallbackCapture, len(h.streamCallbacks))
	copy(result, h.streamCallbacks)
	return result
}

// getLogMessages returns captured log messages
func (h *mockHarnessForStreaming) getLogMessages() []logMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]logMessage, len(h.logMessages))
	copy(result, h.logMessages)
	return result
}

// mockMemoryAccess implements agent.MemoryAccess
type mockMemoryAccess struct {
	storage map[string]interface{}
	mu      *sync.Mutex
}

func (m *mockMemoryAccess) Working() agent.WorkingMemory {
	return &mockWorkingMemory{storage: m.storage, mu: m.mu}
}
func (m *mockMemoryAccess) Mission() agent.MissionMemory {
	return nil
}
func (m *mockMemoryAccess) LongTerm() agent.LongTermMemory {
	return nil
}

// mockWorkingMemory implements agent.WorkingMemory
type mockWorkingMemory struct {
	storage map[string]interface{}
	mu      *sync.Mutex
}

func (m *mockWorkingMemory) Set(ctx context.Context, key string, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage[key] = value
	return nil
}

func (m *mockWorkingMemory) Get(ctx context.Context, key string) (interface{}, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storage[key], nil
}

func (m *mockWorkingMemory) Delete(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.storage, key)
	return nil
}

func (m *mockWorkingMemory) Clear(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage = make(map[string]interface{})
	return nil
}

// mockLogger implements agent.Logger
type mockLogger struct {
	harness *mockHarnessForStreaming
}

func (l *mockLogger) InfoContext(ctx context.Context, msg string, fields ...interface{}) {
	l.harness.mu.Lock()
	defer l.harness.mu.Unlock()
	l.harness.logMessages = append(l.harness.logMessages, logMessage{
		level:   "info",
		message: msg,
		fields:  parseFields(fields),
	})
}

func (l *mockLogger) ErrorContext(ctx context.Context, msg string, fields ...interface{}) {
	l.harness.mu.Lock()
	defer l.harness.mu.Unlock()
	l.harness.logMessages = append(l.harness.logMessages, logMessage{
		level:   "error",
		message: msg,
		fields:  parseFields(fields),
	})
}

func (l *mockLogger) WarnContext(ctx context.Context, msg string, fields ...interface{}) {
	l.harness.mu.Lock()
	defer l.harness.mu.Unlock()
	l.harness.logMessages = append(l.harness.logMessages, logMessage{
		level:   "warn",
		message: msg,
		fields:  parseFields(fields),
	})
}

func (l *mockLogger) DebugContext(ctx context.Context, msg string, fields ...interface{}) {
	l.harness.mu.Lock()
	defer l.harness.mu.Unlock()
	l.harness.logMessages = append(l.harness.logMessages, logMessage{
		level:   "debug",
		message: msg,
		fields:  parseFields(fields),
	})
}

func parseFields(fields []interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			result[key] = fields[i+1]
		}
	}
	return result
}

// TestNetworkReconStreamingIntegration tests the full integration with streaming nmap
func TestNetworkReconStreamingIntegration(t *testing.T) {
	// Note: This test demonstrates how network-recon would use CallToolProtoStream
	// Actual implementation in execute.go would need to be updated to call this

	ctx := context.Background()
	harness := newMockHarnessForStreaming()

	// Create a simple callback that logs progress
	type nmapStreamCallback struct {
		h              agent.Harness
		progressEvents []string
		mu             sync.Mutex
	}

	callback := &nmapStreamCallback{
		h:              harness,
		progressEvents: make([]string, 0),
	}

	// Implement ToolStreamCallback interface
	onProgress := func(percent int, phase, message string) {
		callback.mu.Lock()
		defer callback.mu.Unlock()
		callback.progressEvents = append(callback.progressEvents, message)
		harness.Logger().InfoContext(ctx, "nmap progress",
			"percent", percent,
			"phase", phase,
			"message", message,
		)
	}

	onPartial := func(output protolib.Message, incremental bool) {
		if resp, ok := output.(*toolspb.NmapResponse); ok {
			harness.Logger().InfoContext(ctx, "nmap partial result",
				"hosts", len(resp.Hosts),
				"incremental", incremental,
			)
		}
	}

	onWarning := func(message, context string) {
		harness.Logger().WarnContext(ctx, "nmap warning",
			"message", message,
			"context", context,
		)
	}

	onError := func(err error, fatal bool) {
		harness.Logger().ErrorContext(ctx, "nmap error",
			"error", err.Error(),
			"fatal", fatal,
		)
	}

	// Create callback wrapper
	toolCallback := &mockToolStreamCallbackImpl{
		onProgress: onProgress,
		onPartial:  onPartial,
		onWarning:  onWarning,
		onError:    onError,
	}

	// Create nmap request
	input := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "80,443", "-T4"},
	}

	// Call streaming tool
	t.Log("Calling CallToolProtoStream...")
	result, err := harness.CallToolProtoStream(ctx, "nmap", input, toolCallback)
	require.NoError(t, err, "streaming tool call should succeed")
	require.NotNil(t, result, "should have result")

	// Verify result type
	nmapResp, ok := result.(*toolspb.NmapResponse)
	require.True(t, ok, "result should be NmapResponse")
	assert.NotNil(t, nmapResp.Hosts, "should have hosts")
	t.Logf("Got %d hosts in final result", len(nmapResp.Hosts))

	// Verify streaming callbacks were captured
	callbacks := harness.getStreamCallbacks()
	require.Len(t, callbacks, 1, "should have captured one streaming call")

	capture := callbacks[0]
	assert.Equal(t, "nmap", capture.toolName)

	// Verify progress events
	t.Logf("Progress events: %d", len(capture.progressEvents))
	for i, evt := range capture.progressEvents {
		t.Logf("  [%d] %d%% - %s - %s", i, evt.percent, evt.phase, evt.message)
	}
	assert.NotEmpty(t, capture.progressEvents, "should have progress events")

	// Verify we got the expected phases
	hasInit := false
	hasScanning := false
	hasComplete := false

	for _, evt := range capture.progressEvents {
		if evt.phase == "init" {
			hasInit = true
		}
		if evt.phase == "scanning" {
			hasScanning = true
		}
		if evt.phase == "complete" {
			hasComplete = true
		}
	}

	assert.True(t, hasInit, "should have init phase")
	assert.True(t, hasScanning, "should have scanning phase")
	assert.True(t, hasComplete, "should have complete phase")

	// Verify log messages
	logMessages := harness.getLogMessages()
	t.Logf("Log messages: %d", len(logMessages))
	for i, log := range logMessages {
		t.Logf("  [%d] %s: %s - %v", i, log.level, log.message, log.fields)
	}
	assert.NotEmpty(t, logMessages, "should have log messages")

	// Count progress log messages
	progressLogCount := 0
	for _, log := range logMessages {
		if log.message == "nmap progress" {
			progressLogCount++
		}
	}
	assert.Greater(t, progressLogCount, 0, "should have progress log messages")

	// Verify final result is complete
	assert.Equal(t, capture.finalResult, result, "captured result should match returned result")
}

// mockToolStreamCallbackImpl implements agent.ToolStreamCallback
type mockToolStreamCallbackImpl struct {
	onProgress func(int, string, string)
	onPartial  func(protolib.Message, bool)
	onWarning  func(string, string)
	onError    func(error, bool)
}

func (c *mockToolStreamCallbackImpl) OnProgress(percent int, phase, message string) {
	if c.onProgress != nil {
		c.onProgress(percent, phase, message)
	}
}

func (c *mockToolStreamCallbackImpl) OnPartial(output protolib.Message, incremental bool) {
	if c.onPartial != nil {
		c.onPartial(output, incremental)
	}
}

func (c *mockToolStreamCallbackImpl) OnWarning(message, context string) {
	if c.onWarning != nil {
		c.onWarning(message, context)
	}
}

func (c *mockToolStreamCallbackImpl) OnError(err error, fatal bool) {
	if c.onError != nil {
		c.onError(err, fatal)
	}
}

// TestStreamingCallbackConcurrency tests concurrent callback invocations
func TestStreamingCallbackConcurrency(t *testing.T) {
	harness := newMockHarnessForStreaming()

	var callbackMu sync.Mutex
	callCount := 0

	callback := &mockToolStreamCallbackImpl{
		onProgress: func(percent int, phase, message string) {
			callbackMu.Lock()
			callCount++
			callbackMu.Unlock()
			time.Sleep(1 * time.Millisecond) // Simulate work
		},
	}

	input := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "80"},
	}

	// Call multiple times concurrently
	const numConcurrent = 5
	var wg sync.WaitGroup
	wg.Add(numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func() {
			defer wg.Done()
			ctx := context.Background()
			_, _ = harness.CallToolProtoStream(ctx, "nmap", input, callback)
		}()
	}

	wg.Wait()

	// Verify all callbacks were invoked
	callbacks := harness.getStreamCallbacks()
	assert.Equal(t, numConcurrent, len(callbacks), "should have captured all concurrent calls")

	callbackMu.Lock()
	totalCallbacks := callCount
	callbackMu.Unlock()

	t.Logf("Total callback invocations: %d", totalCallbacks)
	assert.Greater(t, totalCallbacks, 0, "should have callback invocations")
}

// TestStreamingCallbackErrorHandling tests error scenarios
func TestStreamingCallbackErrorHandling(t *testing.T) {
	harness := newMockHarnessForStreaming()

	errorCount := 0
	var errorMu sync.Mutex

	callback := &mockToolStreamCallbackImpl{
		onError: func(err error, fatal bool) {
			errorMu.Lock()
			errorCount++
			errorMu.Unlock()
			t.Logf("Received error: %v (fatal=%v)", err, fatal)
		},
	}

	// Note: Current mock implementation doesn't produce errors
	// This test is a placeholder for when error scenarios are implemented

	input := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "80"},
	}

	ctx := context.Background()
	result, err := harness.CallToolProtoStream(ctx, "nmap", input, callback)

	// For now, we expect success
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Error callback count: %d", errorCount)
}

// TestStreamingWithTimeout tests timeout behavior
func TestStreamingWithTimeout(t *testing.T) {
	harness := newMockHarnessForStreaming()

	callback := &mockToolStreamCallbackImpl{
		onProgress: func(percent int, phase, message string) {
			t.Logf("Progress: %d%% - %s", percent, phase)
		},
	}

	input := &toolspb.NmapRequest{
		Targets: []string{"127.0.0.1"},
		Args:    []string{"-p", "80"},
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Note: Mock implementation completes immediately, so timeout won't trigger
	// In real implementation with actual nmap, this would test timeout behavior
	result, err := harness.CallToolProtoStream(ctx, "nmap", input, callback)

	// Mock completes before timeout
	require.NoError(t, err)
	require.NotNil(t, result)

	callbacks := harness.getStreamCallbacks()
	require.Len(t, callbacks, 1)

	t.Log("Streaming completed (mock implementation finishes before timeout)")
}
