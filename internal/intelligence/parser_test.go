package intelligence

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseIntelligenceResponse_ValidJSON(t *testing.T) {
	response := `{
		"summary": "Found multiple critical vulnerabilities in web application",
		"risk_assessment": "High risk of remote code execution",
		"attack_paths": [
			{
				"name": "SQL Injection to RCE",
				"description": "Exploit SQL injection to gain database access and execute system commands",
				"steps": ["Identify SQLi endpoint", "Extract database credentials", "Execute xp_cmdshell"],
				"risk": "critical"
			}
		],
		"recommendations": [
			{
				"title": "Patch SQL injection vulnerabilities",
				"description": "Use parameterized queries to prevent SQL injection",
				"priority": "immediate"
			}
		],
		"confidence": 0.92
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if intel.Summary != "Found multiple critical vulnerabilities in web application" {
		t.Errorf("Summary mismatch: %q", intel.Summary)
	}

	if intel.RiskAssessment != "High risk of remote code execution" {
		t.Errorf("Risk assessment mismatch: %q", intel.RiskAssessment)
	}

	if intel.Confidence != 0.92 {
		t.Errorf("Confidence mismatch: %f", intel.Confidence)
	}

	if len(intel.AttackPaths) != 1 {
		t.Fatalf("Expected 1 attack path, got %d", len(intel.AttackPaths))
	}

	ap := intel.AttackPaths[0]
	if ap.Name != "SQL Injection to RCE" {
		t.Errorf("Attack path name mismatch: %q", ap.Name)
	}

	if ap.Risk != RiskCritical {
		t.Errorf("Attack path risk mismatch: %q", ap.Risk)
	}

	if len(ap.Steps) != 3 {
		t.Errorf("Expected 3 steps, got %d", len(ap.Steps))
	}

	if len(intel.Recommendations) != 1 {
		t.Fatalf("Expected 1 recommendation, got %d", len(intel.Recommendations))
	}

	rec := intel.Recommendations[0]
	if rec.Priority != PriorityImmediate {
		t.Errorf("Recommendation priority mismatch: %q", rec.Priority)
	}
}

func TestParseIntelligenceResponse_MarkdownCodeBlock(t *testing.T) {
	response := "Here's the analysis:\n\n```json\n" +
		`{"summary": "Test summary", "risk_assessment": "Test risk", "attack_paths": [], "recommendations": [], "confidence": 0.8}` +
		"\n```\n\nHope this helps!"

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if intel.Summary != "Test summary" {
		t.Errorf("Summary mismatch: %q", intel.Summary)
	}

	if intel.Confidence != 0.8 {
		t.Errorf("Confidence mismatch: %f", intel.Confidence)
	}
}

func TestParseIntelligenceResponse_MarkdownCodeBlockNoLanguage(t *testing.T) {
	response := "```\n" +
		`{"summary": "Test", "risk_assessment": "Low", "attack_paths": [], "recommendations": [], "confidence": 0.5}` +
		"\n```"

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if intel.Summary != "Test" {
		t.Errorf("Summary mismatch: %q", intel.Summary)
	}
}

func TestParseIntelligenceResponse_SurroundingText(t *testing.T) {
	response := `Based on the reconnaissance data, I've generated the following intelligence report:

	{
		"summary": "Multiple findings detected",
		"risk_assessment": "Medium risk overall",
		"attack_paths": [],
		"recommendations": [],
		"confidence": 0.75
	}

	Let me know if you need more details!`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if intel.Summary != "Multiple findings detected" {
		t.Errorf("Summary mismatch: %q", intel.Summary)
	}
}

func TestParseIntelligenceResponse_MissingFields(t *testing.T) {
	// Missing summary and risk_assessment, but has other data
	response := `{
		"attack_paths": [
			{
				"name": "Test Attack",
				"description": "Test description",
				"steps": ["Step 1"],
				"risk": "high"
			}
		],
		"recommendations": [],
		"confidence": 0.6
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error for partial data, got: %v", err)
	}

	// Should have attack path even with missing fields
	if len(intel.AttackPaths) != 1 {
		t.Errorf("Expected 1 attack path, got %d", len(intel.AttackPaths))
	}

	// Confidence should still be parsed
	if intel.Confidence != 0.6 {
		t.Errorf("Confidence mismatch: %f", intel.Confidence)
	}
}

func TestParseIntelligenceResponse_InvalidConfidence(t *testing.T) {
	tests := []struct {
		name              string
		confidence        float64
		expectedConfidence float64
	}{
		{"Negative confidence", -0.5, 0.0},
		{"Confidence > 1.0", 1.5, 1.0},
		{"Valid confidence", 0.85, 0.85},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := map[string]interface{}{
				"summary":         "Test",
				"risk_assessment": "Test",
				"attack_paths":    []interface{}{},
				"recommendations": []interface{}{},
				"confidence":      tt.confidence,
			}

			jsonBytes, _ := json.Marshal(response)
			intel, err := ParseIntelligenceResponse(string(jsonBytes))
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			if intel.Confidence != tt.expectedConfidence {
				t.Errorf("Expected confidence %f, got %f", tt.expectedConfidence, intel.Confidence)
			}
		})
	}
}

func TestParseIntelligenceResponse_InvalidRiskLevel(t *testing.T) {
	response := `{
		"summary": "Test",
		"risk_assessment": "Test",
		"attack_paths": [
			{
				"name": "Test Attack",
				"description": "Test",
				"steps": ["Step 1"],
				"risk": "super-critical"
			}
		],
		"recommendations": [],
		"confidence": 0.8
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should default to medium for invalid risk level
	if len(intel.AttackPaths) != 1 {
		t.Fatalf("Expected 1 attack path, got %d", len(intel.AttackPaths))
	}

	if intel.AttackPaths[0].Risk != RiskMedium {
		t.Errorf("Expected risk to default to medium, got %q", intel.AttackPaths[0].Risk)
	}
}

func TestParseIntelligenceResponse_InvalidPriority(t *testing.T) {
	response := `{
		"summary": "Test",
		"risk_assessment": "Test",
		"attack_paths": [],
		"recommendations": [
			{
				"title": "Test Recommendation",
				"description": "Test",
				"priority": "super-urgent"
			}
		],
		"confidence": 0.8
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should default to short-term for invalid priority
	if len(intel.Recommendations) != 1 {
		t.Fatalf("Expected 1 recommendation, got %d", len(intel.Recommendations))
	}

	if intel.Recommendations[0].Priority != PriorityShortTerm {
		t.Errorf("Expected priority to default to short-term, got %q", intel.Recommendations[0].Priority)
	}
}

func TestParseIntelligenceResponse_AllRiskLevels(t *testing.T) {
	tests := []struct {
		input    string
		expected RiskLevel
	}{
		{"critical", RiskCritical},
		{"high", RiskHigh},
		{"medium", RiskMedium},
		{"low", RiskLow},
		{"info", RiskInfo},
		{"CRITICAL", RiskCritical}, // Test case insensitivity
		{"High", RiskHigh},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			response := map[string]interface{}{
				"summary":         "Test",
				"risk_assessment": "Test",
				"attack_paths": []interface{}{
					map[string]interface{}{
						"name":        "Test",
						"description": "Test",
						"steps":       []string{"Step 1"},
						"risk":        tt.input,
					},
				},
				"recommendations": []interface{}{},
				"confidence":      0.8,
			}

			jsonBytes, _ := json.Marshal(response)
			intel, err := ParseIntelligenceResponse(string(jsonBytes))
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			if len(intel.AttackPaths) != 1 {
				t.Fatalf("Expected 1 attack path, got %d", len(intel.AttackPaths))
			}

			if intel.AttackPaths[0].Risk != tt.expected {
				t.Errorf("Expected risk %q, got %q", tt.expected, intel.AttackPaths[0].Risk)
			}
		})
	}
}

func TestParseIntelligenceResponse_AllPriorities(t *testing.T) {
	tests := []struct {
		input    string
		expected Priority
	}{
		{"immediate", PriorityImmediate},
		{"short-term", PriorityShortTerm},
		{"short_term", PriorityShortTerm},
		{"shortterm", PriorityShortTerm},
		{"long-term", PriorityLongTerm},
		{"long_term", PriorityLongTerm},
		{"longterm", PriorityLongTerm},
		{"IMMEDIATE", PriorityImmediate}, // Test case insensitivity
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			response := map[string]interface{}{
				"summary":         "Test",
				"risk_assessment": "Test",
				"attack_paths":    []interface{}{},
				"recommendations": []interface{}{
					map[string]interface{}{
						"title":       "Test",
						"description": "Test",
						"priority":    tt.input,
					},
				},
				"confidence": 0.8,
			}

			jsonBytes, _ := json.Marshal(response)
			intel, err := ParseIntelligenceResponse(string(jsonBytes))
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}

			if len(intel.Recommendations) != 1 {
				t.Fatalf("Expected 1 recommendation, got %d", len(intel.Recommendations))
			}

			if intel.Recommendations[0].Priority != tt.expected {
				t.Errorf("Expected priority %q, got %q", tt.expected, intel.Recommendations[0].Priority)
			}
		})
	}
}

func TestParseIntelligenceResponse_EmptyResponse(t *testing.T) {
	_, err := ParseIntelligenceResponse("")
	if err == nil {
		t.Error("Expected error for empty response")
	}
}

func TestParseIntelligenceResponse_InvalidJSON(t *testing.T) {
	response := `{
		"summary": "Test"
		"risk_assessment": "Missing comma here"
	}`

	_, err := ParseIntelligenceResponse(response)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestParseIntelligenceResponse_AllFieldsEmpty(t *testing.T) {
	response := `{
		"summary": "",
		"risk_assessment": "",
		"attack_paths": [],
		"recommendations": [],
		"confidence": 0.5
	}`

	_, err := ParseIntelligenceResponse(response)
	if err == nil {
		t.Error("Expected error when all meaningful fields are empty")
	}
}

func TestParseIntelligenceResponse_TrailingCommaFix(t *testing.T) {
	// This has trailing commas which are invalid JSON but attemptJSONFix should handle
	response := `{
		"summary": "Test summary",
		"risk_assessment": "Test risk",
		"attack_paths": [],
		"recommendations": [],
		"confidence": 0.8,
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected parser to fix trailing comma, got error: %v", err)
	}

	if intel.Summary != "Test summary" {
		t.Errorf("Summary mismatch: %q", intel.Summary)
	}
}

func TestParseIntelligenceResponse_EmptyStepsFiltered(t *testing.T) {
	response := `{
		"summary": "Test",
		"risk_assessment": "Test",
		"attack_paths": [
			{
				"name": "Test Attack",
				"description": "Test",
				"steps": ["Valid step", "", "  ", "Another valid step"],
				"risk": "high"
			}
		],
		"recommendations": [],
		"confidence": 0.8
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if len(intel.AttackPaths) != 1 {
		t.Fatalf("Expected 1 attack path, got %d", len(intel.AttackPaths))
	}

	// Empty strings should be filtered out
	expectedSteps := 2
	if len(intel.AttackPaths[0].Steps) != expectedSteps {
		t.Errorf("Expected %d steps (empty ones filtered), got %d", expectedSteps, len(intel.AttackPaths[0].Steps))
	}
}

func TestParseIntelligenceResponse_DefaultConfidence(t *testing.T) {
	// Response without confidence field
	response := `{
		"summary": "Test",
		"risk_assessment": "Test",
		"attack_paths": [],
		"recommendations": []
	}`

	intel, err := ParseIntelligenceResponse(response)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Should default to 0.5
	if intel.Confidence != 0.5 {
		t.Errorf("Expected default confidence 0.5, got %f", intel.Confidence)
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		contains string
	}{
		{
			name:     "Pure JSON",
			input:    `{"key": "value"}`,
			wantErr:  false,
			contains: "key",
		},
		{
			name:     "Markdown with json language",
			input:    "```json\n{\"key\": \"value\"}\n```",
			wantErr:  false,
			contains: "key",
		},
		{
			name:     "Markdown without language",
			input:    "```\n{\"key\": \"value\"}\n```",
			wantErr:  false,
			contains: "key",
		},
		{
			name:     "JSON with text before and after",
			input:    "Here is the result: {\"key\": \"value\"} Hope this helps!",
			wantErr:  false,
			contains: "key",
		},
		{
			name:    "No JSON",
			input:   "This is just plain text without JSON",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractJSON(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !strings.Contains(result, tt.contains) {
				t.Errorf("extractJSON() result doesn't contain %q: %q", tt.contains, result)
			}
		})
	}
}

func TestAttemptJSONFix(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantFix bool
	}{
		{
			name:    "Trailing comma before }",
			input:   `{"key": "value",}`,
			wantFix: true,
		},
		{
			name:    "Trailing comma before ]",
			input:   `{"arr": [1, 2, 3,]}`,
			wantFix: true,
		},
		{
			name:    "Multiple trailing commas",
			input:   `{"key": "value", "arr": [1,],}`,
			wantFix: true,
		},
		{
			name:    "Already valid JSON",
			input:   `{"key": "value"}`,
			wantFix: true, // Should remain valid
		},
		{
			name:    "Unfixable JSON",
			input:   `{key: value}`, // Missing quotes
			wantFix: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := attemptJSONFix(tt.input)
			gotFix := result != ""

			if gotFix != tt.wantFix {
				t.Errorf("attemptJSONFix() gotFix = %v, wantFix %v", gotFix, tt.wantFix)
			}

			if gotFix {
				// Verify the result is valid JSON
				var testJSON map[string]interface{}
				if err := json.Unmarshal([]byte(result), &testJSON); err != nil {
					t.Errorf("attemptJSONFix() produced invalid JSON: %v", err)
				}
			}
		})
	}
}
