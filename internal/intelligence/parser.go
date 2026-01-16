package intelligence

import (
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
)

// llmResponse represents the expected JSON structure from LLM completion.
// This mirrors the Intelligence struct but uses pointers for partial parsing.
type llmResponse struct {
	Summary        *string            `json:"summary"`
	RiskAssessment *string            `json:"risk_assessment"`
	AttackPaths    []llmAttackPath    `json:"attack_paths"`
	Recommendations []llmRecommendation `json:"recommendations"`
	Confidence     *float64           `json:"confidence"`
}

// llmAttackPath represents an attack path in the LLM response.
type llmAttackPath struct {
	Name        *string  `json:"name"`
	Description *string  `json:"description"`
	Steps       []string `json:"steps"`
	Risk        *string  `json:"risk"`
}

// llmRecommendation represents a recommendation in the LLM response.
type llmRecommendation struct {
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Priority    *string `json:"priority"`
}

// ParseIntelligenceResponse parses an LLM response string into an Intelligence struct.
// It handles malformed JSON gracefully by extracting partial data when possible and
// returning warnings for validation issues.
//
// The LLM response may contain:
// - Pure JSON
// - JSON wrapped in markdown code blocks (```json ... ```)
// - JSON with surrounding text/commentary
//
// Returns:
// - Intelligence struct with parsed data (may be partial)
// - Error if critical parsing failures occur (returns partial data + error)
// - Nil error if parsing succeeds (may log warnings for non-critical issues)
func ParseIntelligenceResponse(response string) (*Intelligence, error) {
	// Extract JSON from response (may be wrapped in markdown or have extra text)
	jsonStr, err := extractJSON(response)
	if err != nil {
		return nil, fmt.Errorf("failed to extract JSON from response: %w", err)
	}

	// Parse JSON into intermediate structure
	var llmResp llmResponse
	if err := json.Unmarshal([]byte(jsonStr), &llmResp); err != nil {
		// Try to recover partial data by attempting to fix common JSON issues
		fixedJSON := attemptJSONFix(jsonStr)
		if fixedJSON != "" {
			if err := json.Unmarshal([]byte(fixedJSON), &llmResp); err != nil {
				return nil, fmt.Errorf("failed to parse JSON (even after fix attempt): %w", err)
			}
			log.Printf("[WARN] Intelligence parser: Fixed malformed JSON, proceeding with partial data")
		} else {
			return nil, fmt.Errorf("failed to parse JSON: %w", err)
		}
	}

	// Convert to Intelligence struct with validation and normalization
	intel, warnings := convertAndValidate(&llmResp)

	// Log warnings but don't fail on non-critical issues
	if len(warnings) > 0 {
		for _, w := range warnings {
			log.Printf("[WARN] Intelligence parser: %s", w)
		}
	}

	// Check if we have at least some critical data
	if intel.Summary == "" && intel.RiskAssessment == "" && len(intel.AttackPaths) == 0 && len(intel.Recommendations) == 0 {
		return intel, fmt.Errorf("parsed intelligence contains no meaningful data (all fields empty)")
	}

	return intel, nil
}

// extractJSON extracts JSON content from an LLM response that may contain
// markdown code blocks or surrounding text.
//
// Supports:
// - Pure JSON: {"key": "value"}
// - Markdown blocks: ```json\n{...}\n```
// - Markdown blocks without language: ```\n{...}\n```
// - JSON with surrounding text
func extractJSON(response string) (string, error) {
	response = strings.TrimSpace(response)

	// Pattern 1: Try to extract from markdown code blocks
	// Matches ```json\n{...}\n``` or ```\n{...}\n```
	codeBlockPattern := regexp.MustCompile("(?s)```(?:json)?\n?(.*?)\n?```")
	if matches := codeBlockPattern.FindStringSubmatch(response); len(matches) > 1 {
		return strings.TrimSpace(matches[1]), nil
	}

	// Pattern 2: Try to find JSON object boundaries
	// Find first { and last } to extract JSON from surrounding text
	firstBrace := strings.Index(response, "{")
	lastBrace := strings.LastIndex(response, "}")

	if firstBrace == -1 || lastBrace == -1 || firstBrace >= lastBrace {
		return "", fmt.Errorf("no valid JSON object found in response")
	}

	jsonStr := response[firstBrace : lastBrace+1]

	// Basic validation: must contain at least one key-value pair
	if !strings.Contains(jsonStr, ":") {
		return "", fmt.Errorf("extracted string does not appear to be valid JSON")
	}

	return jsonStr, nil
}

// attemptJSONFix attempts to fix common JSON formatting issues.
// Returns fixed JSON string on success, empty string on failure.
func attemptJSONFix(jsonStr string) string {
	// Common fix 1: Remove trailing commas before } or ]
	trailingCommaPattern := regexp.MustCompile(`,(\s*[}\]])`)
	fixed := trailingCommaPattern.ReplaceAllString(jsonStr, "$1")

	// Common fix 2: Replace single quotes with double quotes (if they appear to be quote chars)
	// This is risky, so only do it if there are no double quotes already
	if !strings.Contains(fixed, `"`) && strings.Contains(fixed, "'") {
		fixed = strings.ReplaceAll(fixed, "'", `"`)
	}

	// Validate that the fix worked
	var testJSON map[string]interface{}
	if err := json.Unmarshal([]byte(fixed), &testJSON); err != nil {
		return "" // Fix didn't work
	}

	return fixed
}

// convertAndValidate converts the LLM response structure to Intelligence struct
// with validation and normalization. Returns the struct and a list of warnings.
func convertAndValidate(llmResp *llmResponse) (*Intelligence, []string) {
	var warnings []string

	intel := &Intelligence{}

	// Extract summary with validation
	if llmResp.Summary != nil {
		intel.Summary = strings.TrimSpace(*llmResp.Summary)
		if intel.Summary == "" {
			warnings = append(warnings, "summary field present but empty")
		}
	} else {
		warnings = append(warnings, "summary field missing")
	}

	// Extract risk assessment with validation
	if llmResp.RiskAssessment != nil {
		intel.RiskAssessment = strings.TrimSpace(*llmResp.RiskAssessment)
		if intel.RiskAssessment == "" {
			warnings = append(warnings, "risk_assessment field present but empty")
		}
	} else {
		warnings = append(warnings, "risk_assessment field missing")
	}

	// Extract confidence with validation and normalization
	if llmResp.Confidence != nil {
		intel.Confidence = *llmResp.Confidence

		// Normalize confidence to 0.0-1.0 range
		if intel.Confidence < 0.0 {
			warnings = append(warnings, fmt.Sprintf("confidence value %f < 0.0, clamping to 0.0", intel.Confidence))
			intel.Confidence = 0.0
		} else if intel.Confidence > 1.0 {
			warnings = append(warnings, fmt.Sprintf("confidence value %f > 1.0, clamping to 1.0", intel.Confidence))
			intel.Confidence = 1.0
		}
	} else {
		warnings = append(warnings, "confidence field missing, defaulting to 0.5")
		intel.Confidence = 0.5 // Default to medium confidence
	}

	// Extract attack paths with validation
	for i, ap := range llmResp.AttackPaths {
		attackPath := AttackPath{}
		pathWarnings := []string{}

		if ap.Name != nil {
			attackPath.Name = strings.TrimSpace(*ap.Name)
			if attackPath.Name == "" {
				pathWarnings = append(pathWarnings, "name is empty")
			}
		} else {
			pathWarnings = append(pathWarnings, "name field missing")
		}

		if ap.Description != nil {
			attackPath.Description = strings.TrimSpace(*ap.Description)
			if attackPath.Description == "" {
				pathWarnings = append(pathWarnings, "description is empty")
			}
		} else {
			pathWarnings = append(pathWarnings, "description field missing")
		}

		// Copy steps, filtering empty ones
		for _, step := range ap.Steps {
			trimmed := strings.TrimSpace(step)
			if trimmed != "" {
				attackPath.Steps = append(attackPath.Steps, trimmed)
			}
		}
		if len(attackPath.Steps) == 0 {
			pathWarnings = append(pathWarnings, "no valid steps provided")
		}

		// Validate and normalize risk level
		if ap.Risk != nil {
			riskStr := strings.ToLower(strings.TrimSpace(*ap.Risk))
			switch riskStr {
			case "critical":
				attackPath.Risk = RiskCritical
			case "high":
				attackPath.Risk = RiskHigh
			case "medium":
				attackPath.Risk = RiskMedium
			case "low":
				attackPath.Risk = RiskLow
			case "info":
				attackPath.Risk = RiskInfo
			default:
				pathWarnings = append(pathWarnings, fmt.Sprintf("invalid risk level %q, defaulting to medium", riskStr))
				attackPath.Risk = RiskMedium
			}
		} else {
			pathWarnings = append(pathWarnings, "risk field missing, defaulting to medium")
			attackPath.Risk = RiskMedium
		}

		// Only include attack path if it has at least a name or description
		if attackPath.Name != "" || attackPath.Description != "" {
			intel.AttackPaths = append(intel.AttackPaths, attackPath)
		}

		// Log warnings for this attack path
		if len(pathWarnings) > 0 {
			warnings = append(warnings, fmt.Sprintf("attack_path[%d]: %s", i, strings.Join(pathWarnings, ", ")))
		}
	}

	// Extract recommendations with validation
	for i, rec := range llmResp.Recommendations {
		recommendation := Recommendation{}
		recWarnings := []string{}

		if rec.Title != nil {
			recommendation.Title = strings.TrimSpace(*rec.Title)
			if recommendation.Title == "" {
				recWarnings = append(recWarnings, "title is empty")
			}
		} else {
			recWarnings = append(recWarnings, "title field missing")
		}

		if rec.Description != nil {
			recommendation.Description = strings.TrimSpace(*rec.Description)
			if recommendation.Description == "" {
				recWarnings = append(recWarnings, "description is empty")
			}
		} else {
			recWarnings = append(recWarnings, "description field missing")
		}

		// Validate and normalize priority
		if rec.Priority != nil {
			priorityStr := strings.ToLower(strings.TrimSpace(*rec.Priority))
			switch priorityStr {
			case "immediate":
				recommendation.Priority = PriorityImmediate
			case "short-term", "short_term", "shortterm":
				recommendation.Priority = PriorityShortTerm
			case "long-term", "long_term", "longterm":
				recommendation.Priority = PriorityLongTerm
			default:
				recWarnings = append(recWarnings, fmt.Sprintf("invalid priority %q, defaulting to short-term", priorityStr))
				recommendation.Priority = PriorityShortTerm
			}
		} else {
			recWarnings = append(recWarnings, "priority field missing, defaulting to short-term")
			recommendation.Priority = PriorityShortTerm
		}

		// Only include recommendation if it has at least a title or description
		if recommendation.Title != "" || recommendation.Description != "" {
			intel.Recommendations = append(intel.Recommendations, recommendation)
		}

		// Log warnings for this recommendation
		if len(recWarnings) > 0 {
			warnings = append(warnings, fmt.Sprintf("recommendation[%d]: %s", i, strings.Join(recWarnings, ", ")))
		}
	}

	return intel, warnings
}
