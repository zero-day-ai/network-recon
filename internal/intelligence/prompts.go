package intelligence

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PhasePromptTemplate generates an LLM prompt for analyzing reconnaissance data from a specific phase.
// The prompt instructs the LLM to analyze provided entities (hosts, ports, endpoints, technologies,
// findings) and generate structured security intelligence including risk assessment, attack paths,
// and remediation recommendations.
//
// The template is designed to stay under 2000 tokens (including placeholders) to leave room for
// reconnaissance data in the actual prompt. The LLM is instructed to return strictly valid JSON
// matching the expected output format.
const PhasePromptTemplate = `You are a senior security analyst conducting a security assessment of a network environment. You have been provided with reconnaissance data from the {{.Phase}} phase of an automated security scan.

**Your Task:**
Analyze the provided reconnaissance data and generate actionable security intelligence. Focus on identifying security risks, potential attack vectors, and prioritized remediation recommendations.

**Reconnaissance Phase: {{.Phase}}**

{{.PhaseDescription}}

**Reconnaissance Data:**
{{.Data}}

**Analysis Requirements:**
1. Provide an executive summary (2-4 paragraphs) of the key security findings
2. Assess the overall risk posture based on discovered assets and vulnerabilities
3. Identify potential attack paths that adversaries could exploit
4. Provide prioritized, actionable remediation recommendations
5. Assign a confidence score (0.0-1.0) indicating data quality and analysis certainty

**Output Format:**
You MUST respond with ONLY valid JSON matching this exact structure. Do not include any text before or after the JSON.

{
  "summary": "Executive summary of security findings from this phase (2-4 paragraphs)",
  "risk_assessment": "Overall risk evaluation including severity, likelihood, and potential impact",
  "attack_paths": [
    {
      "name": "Short descriptive name (e.g., 'Unauthenticated RCE via Exposed Admin Panel')",
      "description": "Detailed attack scenario explanation including prerequisites and potential impact",
      "steps": [
        "Step 1: Initial access method",
        "Step 2: Privilege escalation technique",
        "Step 3: Lateral movement or impact action"
      ],
      "risk": "critical|high|medium|low",
      "finding_ids": ["finding-id-1", "finding-id-2"]
    }
  ],
  "recommendations": [
    {
      "title": "Short actionable recommendation (e.g., 'Patch Apache Struts to 2.5.30+')",
      "description": "Detailed implementation guidance including specific steps and configurations",
      "priority": "immediate|short-term|long-term",
      "affected_node_ids": ["node-id-1", "node-id-2"]
    }
  ],
  "confidence": 0.85
}

**Important Guidelines:**
- Base your analysis strictly on the provided reconnaissance data
- Do not speculate about data not present in the reconnaissance output
- Prioritize findings based on exploitability and potential impact
- Use technical precision in describing attack paths and recommendations
- Assign "immediate" priority only to critical risks requiring urgent action
- Include finding_ids and affected_node_ids from the reconnaissance data where applicable
- If insufficient data exists for confident analysis, lower the confidence score accordingly

**Response:**`

// SummaryPromptTemplate generates an LLM prompt for synthesizing mission-wide security intelligence
// across all reconnaissance phases. This prompt instructs the LLM to analyze data from multiple
// phases (discover, probe, scan, domain) to produce a comprehensive security assessment covering
// the complete attack surface.
const SummaryPromptTemplate = `You are a senior security analyst producing a comprehensive security assessment report for executive leadership. You have been provided with reconnaissance data from a complete multi-phase security scan of a network environment.

**Your Task:**
Synthesize findings across all reconnaissance phases (discover, probe, scan, domain) into a cohesive security intelligence report. Provide strategic insights about the overall security posture, critical risks, and prioritized remediation roadmap.

**Mission Context:**
- Mission ID: {{.MissionID}}
- Phases Completed: {{.PhasesCompleted}}
- Total Entities Analyzed: {{.TotalNodes}}

**Reconnaissance Data by Phase:**
{{.Data}}

**Analysis Requirements:**
1. Provide an executive summary suitable for security leadership (3-5 paragraphs)
2. Assess the overall security posture and risk exposure across the entire environment
3. Identify critical attack paths that span multiple phases (e.g., reconnaissance → initial access → privilege escalation)
4. Provide a prioritized remediation roadmap organized by immediate, short-term, and long-term actions
5. Assign a confidence score (0.0-1.0) indicating overall data quality and analysis certainty

**Output Format:**
You MUST respond with ONLY valid JSON matching this exact structure. Do not include any text before or after the JSON.

{
  "summary": "Executive summary synthesizing findings across all phases (3-5 paragraphs, suitable for leadership)",
  "risk_assessment": "Comprehensive risk evaluation covering the complete attack surface with business impact context",
  "attack_paths": [
    {
      "name": "Short descriptive name for multi-phase attack scenario",
      "description": "End-to-end attack narrative spanning discovery through impact",
      "steps": [
        "Step 1: Initial reconnaissance technique",
        "Step 2: Initial access method",
        "Step 3: Privilege escalation or lateral movement",
        "Step 4: Impact or data exfiltration"
      ],
      "risk": "critical|high|medium|low",
      "finding_ids": ["finding-id-1", "finding-id-2", "finding-id-3"]
    }
  ],
  "recommendations": [
    {
      "title": "Strategic recommendation title",
      "description": "Comprehensive implementation guidance with business justification",
      "priority": "immediate|short-term|long-term",
      "affected_node_ids": ["node-id-1", "node-id-2", "node-id-3"]
    }
  ],
  "confidence": 0.85
}

**Important Guidelines:**
- Synthesize patterns and trends across all phases, not just isolated findings
- Highlight relationships between discoveries (e.g., vulnerable service on exposed host)
- Prioritize recommendations that address multiple findings or systemic issues
- Frame risk assessment in business impact terms (availability, confidentiality, integrity)
- Assign "immediate" priority to critical issues requiring urgent executive attention
- Provide strategic context for long-term recommendations (architecture, processes, culture)
- If data quality varies across phases, adjust confidence score and note gaps in risk_assessment

**Response:**`

// PhaseDescriptions maps reconnaissance phases to their security analysis context.
// These descriptions help the LLM understand what types of security insights to extract
// from each phase's reconnaissance data.
var PhaseDescriptions = map[string]string{
	"discover": `The discover phase performed network host and port scanning to identify live systems and exposed services. 
Security Focus: Identify exposed attack surface, unnecessary services, unexpected hosts, and potential entry points.`,

	"probe": `The probe phase performed HTTP/HTTPS endpoint probing and technology fingerprinting.
Security Focus: Identify web application attack surface, outdated software versions, exposed admin interfaces, and technology stack vulnerabilities.`,

	"scan": `The scan phase performed vulnerability scanning against discovered endpoints and services.
Security Focus: Identify exploitable vulnerabilities, misconfigurations, weak authentication, and known CVEs.`,

	"domain": `The domain phase performed DNS enumeration, subdomain discovery, and domain reconnaissance.
Security Focus: Identify exposed subdomains, DNS misconfigurations, shadow IT, and potential phishing attack vectors.`,
}

// PhasePromptData contains the data used to populate the PhasePromptTemplate.
type PhasePromptData struct {
	// Phase is the reconnaissance phase being analyzed (discover, probe, scan, domain).
	Phase string

	// PhaseDescription provides security-focused context about what this phase discovers.
	PhaseDescription string

	// Data contains the JSON-formatted reconnaissance entities from the knowledge graph.
	// This should be a structured representation of hosts, ports, endpoints, findings, etc.
	Data string
}

// SummaryPromptData contains the data used to populate the SummaryPromptTemplate.
type SummaryPromptData struct {
	// MissionID identifies the mission being analyzed.
	MissionID string

	// PhasesCompleted lists the reconnaissance phases that have completed.
	PhasesCompleted string

	// TotalNodes is the count of entities analyzed across all phases.
	TotalNodes int

	// Data contains the JSON-formatted reconnaissance entities from all phases.
	// This should be organized by phase for clarity.
	Data string
}

// BuildPhasePrompt constructs a complete LLM prompt for phase-specific security analysis.
// It populates the PhasePromptTemplate with reconnaissance data and phase context.
//
// The phase parameter specifies which reconnaissance phase is being analyzed.
// The entities parameter contains the knowledge graph entities (as a map or struct) to be analyzed.
//
// Returns the complete prompt string ready for LLM completion, or an error if prompt
// construction fails (e.g., JSON marshaling error, unknown phase).
func BuildPhasePrompt(phase string, entities interface{}) (string, error) {
	phaseDesc, ok := PhaseDescriptions[phase]
	if !ok {
		return "", fmt.Errorf("unknown phase: %s", phase)
	}

	// Marshal entities to JSON for inclusion in prompt
	dataJSON, err := json.MarshalIndent(entities, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal entities to JSON: %w", err)
	}

	data := PhasePromptData{
		Phase:            phase,
		PhaseDescription: phaseDesc,
		Data:             string(dataJSON),
	}

	prompt := PhasePromptTemplate
	prompt = strings.ReplaceAll(prompt, "{{.Phase}}", data.Phase)
	prompt = strings.ReplaceAll(prompt, "{{.PhaseDescription}}", data.PhaseDescription)
	prompt = strings.ReplaceAll(prompt, "{{.Data}}", data.Data)

	return prompt, nil
}

// BuildSummaryPrompt constructs a complete LLM prompt for mission-wide security analysis.
// It populates the SummaryPromptTemplate with reconnaissance data from all phases.
//
// The missionID parameter identifies the mission context.
// The phasesCompleted parameter lists the phases that have finished (e.g., "discover, probe, scan, domain").
// The totalNodes parameter indicates the total entity count across all phases.
// The entitiesByPhase parameter contains the knowledge graph entities organized by phase.
//
// Returns the complete prompt string ready for LLM completion, or an error if prompt
// construction fails (e.g., JSON marshaling error).
func BuildSummaryPrompt(missionID string, phasesCompleted []string, totalNodes int, entitiesByPhase interface{}) (string, error) {
	// Marshal entities to JSON for inclusion in prompt
	dataJSON, err := json.MarshalIndent(entitiesByPhase, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal entities to JSON: %w", err)
	}

	data := SummaryPromptData{
		MissionID:       missionID,
		PhasesCompleted: strings.Join(phasesCompleted, ", "),
		TotalNodes:      totalNodes,
		Data:            string(dataJSON),
	}

	prompt := SummaryPromptTemplate
	prompt = strings.ReplaceAll(prompt, "{{.MissionID}}", data.MissionID)
	prompt = strings.ReplaceAll(prompt, "{{.PhasesCompleted}}", data.PhasesCompleted)
	prompt = strings.ReplaceAll(prompt, "{{.TotalNodes}}", fmt.Sprintf("%d", data.TotalNodes))
	prompt = strings.ReplaceAll(prompt, "{{.Data}}", data.Data)

	return prompt, nil
}

// EstimatePromptTokens provides a rough estimate of token count for a prompt string.
// This uses a simple heuristic of ~4 characters per token, which is approximate but
// sufficient for ensuring prompts stay under token limits.
//
// For production use with specific LLM providers, consider using provider-specific
// tokenization libraries for accurate counts.
func EstimatePromptTokens(prompt string) int {
	// Rough estimate: ~4 characters per token
	return len(prompt) / 4
}
