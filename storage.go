package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/api/gen/toolspb"
)

// storeNodes iterates through the NmapResponse and stores Host, Port, and Service nodes in Neo4j.
// It creates proper relationships: Port -> Host, Service -> Port.
// If a node already exists (based on natural key), it will be updated rather than duplicated.
func storeNodes(ctx context.Context, harness agent.Harness, nmapResponse *toolspb.NmapResponse) {
	logger := harness.Logger()

	if nmapResponse == nil || len(nmapResponse.Hosts) == 0 {
		logger.InfoContext(ctx, "No hosts to store in graph")
		return
	}

	logger.InfoContext(ctx, "Storing scan results in Neo4j graph", "host_count", len(nmapResponse.Hosts))

	for _, host := range nmapResponse.Hosts {
		if host == nil {
			continue
		}

		// Store Host node
		hostNodeID, err := storeHostNode(ctx, harness, host)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to store host node", "ip", host.Ip, "error", err)
			continue // Continue processing other hosts
		}

		logger.DebugContext(ctx, "Stored host node", "ip", host.Ip, "node_id", hostNodeID)

		// Store Port and Service nodes for this host
		for _, port := range host.Ports {
			if port == nil {
				continue
			}

			portNodeID, err := storePortNode(ctx, harness, port, host.Ip)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to store port node",
					"ip", host.Ip,
					"port", port.Number,
					"error", err)
				continue
			}

			logger.DebugContext(ctx, "Stored port node",
				"ip", host.Ip,
				"port", port.Number,
				"node_id", portNodeID)

			// Store Service node if service detection was performed
			if port.Service != nil {
				serviceNodeID, err := storeServiceNode(ctx, harness, port.Service, host.Ip, port.Number)
				if err != nil {
					logger.ErrorContext(ctx, "Failed to store service node",
						"ip", host.Ip,
						"port", port.Number,
						"service", port.Service.Name,
						"error", err)
					continue
				}

				logger.DebugContext(ctx, "Stored service node",
					"ip", host.Ip,
					"port", port.Number,
					"service", port.Service.Name,
					"node_id", serviceNodeID)
			}
		}
	}

	logger.InfoContext(ctx, "Completed storing scan results in graph")
}

// storeHostNode creates a Host node in Neo4j with all available properties.
func storeHostNode(ctx context.Context, harness agent.Harness, host *toolspb.NmapHost) (string, error) {
	// Build properties map
	properties := make(map[string]*graphragpb.Value)

	// Required properties
	properties["ip"] = stringValue(host.Ip)
	properties["state"] = stringValue(host.State)

	// Optional properties
	if host.Hostname != "" {
		properties["hostname"] = stringValue(host.Hostname)
	}
	if host.StateReason != "" {
		properties["state_reason"] = stringValue(host.StateReason)
	}
	if len(host.Hostnames) > 0 {
		properties["hostnames"] = stringValue(strings.Join(host.Hostnames, ","))
	}
	if host.Distance > 0 {
		properties["distance"] = intValue(int64(host.Distance))
	}
	if host.Uptime > 0 {
		properties["uptime"] = intValue(host.Uptime)
	}
	if host.LastBoot != "" {
		properties["last_boot"] = stringValue(host.LastBoot)
	}

	// OS detection information
	if len(host.OsMatches) > 0 {
		bestMatch := host.OsMatches[0]
		properties["os_name"] = stringValue(bestMatch.Name)
		properties["os_accuracy"] = intValue(int64(bestMatch.Accuracy))

		if len(bestMatch.Classes) > 0 {
			bestClass := bestMatch.Classes[0]
			if bestClass.OsFamily != "" {
				properties["os_family"] = stringValue(bestClass.OsFamily)
			}
			if bestClass.Vendor != "" {
				properties["os_vendor"] = stringValue(bestClass.Vendor)
			}
			if len(bestClass.Cpe) > 0 {
				properties["os_cpe"] = stringValue(bestClass.Cpe[0])
			}
		}
	}

	// Create GraphNode
	node := &graphragpb.GraphNode{
		Type:       "Host",
		Properties: properties,
		Content:    fmt.Sprintf("Host %s (%s) - %s", host.Ip, host.Hostname, host.State),
	}

	// Store node via harness
	nodeID, err := harness.StoreNode(ctx, node)
	if err != nil {
		return "", fmt.Errorf("failed to store host node: %w", err)
	}

	return nodeID, nil
}

// storePortNode creates a Port node in Neo4j with relationship to its Host.
func storePortNode(ctx context.Context, harness agent.Harness, port *toolspb.NmapPort, hostIP string) (string, error) {
	// Build properties map
	properties := make(map[string]*graphragpb.Value)

	// Required properties
	properties["number"] = intValue(int64(port.Number))
	properties["protocol"] = stringValue(port.Protocol)
	properties["state"] = stringValue(port.State)

	// Optional properties
	if port.StateReason != "" {
		properties["state_reason"] = stringValue(port.StateReason)
	}

	// Create unique identifier for parent relationship
	parentID := hostIP
	parentType := "Host"
	parentRelationship := "HAS_PORT"

	// Create GraphNode with parent reference
	node := &graphragpb.GraphNode{
		Type:               "Port",
		Properties:         properties,
		Content:            fmt.Sprintf("Port %d/%s on %s - %s", port.Number, port.Protocol, hostIP, port.State),
		ParentId:           &parentID,
		ParentType:         &parentType,
		ParentRelationship: &parentRelationship,
	}

	// Store node via harness
	nodeID, err := harness.StoreNode(ctx, node)
	if err != nil {
		return "", fmt.Errorf("failed to store port node: %w", err)
	}

	return nodeID, nil
}

// storeServiceNode creates a Service node in Neo4j with relationship to its Port.
func storeServiceNode(ctx context.Context, harness agent.Harness, service *toolspb.NmapService, hostIP string, portNumber int32) (string, error) {
	// Build properties map
	properties := make(map[string]*graphragpb.Value)

	// Required properties
	properties["name"] = stringValue(service.Name)

	// Optional properties
	if service.Product != "" {
		properties["product"] = stringValue(service.Product)
	}
	if service.Version != "" {
		properties["version"] = stringValue(service.Version)
	}
	if service.ExtraInfo != "" {
		properties["extra_info"] = stringValue(service.ExtraInfo)
	}
	if service.Method != "" {
		properties["method"] = stringValue(service.Method)
	}
	if service.Confidence > 0 {
		properties["confidence"] = intValue(int64(service.Confidence))
	}
	if len(service.Cpe) > 0 {
		properties["cpe"] = stringValue(service.Cpe[0])
		if len(service.Cpe) > 1 {
			properties["cpe_list"] = stringValue(strings.Join(service.Cpe, ","))
		}
	}
	if service.Hostname != "" {
		properties["hostname"] = stringValue(service.Hostname)
	}
	if service.OsType != "" {
		properties["os_type"] = stringValue(service.OsType)
	}
	if service.DeviceType != "" {
		properties["device_type"] = stringValue(service.DeviceType)
	}

	// Create unique identifier for parent relationship
	// Port is identified by host IP + port number + protocol
	parentID := fmt.Sprintf("%s:%d", hostIP, portNumber)
	parentType := "Port"
	parentRelationship := "RUNS_SERVICE"

	// Build content for semantic search
	content := fmt.Sprintf("Service %s", service.Name)
	if service.Product != "" {
		content += fmt.Sprintf(" (%s", service.Product)
		if service.Version != "" {
			content += fmt.Sprintf(" %s", service.Version)
		}
		content += ")"
	}
	content += fmt.Sprintf(" on %s:%d", hostIP, portNumber)

	// Create GraphNode with parent reference
	node := &graphragpb.GraphNode{
		Type:               "Service",
		Properties:         properties,
		Content:            content,
		ParentId:           &parentID,
		ParentType:         &parentType,
		ParentRelationship: &parentRelationship,
	}

	// Store node via harness
	nodeID, err := harness.StoreNode(ctx, node)
	if err != nil {
		return "", fmt.Errorf("failed to store service node: %w", err)
	}

	return nodeID, nil
}

// updateNodeWithIntel updates an existing node in Neo4j with risk intelligence properties.
// This adds: risk_level, risk_reasons, attack_surface_notes, recommended_next_steps.
func updateNodeWithIntel(ctx context.Context, harness agent.Harness, nodeIntel NodeIntel) error {
	logger := harness.Logger()

	// Query for the existing node based on type and identifier
	query := &graphragpb.GraphQuery{
		NodeTypes: []string{capitalizeNodeType(nodeIntel.NodeType)},
		Filters: map[string]string{
			"identifier": nodeIntel.Identifier,
		},
		TopK: 1,
	}

	results, err := harness.QueryNodes(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query node: %w", err)
	}

	if len(results) == 0 {
		logger.WarnContext(ctx, "Node not found for intel update",
			"node_type", nodeIntel.NodeType,
			"identifier", nodeIntel.Identifier)
		return nil // Not an error - node may not have been stored yet
	}

	// Get the existing node
	existingNode := results[0].Node

	// Update properties with intel
	if existingNode.Properties == nil {
		existingNode.Properties = make(map[string]*graphragpb.Value)
	}

	existingNode.Properties["risk_level"] = stringValue(nodeIntel.RiskLevel)
	existingNode.Properties["risk_reasons"] = stringValue(strings.Join(nodeIntel.RiskReasons, "; "))
	existingNode.Properties["notes"] = stringValue(nodeIntel.Notes)

	// Store the updated node
	_, err = harness.StoreNode(ctx, existingNode)
	if err != nil {
		return fmt.Errorf("failed to update node with intel: %w", err)
	}

	logger.InfoContext(ctx, "Updated node with risk intel",
		"node_type", nodeIntel.NodeType,
		"identifier", nodeIntel.Identifier,
		"risk_level", nodeIntel.RiskLevel)

	return nil
}

// Helper functions to create graphragpb.Value instances

func stringValue(s string) *graphragpb.Value {
	return &graphragpb.Value{
		Kind: &graphragpb.Value_StringValue{
			StringValue: s,
		},
	}
}

func intValue(i int64) *graphragpb.Value {
	return &graphragpb.Value{
		Kind: &graphragpb.Value_IntValue{
			IntValue: i,
		},
	}
}

func boolValue(b bool) *graphragpb.Value {
	return &graphragpb.Value{
		Kind: &graphragpb.Value_BoolValue{
			BoolValue: b,
		},
	}
}

func doubleValue(d float64) *graphragpb.Value {
	return &graphragpb.Value{
		Kind: &graphragpb.Value_DoubleValue{
			DoubleValue: d,
		},
	}
}

// capitalizeNodeType converts node type to proper case for Neo4j labels
// "host" -> "Host", "port" -> "Port", "service" -> "Service"
func capitalizeNodeType(nodeType string) string {
	if nodeType == "" {
		return ""
	}
	// Simple title case for single words
	return strings.ToUpper(nodeType[:1]) + strings.ToLower(nodeType[1:])
}
