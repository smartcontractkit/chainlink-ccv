package registration

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nodev1 "github.com/smartcontractkit/chainlink-protos/job-distributor/v1/node"
	"github.com/smartcontractkit/chainlink-protos/job-distributor/v1/shared/ptypes"
)

const (
	labelProduct     = "product"
	labelEnvironment = "environment"
	labelType        = "type"
)

// Register reconciles one chain-agnostic node identity in JD without changing its CSA key.
func Register(ctx context.Context, client JDClient, provider CSAKeyProvider, spec NodeSpec) (Result, error) {
	if client == nil {
		return Result{}, fmt.Errorf("JD client is required to register node %s", spec.Name)
	}
	if provider == nil {
		return Result{}, fmt.Errorf("CSA key provider is required to register node %s", spec.Name)
	}
	spec, err := normalizeSpec(spec)
	if err != nil {
		return Result{}, err
	}
	providedKey, err := provider.CSAKey(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("resolve CSA key for node %s: %w", spec.Name, err)
	}
	csaKey, err := normalizeCSAKey(providedKey)
	if err != nil {
		return Result{}, fmt.Errorf("invalid CSA key for node %s: %w", spec.Name, err)
	}

	existing, err := client.GetNode(ctx, &nodev1.GetNodeRequest{PublicKey: &csaKey})
	switch {
	case err == nil:
		return reconcileExistingNode(ctx, client, existing, spec, csaKey)
	case !isJDNotFound(err):
		return Result{}, fmt.Errorf("look up node %s by CSA key: %w", spec.Name, err)
	}

	listResp, err := client.ListNodes(ctx, &nodev1.ListNodesRequest{})
	if err != nil {
		return Result{}, fmt.Errorf("check name conflict for node %s: %w", spec.Name, err)
	}
	if listResp == nil {
		return Result{}, fmt.Errorf("invalid JD response while checking name conflict for node %s", spec.Name)
	}
	for _, node := range listResp.Nodes {
		if node == nil || !strings.EqualFold(node.Name, spec.Name) {
			continue
		}
		if node.Id == "" {
			return Result{}, fmt.Errorf("JD returned node %s with an empty ID", spec.Name)
		}
		if strings.EqualFold(node.PublicKey, csaKey) {
			return reconcileExisting(ctx, client, node, spec)
		}
		return Result{}, fmt.Errorf("node name %s is already registered with a different CSA key and node ID %s", spec.Name, node.Id)
	}

	desiredLabels, err := desiredLabels(spec)
	if err != nil {
		return Result{}, err
	}
	registerResp, err := client.RegisterNode(ctx, &nodev1.RegisterNodeRequest{
		Name:      spec.Name,
		PublicKey: csaKey,
		Labels:    sortedLabels(desiredLabels),
	})
	if err != nil {
		return handleRegisterError(ctx, client, spec, csaKey, err)
	}
	if registerResp == nil || registerResp.Node == nil || registerResp.Node.Id == "" {
		return Result{}, fmt.Errorf("invalid JD response after registering node %s", spec.Name)
	}
	if !strings.EqualFold(registerResp.Node.Name, spec.Name) || !strings.EqualFold(registerResp.Node.PublicKey, csaKey) {
		return Result{}, fmt.Errorf("JD returned a different node after registering %s", spec.Name)
	}
	if !labelsMatch(desiredLabels, labelMap(registerResp.Node.Labels)) {
		return Result{}, fmt.Errorf("invalid JD response after registering node %s: requested labels are missing or mismatched", spec.Name)
	}
	return Result{NodeID: registerResp.Node.Id, Status: StatusRegistered}, nil
}

func handleRegisterError(ctx context.Context, client JDClient, spec NodeSpec, csaKey string, registerErr error) (Result, error) {
	if !isJDAlreadyExists(registerErr) {
		return Result{}, fmt.Errorf("register node %s with JD: %w", spec.Name, registerErr)
	}
	result, err := reconcileExistingByKey(ctx, client, spec, csaKey)
	if err == nil {
		return result, nil
	}
	if isJDNotFound(err) {
		return Result{}, fmt.Errorf("register node %s with JD: %w", spec.Name, registerErr)
	}
	return Result{}, err
}

func reconcileExistingByKey(ctx context.Context, client JDClient, spec NodeSpec, csaKey string) (Result, error) {
	existing, err := client.GetNode(ctx, &nodev1.GetNodeRequest{PublicKey: &csaKey})
	if err != nil {
		return Result{}, err
	}
	return reconcileExistingNode(ctx, client, existing, spec, csaKey)
}

func reconcileExistingNode(ctx context.Context, client JDClient, existing *nodev1.GetNodeResponse, spec NodeSpec, csaKey string) (Result, error) {
	if existing == nil || existing.Node == nil || existing.Node.Id == "" {
		return Result{}, fmt.Errorf("invalid JD response for CSA lookup of node %s", spec.Name)
	}
	if !strings.EqualFold(existing.Node.PublicKey, csaKey) {
		return Result{}, fmt.Errorf("JD returned a different CSA key for node %s", spec.Name)
	}
	if !strings.EqualFold(existing.Node.Name, spec.Name) {
		return Result{}, fmt.Errorf("CSA key for node %s is already registered as %q with node ID %s", spec.Name, existing.Node.Name, existing.Node.Id)
	}
	return reconcileExisting(ctx, client, existing.Node, spec)
}

// RegisterAndWait registers a node and waits for that exact JD record to connect.
func RegisterAndWait(ctx context.Context, client JDClient, provider CSAKeyProvider, spec NodeSpec, wait WaitConfig) (Result, error) {
	result, err := Register(ctx, client, provider, spec)
	if err != nil {
		return result, err
	}
	if err := WaitForConnection(ctx, client, result.NodeID, wait); err != nil {
		return result, fmt.Errorf("node %s (ID %s): %w", spec.Name, result.NodeID, err)
	}
	return result, nil
}

func reconcileExisting(ctx context.Context, client JDClient, existing *nodev1.Node, spec NodeSpec) (Result, error) {
	result := Result{NodeID: existing.Id, Status: StatusExisting}
	desired, err := desiredLabels(spec)
	if err != nil {
		return result, err
	}
	current := labelMap(existing.Labels)
	needsUpdate := false
	for key, value := range desired {
		currentValue, ok := current[key]
		if !ok || currentValue != value {
			needsUpdate = true
			break
		}
	}
	if !needsUpdate {
		return result, nil
	}

	merged := make(map[string]string, len(current)+len(desired))
	maps.Copy(merged, current)
	maps.Copy(merged, desired)
	updateResp, err := client.UpdateNode(ctx, &nodev1.UpdateNodeRequest{
		Id:        existing.Id,
		Name:      existing.Name,
		PublicKey: existing.PublicKey,
		Labels:    sortedLabels(merged),
	})
	if err != nil {
		return result, fmt.Errorf("reconcile labels for node %s: %w", spec.Name, err)
	}
	if updateResp == nil || updateResp.Node == nil || updateResp.Node.Id != existing.Id ||
		updateResp.Node.Name != existing.Name || updateResp.Node.PublicKey != existing.PublicKey ||
		!labelsMatch(merged, labelMap(updateResp.Node.Labels)) {
		return result, fmt.Errorf("invalid JD response after reconciling labels for node %s", spec.Name)
	}
	result.LabelsReconciled = true
	return result, nil
}

func normalizeSpec(spec NodeSpec) (NodeSpec, error) {
	spec.Name = strings.TrimSpace(spec.Name)
	spec.Product = strings.TrimSpace(spec.Product)
	spec.Environment = strings.TrimSpace(spec.Environment)
	if spec.Name == "" || spec.Product == "" || spec.Environment == "" {
		return NodeSpec{}, fmt.Errorf("node name, product, and environment are required")
	}
	_, err := desiredLabels(spec)
	if err != nil {
		return NodeSpec{}, err
	}
	return spec, nil
}

func normalizeCSAKey(key string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(key))
	decoded, err := hex.DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("CSA key must be hex encoded: %w", err)
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("CSA key must be 32 bytes, got %d", len(decoded))
	}
	return normalized, nil
}

func desiredLabels(spec NodeSpec) (map[string]string, error) {
	labels := map[string]string{
		labelProduct:     spec.Product,
		labelEnvironment: spec.Environment,
		labelType:        "plugin",
	}
	if spec.IsBootstrap {
		labels[labelType] = "bootstrap"
	}
	for key, value := range spec.Labels {
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("node %s has an empty label key", spec.Name)
		}
		if _, reserved := labels[key]; reserved {
			return nil, fmt.Errorf("node %s label %q is managed by registration", spec.Name, key)
		}
		labels[key] = value
	}
	return labels, nil
}

func sortedLabels(labels map[string]string) []*ptypes.Label {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]*ptypes.Label, 0, len(keys))
	for _, key := range keys {
		value := labels[key]
		result = append(result, &ptypes.Label{Key: key, Value: &value})
	}
	return result
}

func labelMap(labels []*ptypes.Label) map[string]string {
	result := make(map[string]string, len(labels))
	for _, label := range labels {
		if label == nil {
			continue
		}
		value := ""
		if label.Value != nil {
			value = *label.Value
		}
		result[label.Key] = value
	}
	return result
}

func labelsMatch(expected, actual map[string]string) bool {
	for key, value := range expected {
		actualValue, ok := actual[key]
		if !ok || actualValue != value {
			return false
		}
	}
	return true
}

func isJDAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	if st.Code() == codes.AlreadyExists {
		return true
	}
	return st.Code() == codes.Internal && strings.Contains(st.Message(), "code = AlreadyExists desc =")
}

func isJDNotFound(err error) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	if st.Code() == codes.NotFound {
		return true
	}
	return st.Code() == codes.Internal && strings.Contains(st.Message(), "code = NotFound desc =")
}
