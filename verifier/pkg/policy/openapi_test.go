package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// specPath is the published endpoint contract, relative to this package.
const specPath = "../../policy_hook_openapi_v1.yaml"

type openAPISchema struct {
	Properties map[string]struct {
		Enum []string `yaml:"enum"`
	} `yaml:"properties"`
	Required []string `yaml:"required"`
	Type     string   `yaml:"type"`
}

type openAPISpec struct {
	OpenAPI    string `yaml:"openapi"`
	Components struct {
		Schemas map[string]openAPISchema `yaml:"schemas"`
	} `yaml:"components"`
	Paths map[string]map[string]struct {
		OperationID string `yaml:"operationId"`
	} `yaml:"paths"`
}

func loadSpec(t *testing.T) openAPISpec {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	require.NoError(t, err, "the published contract must live at %s", specPath)

	var spec openAPISpec
	require.NoError(t, yaml.Unmarshal(raw, &spec))
	return spec
}

// jsonFields returns the JSON field names of a struct, and the subset that is required (a field
// without omitempty is always present on the wire).
func jsonFields(t *testing.T, v any) (all, required []string) {
	t.Helper()

	typ := reflect.TypeOf(v)
	require.Equal(t, reflect.Struct, typ.Kind())

	for field := range typ.Fields() {
		tag := field.Tag.Get("json")
		require.NotEmpty(t, tag, "%s.%s has no json tag, so it cannot be checked against the spec",
			typ.Name(), field.Name)

		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "-" {
			continue
		}
		all = append(all, name)
		if !slices.Contains(parts[1:], "omitempty") {
			required = append(required, name)
		}
	}
	slices.Sort(all)
	slices.Sort(required)
	return all, required
}

// The Go types now come from the spec, so asserting they match it is circular: a field or an enum
// value removed from the spec removes the generated identifier and fails to compile. What
// generation does not cover is behavior, and this is the behavior worth pinning. HOLD stays
// published so adding it later is additive for an endpoint validating strictly, and the client
// keeps refusing it, so the reservation cannot quietly become a verdict that signs or drops a
// message.
func TestReservedHoldIsRefused(t *testing.T) {
	_, err := parseDecision(DecisionHold)
	require.Error(t, err, "HOLD is reserved: honouring it would hold or drop a message on behavior v1 does not have")
	assert.Contains(t, err.Error(), "reserved")
	assert.Contains(t, err.Error(), string(DecisionFail),
		"the error must point the operator at the supported way to hold a message")
}

// The one part of the contract generation does not tie to the code. The generated client hard
// codes the operation path it read from the spec, while EvaluatePath is written by hand in
// config.go: it is what Config.EvaluateURL reports and what validation rejects a base_url for
// already ending in. Move the path in the spec and the two disagree silently, with the client
// posting the new path while the logs, the errors, and the validation all name the old one.
func TestOpenAPISpecDeclaresEvaluateOperation(t *testing.T) {
	spec := loadSpec(t)

	require.Len(t, spec.Paths, 1, "v1 is a one-operation contract")
	for path, methods := range spec.Paths {
		assert.Equal(t, EvaluatePath, path,
			"the spec's operation path and policy.EvaluatePath must be the same string")
		for method, op := range methods {
			assert.Equal(t, "post", method, "the hook is a POST-only contract")
			assert.Equal(t, "policy-evaluate", op.OperationID)
		}
	}
}

// The verifier must be able to read a response written exactly as the spec's example shows.
func TestEvaluateResponse_DecodesSpecShape(t *testing.T) {
	var pass EvaluateResponse
	require.NoError(t, json.Unmarshal([]byte(`{"decision":"PASS"}`), &pass))
	assert.Equal(t, DecisionPass, pass.Decision)

	var fail EvaluateResponse
	require.NoError(t, json.Unmarshal([]byte(`{"decision":"FAIL","reason":"sanctioned sender"}`), &fail))
	assert.Equal(t, DecisionFail, fail.Decision)
	require.NotNil(t, fail.Reason)
	assert.Equal(t, "sanctioned sender", *fail.Reason)

	// reason and message_id are optional in the contract, which the generated types express as
	// a nil pointer rather than an empty string, so an endpoint that omits them is
	// distinguishable from one that sent them blank.
	assert.Nil(t, pass.Reason)
	assert.Nil(t, pass.MessageId)
}
